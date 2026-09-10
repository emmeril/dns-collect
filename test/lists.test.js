const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  buildAddressListEntry,
  collectEntries,
  createDeliveryStore,
  getAnswerIps,
  loadConfig,
  matchDomain,
  normalizeDomain,
} = require("../lists");

test("domain matching respects DNS label boundaries", () => {
  assert.deepEqual(matchDomain("www.youtube.com."), {
    listName: "Sosmed",
    domain: "www.youtube.com",
  });
  assert.deepEqual(matchDomain("vpn.example"), {
    listName: "Block",
    domain: "vpn.example",
  });
  assert.equal(matchDomain("reddit.com"), null);
  assert.equal(matchDomain("notyoutube.example"), null);
  assert.equal(matchDomain("myvpncompany.example"), null);
  assert.equal(matchDomain("secure-vpn.example"), null);
  assert.equal(matchDomain("examplex.com"), null);
});

test("domain normalization rejects invalid and injectable values", () => {
  assert.equal(normalizeDomain("YouTube.COM."), "youtube.com");
  assert.equal(normalizeDomain("youtube.com\n/system reboot"), "");
  assert.equal(normalizeDomain("bad label.example"), "");
  assert.equal(normalizeDomain(""), "");
});

test("only valid IPv4 A answers are collected", () => {
  const query = {
    answer: [
      { type: "A", value: "1.2.3.4" },
      { type: "A", value: "1.2.3.4\n/system reboot" },
      { type: "AAAA", value: "2001:db8::1" },
    ],
  };
  assert.deepEqual(getAnswerIps(query), ["1.2.3.4"]);
});

test("generated RouterOS commands are idempotent", () => {
  const command = buildAddressListEntry({
    ipAddress: "1.2.3.4",
    listName: "Sosmed",
    domain: "youtube.com",
  });
  assert.match(command, /address-list find where list="Sosmed" and address="1\.2\.3\.4"/);
  assert.match(command, /address-list add list="Sosmed"/);
  assert.match(command, /address-list set \$entryIds/);
  assert.match(command, /timeout=01:00:00/);
});

test("query collection deduplicates by list and IP and honors block priority", () => {
  const entries = collectEntries([
    {
      status: "NOERROR",
      question: { name: "youtube.pornhub.com" },
      answer: [{ type: "A", value: "1.2.3.4" }],
    },
    {
      status: "NOERROR",
      question: { name: "www.youtube.com" },
      answer: [{ type: "A", value: "1.2.3.4" }],
    },
  ]);
  assert.deepEqual(entries.map(({ listName, ipAddress }) => ({ listName, ipAddress })), [
    { listName: "Block", ipAddress: "1.2.3.4" },
    { listName: "Sosmed", ipAddress: "1.2.3.4" },
  ]);
});

test("delivery store preserves unacknowledged entries and survives restart", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "dns-collect-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const options = {
    stateFile: path.join(directory, "state.json"),
    legacyCacheFile: path.join(directory, "legacy.json"),
    outputFile: path.join(directory, "output.rsc"),
    addressTimeoutMs: 1_000,
  };
  const firstEntry = { ipAddress: "1.2.3.4", listName: "Sosmed", domain: "youtube.com" };
  const secondEntry = { ipAddress: "5.6.7.8", listName: "Block", domain: "pornhub.com" };

  const store = createDeliveryStore(options);
  store.load(1_000);
  store.enqueue([firstEntry], 1_000);
  const firstBatch = store.getOrCreateBatch(1_100);
  store.enqueue([secondEntry], 1_200);

  assert.equal(store.getOrCreateBatch(1_300).id, firstBatch.id);
  assert.equal(store.snapshot().pendingEntries.length, 2);
  assert.equal(store.acknowledge(firstBatch.id, "wrong-token", 1_400), false);
  assert.equal(store.acknowledge(firstBatch.id, firstBatch.ackToken, 1_400), true);
  assert.deepEqual(store.snapshot().pendingEntries, [secondEntry]);

  const restartedStore = createDeliveryStore(options);
  restartedStore.load(1_500);
  const secondBatch = restartedStore.getOrCreateBatch(1_500);
  assert.deepEqual(secondBatch.entries, [secondEntry]);
  assert.equal(restartedStore.acknowledge(secondBatch.id, secondBatch.ackToken, 1_600), true);

  restartedStore.enqueue([firstEntry], 2_000);
  assert.equal(restartedStore.snapshot().pendingEntries.length, 0);
  restartedStore.enqueue([firstEntry], 2_401);
  assert.deepEqual(restartedStore.snapshot().pendingEntries, [firstEntry]);
});

test("configuration requires strong auth and explicit insecure HTTP opt-in", () => {
  const secureEnvironment = {
    ADGUARD_API_URL: "https://adguard.example/control/querylog",
    ADGUARD_USERNAME: "user",
    ADGUARD_PASSWORD: "password",
    MIKROTIK_API_TOKEN: "a".repeat(32),
    MIKROTIK_PUBLIC_BASE_URL: "https://collector.example",
  };
  assert.equal(loadConfig(secureEnvironment).serverPort, 8521);
  assert.throws(
    () => loadConfig({ ...secureEnvironment, MIKROTIK_API_TOKEN: "short" }),
    /minimal 32 karakter/
  );
  assert.throws(
    () => loadConfig({ ...secureEnvironment, ADGUARD_API_URL: "http://adguard.local/log" }),
    /ADGUARD_API_URL wajib HTTPS/
  );
  assert.doesNotThrow(() => loadConfig({
    ...secureEnvironment,
    ADGUARD_API_URL: "http://adguard.local/log",
    MIKROTIK_PUBLIC_BASE_URL: "http://collector.local",
    ALLOW_INSECURE_ADGUARD_HTTP: "true",
    ALLOW_INSECURE_MIKROTIK_HTTP: "true",
  }));
});

test("HTTP download requires auth and only explicit callback acknowledges", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "dns-collect-http-test-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const token = "t".repeat(32);
  const config = {
    addressTimeoutMs: 60_000,
    adguardApiUrl: "https://adguard.example/control/querylog",
    adguardAuth: { username: "user", password: "password" },
    adguardRequestTimeoutMs: 1_000,
    maxResponseBytes: 1_024,
    mikrotikApiToken: token,
    pollIntervalMs: 60_000,
    publicBaseUrl: "https://collector.example",
    serverHost: "127.0.0.1",
    serverPort: 0,
  };
  const { createService } = require("../lists");
  const service = createService(config, { baseDirectory: directory });
  const entry = { ipAddress: "1.2.3.4", listName: "Sosmed", domain: "youtube.com" };
  service.deliveryStore.enqueue([entry]);

  const server = service.app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const localBaseUrl = `http://127.0.0.1:${server.address().port}`;

  const unauthorized = await fetch(`${localBaseUrl}/mikrotik_list.rsc`);
  assert.equal(unauthorized.status, 401);
  assert.equal(service.deliveryStore.snapshot().activeBatch, null);

  const download = await fetch(`${localBaseUrl}/mikrotik_list.rsc`, {
    headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(download.status, 200);
  const script = await download.text();
  assert.match(script, /http-method=post/);
  assert.equal(service.deliveryStore.snapshot().pendingEntries.length, 1);

  const callbackUrl = new URL(script.match(/url="([^"]+)" http-method=post/)[1]);
  const badCallback = await fetch(
    `${localBaseUrl}${callbackUrl.pathname}?token=wrong`,
    { method: "POST" }
  );
  assert.equal(badCallback.status, 404);
  assert.equal(service.deliveryStore.snapshot().pendingEntries.length, 1);

  const callback = await fetch(
    `${localBaseUrl}${callbackUrl.pathname}${callbackUrl.search}`,
    { method: "POST" }
  );
  assert.equal(callback.status, 204);
  assert.equal(service.deliveryStore.snapshot().pendingEntries.length, 0);
});
