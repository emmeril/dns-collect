require("dotenv").config({ quiet: true });

const axios = require("axios");
const crypto = require("crypto");
const express = require("express");
const fs = require("fs");
const net = require("net");
const path = require("path");

const DEFAULT_PORT = 8521;
const DEFAULT_POLL_INTERVAL_MS = 60 * 1000;
const DEFAULT_REQUEST_TIMEOUT_MS = 15 * 1000;
const DEFAULT_ADDRESS_TIMEOUT_MS = 60 * 60 * 1000;
const DEFAULT_MAX_RESPONSE_BYTES = 5 * 1024 * 1024;
const ADDRESS_LIST_TIMEOUT = "01:00:00";
const COMMENT_PREFIX = "dns-collect:";

const domainsSosmed = [
  "youtube", "youtube.com", "music.youtube", "ytimg", "googlevideo",
  "youtubei", "youtube-nocookie", "youtu.be", "facebook", "facebook.com", "fbcdn",
  "messenger", "instagram", "cdninstagram", "telegram", "telegram.org",
  "telegram.me", "t.me", "telegra.ph", "cdn-telegram", "lazada",
  "lazcdn", "lzd.co", "shopee", "shopeemobile", "shopeeimg", "shp.ee",
  "tokopedia", "tokopedia.net", "bukalapak", "bukalapak.com",
  "bukalapak.io", "netflix", "nflxvideo", "nflximg", "nflxext",
  "nflxso", "spotify", "spotifycdn", "scdn.co", "pscdn.co", "twitter",
  "x.com", "twimg", "t.co", "tiktok", "snackvideo", "bytetcdn",
  "byteoversea", "byteimg", "ibytedtos", "kwaipros", "ksapisrv", "kwai",
  "kwaicdn", "tiktokcdn", "tiktokv", "muscdn", "ttcdn",
];

const domainsBlock = [
  "speedtest", "xnxx", "porn", "vpn", "arcai", "netcut", "xhamster",
  "javhd", "bokep", "bokepindo", "indobokep", "bokepin", "bokepviral",
  "bokepnesia", "semprot", "simontok", "ngentot", "ngewe", "mesum",
  "bugil", "hentai", "nekopoi", "nhentai", "hanime", "rule34", "redtube",
  "youporn", "pornhub", "xvideos", "youjizz", "spankbang", "tube8",
];

// Block wins when a deliberately crafted name matches both categories.
const domainLists = [
  { name: "Block", keywords: domainsBlock },
  { name: "Sosmed", keywords: domainsSosmed },
];

function parsePositiveInteger(value, fallback, name, maximum = Number.MAX_SAFE_INTEGER) {
  if (value === undefined || value === "") return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0 || parsed > maximum) {
    throw new Error(`${name} harus berupa bilangan bulat antara 1 dan ${maximum}.`);
  }
  return parsed;
}

function parseBoolean(value) {
  return String(value).toLowerCase() === "true";
}

function parseHttpUrl(value, name) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${name} harus berupa URL http/https yang valid.`);
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error(`${name} harus menggunakan http atau https.`);
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error(`${name} tidak boleh berisi kredensial, query, atau fragment.`);
  }
  return parsed;
}

function loadConfig(env = process.env) {
  const missing = [
    "ADGUARD_API_URL",
    "ADGUARD_USERNAME",
    "ADGUARD_PASSWORD",
    "MIKROTIK_API_TOKEN",
    "MIKROTIK_PUBLIC_BASE_URL",
  ].filter((name) => !env[name]);
  if (missing.length > 0) {
    throw new Error(`Konfigurasi wajib belum diisi: ${missing.join(", ")}.`);
  }
  if (env.MIKROTIK_API_TOKEN.length < 32 || /[\r\n]/.test(env.MIKROTIK_API_TOKEN)) {
    throw new Error("MIKROTIK_API_TOKEN minimal 32 karakter dan tidak boleh berisi baris baru.");
  }

  const adguardApiUrl = parseHttpUrl(env.ADGUARD_API_URL, "ADGUARD_API_URL");
  const publicBaseUrl = parseHttpUrl(
    env.MIKROTIK_PUBLIC_BASE_URL,
    "MIKROTIK_PUBLIC_BASE_URL"
  );
  if (adguardApiUrl.protocol !== "https:" && !parseBoolean(env.ALLOW_INSECURE_ADGUARD_HTTP)) {
    throw new Error(
      "ADGUARD_API_URL wajib HTTPS. Untuk jaringan lokal tepercaya, set ALLOW_INSECURE_ADGUARD_HTTP=true secara eksplisit."
    );
  }
  if (publicBaseUrl.protocol !== "https:" && !parseBoolean(env.ALLOW_INSECURE_MIKROTIK_HTTP)) {
    throw new Error(
      "MIKROTIK_PUBLIC_BASE_URL wajib HTTPS. Untuk jaringan lokal tepercaya, set ALLOW_INSECURE_MIKROTIK_HTTP=true secara eksplisit."
    );
  }

  publicBaseUrl.pathname = publicBaseUrl.pathname.replace(/\/$/, "");
  return {
    addressTimeoutMs: DEFAULT_ADDRESS_TIMEOUT_MS,
    adguardApiUrl: adguardApiUrl.toString(),
    adguardAuth: {
      username: env.ADGUARD_USERNAME,
      password: env.ADGUARD_PASSWORD,
    },
    adguardRequestTimeoutMs: parsePositiveInteger(
      env.ADGUARD_REQUEST_TIMEOUT_MS,
      DEFAULT_REQUEST_TIMEOUT_MS,
      "ADGUARD_REQUEST_TIMEOUT_MS"
    ),
    maxResponseBytes: parsePositiveInteger(
      env.ADGUARD_MAX_RESPONSE_BYTES,
      DEFAULT_MAX_RESPONSE_BYTES,
      "ADGUARD_MAX_RESPONSE_BYTES"
    ),
    mikrotikApiToken: env.MIKROTIK_API_TOKEN,
    pollIntervalMs: parsePositiveInteger(
      env.POLL_INTERVAL_MS,
      DEFAULT_POLL_INTERVAL_MS,
      "POLL_INTERVAL_MS"
    ),
    publicBaseUrl: publicBaseUrl.toString().replace(/\/$/, ""),
    serverHost: env.SERVER_HOST || "0.0.0.0",
    serverPort: parsePositiveInteger(env.SERVER_PORT, DEFAULT_PORT, "SERVER_PORT", 65535),
  };
}

function normalizeDomain(domain) {
  if (typeof domain !== "string") return "";
  const normalized = domain.trim().replace(/\.+$/, "").toLowerCase();
  if (
    !normalized || normalized.length > 253 || /[\r\n]/.test(normalized) ||
    !normalized.split(".").every((label) =>
      label.length > 0 && label.length <= 63 &&
      /^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/.test(label)
    )
  ) {
    return "";
  }
  return normalized;
}

function domainMatchesKeyword(domain, keyword) {
  if (keyword.includes(".")) {
    return domain === keyword || domain.endsWith(`.${keyword}`);
  }
  return domain.split(".").includes(keyword);
}

function matchDomain(domain) {
  const normalizedDomain = normalizeDomain(domain);
  if (!normalizedDomain) return null;
  const matchedList = domainLists.find(({ keywords }) =>
    keywords.some((keyword) => domainMatchesKeyword(normalizedDomain, keyword))
  );
  return matchedList ? { listName: matchedList.name, domain: normalizedDomain } : null;
}

function findQueryMatch(query) {
  const directMatch = matchDomain(query?.question?.name);
  if (directMatch) return directMatch;
  if (!Array.isArray(query?.answer)) return null;
  for (const answer of query.answer) {
    if (answer?.type !== "CNAME") continue;
    const cnameMatch = matchDomain(answer.value);
    if (cnameMatch) return { ...cnameMatch, viaCname: true };
  }
  return null;
}

function getAnswerIps(query) {
  if (!Array.isArray(query?.answer)) return [];
  return query.answer
    .filter((answer) => answer?.type === "A" && net.isIP(answer.value) === 4)
    .map((answer) => answer.value);
}

function escapeMikrotikValue(value) {
  return String(value)
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\r/g, "\\r")
    .replace(/\n/g, "\\n");
}

function buildAddressListEntry({ ipAddress, listName, domain }) {
  const safeIpAddress = escapeMikrotikValue(ipAddress);
  const safeListName = escapeMikrotikValue(listName);
  const safeComment = escapeMikrotikValue(`${COMMENT_PREFIX}${domain}`);
  return `:local entryIds [/ip firewall address-list find where list="${safeListName}" and address="${safeIpAddress}"]; :if ([:len \$entryIds] = 0) do={ /ip firewall address-list add list="${safeListName}" address="${safeIpAddress}" comment="${safeComment}" timeout=${ADDRESS_LIST_TIMEOUT} } else={ /ip firewall address-list set \$entryIds comment="${safeComment}" timeout=${ADDRESS_LIST_TIMEOUT} }`;
}

function buildEntryKey(listName, ipAddress) {
  return `${listName}:${ipAddress}`;
}

function isValidEntry(entry) {
  return Boolean(
    entry && ["Block", "Sosmed"].includes(entry.listName) &&
    net.isIP(entry.ipAddress) === 4 && normalizeDomain(entry.domain) === entry.domain
  );
}

function atomicWriteFileSync(filePath, content, mode = 0o600) {
  const tempFile = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tempFile, content, { mode });
  fs.renameSync(tempFile, filePath);
}

function safeTokenEquals(actual, expected) {
  const actualBuffer = Buffer.from(actual || "");
  const expectedBuffer = Buffer.from(expected);
  return actualBuffer.length === expectedBuffer.length &&
    crypto.timingSafeEqual(actualBuffer, expectedBuffer);
}

function extractBearerToken(req) {
  const authorization = req.get("authorization") || "";
  const match = authorization.match(/^Bearer ([^\s]+)$/);
  return match ? match[1] : "";
}

function createDeliveryStore({ stateFile, legacyCacheFile, outputFile, addressTimeoutMs }) {
  const recentlyAcknowledged = new Map();
  const pendingEntries = new Map();
  let activeBatch = null;

  function prune(now) {
    let changed = false;
    for (const [entryKey, expiresAt] of recentlyAcknowledged) {
      if (expiresAt <= now) {
        recentlyAcknowledged.delete(entryKey);
        changed = true;
      }
    }
    return changed;
  }

  function serialize() {
    return {
      version: 1,
      recentlyAcknowledged: Object.fromEntries(recentlyAcknowledged),
      pendingEntries: Array.from(pendingEntries.values()),
      activeBatch,
    };
  }

  function buildScript(entries, ackUrl) {
    let content = `# MikroTik Address-List generated on ${new Date().toISOString()}\n\n`;
    if (entries.length === 0) return `${content}# Tidak ada IP yang menunggu pengiriman.\n`;
    content += "# Perintah idempotent; acknowledgement dijalankan setelah seluruh entri diproses.\n";
    for (const entry of entries) content += `${buildAddressListEntry(entry)}\n`;
    if (ackUrl) {
      content += `/tool fetch url="${escapeMikrotikValue(ackUrl)}" http-method=post keep-result=no\n`;
    }
    return content;
  }

  function writePreview() {
    const entries = activeBatch?.entries || Array.from(pendingEntries.values());
    atomicWriteFileSync(outputFile, buildScript(entries, null), 0o644);
  }

  function persist() {
    atomicWriteFileSync(stateFile, `${JSON.stringify(serialize(), null, 2)}\n`);
    writePreview();
  }

  function loadAcknowledgedObject(cache, now) {
    if (!cache || typeof cache !== "object" || Array.isArray(cache)) return;
    for (const [entryKey, expiresAt] of Object.entries(cache)) {
      if (Number.isFinite(Number(expiresAt)) && Number(expiresAt) > now) {
        recentlyAcknowledged.set(entryKey, Number(expiresAt));
      }
    }
  }

  function load(now = Date.now()) {
    if (fs.existsSync(stateFile)) {
      try {
        const saved = JSON.parse(fs.readFileSync(stateFile, "utf8"));
        if (saved.version !== 1) throw new Error("versi state tidak didukung");
        loadAcknowledgedObject(saved.recentlyAcknowledged, now);
        if (Array.isArray(saved.pendingEntries)) {
          if (!saved.pendingEntries.every(isValidEntry)) {
            throw new Error("state berisi pending entry yang tidak valid");
          }
          for (const entry of saved.pendingEntries) {
            pendingEntries.set(buildEntryKey(entry.listName, entry.ipAddress), entry);
          }
        }
        if (
          saved.activeBatch && typeof saved.activeBatch.id === "string" &&
          typeof saved.activeBatch.ackToken === "string" &&
          Array.isArray(saved.activeBatch.entries) && saved.activeBatch.entries.every(isValidEntry)
        ) {
          activeBatch = saved.activeBatch;
          for (const entry of activeBatch.entries) {
            pendingEntries.set(buildEntryKey(entry.listName, entry.ipAddress), entry);
          }
        }
      } catch (error) {
        throw new Error(`State pengiriman tidak bisa dibaca; file dipertahankan: ${error.message}`);
      }
    } else if (fs.existsSync(legacyCacheFile)) {
      try {
        loadAcknowledgedObject(JSON.parse(fs.readFileSync(legacyCacheFile, "utf8")), now);
      } catch (error) {
        console.warn(`[WARN] Cache lama tidak bisa dibaca dan akan diabaikan: ${error.message}`);
      }
    }
    prune(now);
    persist();
  }

  function enqueue(entries, now = Date.now()) {
    let changed = prune(now);
    for (const entry of entries) {
      if (!isValidEntry(entry)) continue;
      const entryKey = buildEntryKey(entry.listName, entry.ipAddress);
      if (recentlyAcknowledged.has(entryKey) || pendingEntries.has(entryKey)) continue;
      pendingEntries.set(entryKey, entry);
      changed = true;
    }
    if (changed) persist();
    return changed;
  }

  function getOrCreateBatch(now = Date.now()) {
    if (activeBatch) return activeBatch;
    if (pendingEntries.size === 0) return null;
    activeBatch = {
      id: crypto.randomUUID(),
      ackToken: crypto.randomBytes(32).toString("hex"),
      createdAt: now,
      entries: Array.from(pendingEntries.values()).sort((a, b) =>
        buildEntryKey(a.listName, a.ipAddress).localeCompare(buildEntryKey(b.listName, b.ipAddress))
      ),
    };
    persist();
    return activeBatch;
  }

  function acknowledge(batchId, ackToken, now = Date.now()) {
    if (!activeBatch || activeBatch.id !== batchId) return false;
    if (!safeTokenEquals(ackToken, activeBatch.ackToken)) return false;
    for (const entry of activeBatch.entries) {
      const entryKey = buildEntryKey(entry.listName, entry.ipAddress);
      pendingEntries.delete(entryKey);
      recentlyAcknowledged.set(entryKey, now + addressTimeoutMs);
    }
    activeBatch = null;
    prune(now);
    persist();
    return true;
  }

  return {
    acknowledge,
    buildScript,
    enqueue,
    getOrCreateBatch,
    load,
    snapshot: () => serialize(),
  };
}

function collectEntries(queries) {
  const entries = [];
  const processedEntries = new Set();
  const loggedDomains = new Set();
  for (const query of queries) {
    if (query?.status !== "NOERROR") continue;
    const match = findQueryMatch(query);
    if (!match) continue;
    const logKey = `${match.listName}:${match.domain}`;
    if (!loggedDomains.has(logKey)) {
      console.log(`[MATCH] ${match.viaCname ? "(via CNAME) " : ""}${match.listName}: ${match.domain}`);
      loggedDomains.add(logKey);
    }
    for (const ipAddress of getAnswerIps(query)) {
      const entryKey = buildEntryKey(match.listName, ipAddress);
      if (processedEntries.has(entryKey)) continue;
      processedEntries.add(entryKey);
      entries.push({ ipAddress, listName: match.listName, domain: match.domain });
    }
  }
  return entries;
}

function createService(config, options = {}) {
  const app = express();
  const httpClient = options.httpClient || axios;
  const baseDirectory = options.baseDirectory || __dirname;
  const deliveryStore = options.deliveryStore || createDeliveryStore({
    stateFile: path.join(baseDirectory, ".dns_collect_state.json"),
    legacyCacheFile: path.join(baseDirectory, ".mikrotik_emitted_cache.json"),
    outputFile: path.join(baseDirectory, "mikrotik_list.rsc"),
    addressTimeoutMs: config.addressTimeoutMs,
  });
  let isGenerating = false;

  deliveryStore.load();
  app.disable("x-powered-by");

  async function generateMikrotikScript() {
    if (isGenerating) {
      console.log("[INFO] Pembaruan sebelumnya masih berjalan; jadwal dilewati.");
      return;
    }
    isGenerating = true;
    try {
      const response = await httpClient.get(config.adguardApiUrl, {
        auth: config.adguardAuth,
        timeout: config.adguardRequestTimeoutMs,
        maxContentLength: config.maxResponseBytes,
        maxBodyLength: config.maxResponseBytes,
        maxRedirects: 0,
        responseType: "json",
      });
      const queries = response.data?.data;
      if (!Array.isArray(queries)) {
        throw new Error("respons AdGuard tidak memiliki array data yang valid");
      }
      const entries = collectEntries(queries);
      deliveryStore.enqueue(entries);
      console.log(`[SUCCESS] ${queries.length} query diperiksa; ${entries.length} kandidat valid ditemukan.`);
    } catch (error) {
      console.error(`[ERROR] Gagal mengambil query dari AdGuard: ${error.message}`);
    } finally {
      isGenerating = false;
    }
  }

  function requireMikrotikAuth(req, res, next) {
    if (!safeTokenEquals(extractBearerToken(req), config.mikrotikApiToken)) {
      res.set("WWW-Authenticate", "Bearer");
      res.status(401).send("Unauthorized");
      return;
    }
    next();
  }

  app.get("/healthz", (req, res) => res.json({ status: "ok" }));

  app.get("/mikrotik_list.rsc", requireMikrotikAuth, (req, res) => {
    const batch = deliveryStore.getOrCreateBatch();
    res.set("Cache-Control", "no-store");
    if (!batch) {
      res.type("text/plain").send(deliveryStore.buildScript([], null));
      return;
    }
    const ackUrl = `${config.publicBaseUrl}/mikrotik_list/ack/${encodeURIComponent(batch.id)}?token=${encodeURIComponent(batch.ackToken)}`;
    res.type("text/plain").send(deliveryStore.buildScript(batch.entries, ackUrl));
  });

  app.post("/mikrotik_list/ack/:batchId", (req, res) => {
    res.set("Cache-Control", "no-store");
    if (!deliveryStore.acknowledge(req.params.batchId, String(req.query.token || ""))) {
      res.status(404).send("Batch acknowledgement tidak valid atau sudah diproses.");
      return;
    }
    res.status(204).end();
  });

  return { app, deliveryStore, generateMikrotikScript };
}

function startServer(env = process.env) {
  let config;
  let service;
  try {
    config = loadConfig(env);
    service = createService(config);
  } catch (error) {
    console.error(`[FATAL] Service tidak dapat dimulai: ${error.message}`);
    process.exitCode = 1;
    return null;
  }

  const server = service.app.listen(config.serverPort, config.serverHost, () => {
    console.log(`Express server running at http://${config.serverHost}:${config.serverPort}`);
    service.generateMikrotikScript();
  });
  const interval = setInterval(service.generateMikrotikScript, config.pollIntervalMs);
  interval.unref();
  server.on("close", () => clearInterval(interval));
  return { ...service, server };
}

if (require.main === module) startServer();

module.exports = {
  buildAddressListEntry,
  collectEntries,
  createDeliveryStore,
  createService,
  domainMatchesKeyword,
  findQueryMatch,
  getAnswerIps,
  loadConfig,
  matchDomain,
  normalizeDomain,
  safeTokenEquals,
  startServer,
};
