require("dotenv").config();
const express = require("express");
const axios = require("axios");
const fs = require("fs");
const path = require("path");

const app = express();
const port = Number(process.env.SERVER_PORT) || 8521;
const intervalTime = 60 * 1000; // 1 menit
const outputFile = path.join(__dirname, "mikrotik_list.rsc");
const emittedCacheFile = path.join(__dirname, ".mikrotik_emitted_cache.json");
const commentPrefix = "dns-collect:";
const addressListTimeout = "01:00:00";
const addressListTimeoutMs = 60 * 60 * 1000;
const adguardRequestTimeoutMs = Number(process.env.ADGUARD_REQUEST_TIMEOUT_MS) || 15000;

let isGenerating = false;
let outputState = {
  batchId: 0,
  pendingEntries: [],
  scriptContent: null,
};
const recentlyEmittedEntries = new Map();

// --- Konfigurasi AdGuard ---
const adguardApiUrl = process.env.ADGUARD_API_URL;
const adguardAuth = {
  username: process.env.ADGUARD_USERNAME,
  password: process.env.ADGUARD_PASSWORD,
};

// --- Daftar Kata Kunci Domain ---
const domainsSosmed = [
  "youtube",
  "bytetcdn",
  "ytimg",
  "fbcdn",
  "byteoversea",
  "kwaipros",
  "facebook",
  "ksapisrv",
  "instagram",
  "akamai",
  "googlevideo",
  "lazada",
  "shopee",
  "snackvideo",
  "bukalapak",
  "tokopedia",
  "netflix",
  "twitter",
  "tiktok",
];

const domainsBlock = [
  "speedtest",
  "xnxx",
  "porn",
  "vpn",
  "arcai",
  "netcut",
  "xhamster",
  "javhd",
  "bokep",
  "bokepindo",
  "indobokep",
  "bokepin",
  "bokepviral",
  "bokepnesia",
  "semprot",
  "simontok",
  "ngentot",
  "ngewe",
  "mesum",
  "bugil",
  "hentai",
  "nekopoi",
  "nhentai",
  "hanime",
  "rule34",
  "redtube",
  "youporn",
  "pornhub",
  "xvideos",
  "youjizz",
  "spankbang",
  "tube8",
];

const domainLists = [
  { name: "Sosmed", keywords: domainsSosmed },
  { name: "Block", keywords: domainsBlock },
];

function normalizeDomain(domain) {
  if (!domain) return "";
  const normalized = domain.endsWith(".") ? domain.slice(0, -1) : domain;
  return normalized.toLowerCase();
}

function matchDomain(domain) {
  const normalizedDomain = normalizeDomain(domain);
  if (!normalizedDomain) return null;

  const matchedList = domainLists.find(({ keywords }) =>
    keywords.some((keyword) => normalizedDomain.includes(keyword))
  );

  return matchedList ? { listName: matchedList.name, domain: normalizedDomain } : null;
}

function findQueryMatch(query) {
  const directMatch = matchDomain(query.question?.name);
  if (directMatch) return directMatch;

  if (!Array.isArray(query.answer)) return null;

  for (const answer of query.answer) {
    if (answer.type !== "CNAME") continue;

    const cnameMatch = matchDomain(answer.value);
    if (cnameMatch) {
      return { ...cnameMatch, viaCname: true };
    }
  }

  return null;
}

function getAnswerIps(query) {
  if (!Array.isArray(query.answer)) return [];

  return query.answer
    .filter((answer) => answer.type === "A" && answer.value)
    .map((answer) => answer.value);
}

function escapeMikrotikValue(value) {
  return String(value).replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function buildAddressListEntry({ ipAddress, listName, domain }) {
  const safeIpAddress = escapeMikrotikValue(ipAddress);
  const safeListName = escapeMikrotikValue(listName);
  const safeComment = escapeMikrotikValue(`${commentPrefix}${domain}`);

  return `/ip firewall address-list add list="${safeListName}" address="${safeIpAddress}" comment="${safeComment}" timeout=${addressListTimeout}`;
}

function buildEntryKey(listName, ipAddress) {
  return `${listName}:${ipAddress}`;
}

function atomicWriteFileSync(filePath, content) {
  const tempFile = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tempFile, content);
  fs.renameSync(tempFile, filePath);
}

function pruneRecentlyEmittedEntries(now) {
  for (const [entryKey, expiresAt] of recentlyEmittedEntries) {
    if (expiresAt <= now) {
      recentlyEmittedEntries.delete(entryKey);
    }
  }
}

function loadRecentlyEmittedEntries() {
  if (!fs.existsSync(emittedCacheFile)) return;

  try {
    const cache = JSON.parse(fs.readFileSync(emittedCacheFile, "utf8"));
    const now = Date.now();

    for (const [entryKey, expiresAt] of Object.entries(cache)) {
      if (Number(expiresAt) > now) {
        recentlyEmittedEntries.set(entryKey, Number(expiresAt));
      }
    }
  } catch (error) {
    console.warn(`[WARN] Cache IP lama tidak bisa dibaca: ${error.message}`);
  }
}

function saveRecentlyEmittedEntries() {
  const cache = Object.fromEntries(recentlyEmittedEntries);
  atomicWriteFileSync(emittedCacheFile, JSON.stringify(cache, null, 2));
}

function markEntriesAsEmitted(entries, now) {
  for (const entry of entries) {
    const entryKey = buildEntryKey(entry.listName, entry.ipAddress);
    const expiresAt = now + addressListTimeoutMs;
    const currentExpiresAt = recentlyEmittedEntries.get(entryKey) || 0;

    if (!currentExpiresAt) {
      recentlyEmittedEntries.set(entryKey, expiresAt);
    }
  }

  saveRecentlyEmittedEntries();
}

async function generateMikrotikScript() {
  if (isGenerating) {
    console.log("[INFO] Pembaruan sebelumnya masih berjalan, jadwal ini dilewati.");
    return;
  }

  if (!adguardApiUrl || !adguardAuth.username || !adguardAuth.password) {
    console.error("[ERROR] Konfigurasi AdGuard belum lengkap di file .env.");
    return;
  }

  isGenerating = true;
  let scriptContent = `# Mikrotik Address-List generated on ${new Date().toISOString()}\n\n`;

  try {
    const response = await axios.get(adguardApiUrl, {
      auth: adguardAuth,
      timeout: adguardRequestTimeoutMs,
    });
    const queries = response.data?.data;

    if (!queries || queries.length === 0) {
      console.log("[INFO] Tidak ada query dari AdGuard.");
      return;
    }

    console.log(`[INFO] Jumlah query dari AdGuard: ${queries.length}`);

    const now = Date.now();
    const entries = [];
    const processedEntries = new Set();
    const loggedDomains = new Set();
    pruneRecentlyEmittedEntries(now);

    for (const query of queries) {
      if (query.status !== "NOERROR") continue;

      const match = findQueryMatch(query);
      if (!match) continue;

      const logKey = `${match.listName}:${match.domain}`;
      if (!loggedDomains.has(logKey)) {
        const cnamePrefix = match.viaCname ? "(via CNAME) " : "";
        console.log(`[MATCH] ${cnamePrefix}${match.listName}: ${match.domain}`);
        loggedDomains.add(logKey);
      }

      for (const ipAddress of getAnswerIps(query)) {
        const entryKey = buildEntryKey(match.listName, ipAddress);
        if (processedEntries.has(entryKey)) continue;
        processedEntries.add(entryKey);

        if (recentlyEmittedEntries.has(entryKey)) continue;

        console.log(`  [IP FOUND] Menambahkan IP: ${ipAddress}`);
        entries.push({
          ipAddress,
          listName: match.listName,
          domain: match.domain,
        });
      }
    }

    if (entries.length === 0) {
      scriptContent += `# Tidak ada IP baru untuk ditambahkan pada ${new Date().toISOString()}\n`;
    } else {
      scriptContent += `# Tambahkan hanya IP baru; entry lama dibiarkan expire oleh timeout MikroTik\n`;
      for (const entry of entries.sort((a, b) =>
        `${a.listName}:${a.ipAddress}`.localeCompare(`${b.listName}:${b.ipAddress}`)
      )) {
        scriptContent += `${buildAddressListEntry(entry)}\n`;
      }
    }

    atomicWriteFileSync(outputFile, scriptContent);
    outputState = {
      batchId: outputState.batchId + 1,
      pendingEntries: entries,
      scriptContent,
    };
    console.log(
      `[SUCCESS] File mikrotik_list.rsc diperbarui (${entries.length} entri baru)`
    );
  } catch (error) {
    console.error(
      `[ERROR] Gagal mengambil query dari AdGuard: ${error.message}`
    );
  } finally {
    isGenerating = false;
  }
}

// Interval setiap 1 menit
setInterval(generateMikrotikScript, intervalTime);

// Endpoint HTTP
app.get("/mikrotik_list.rsc", (req, res) => {
  const sentState = outputState;

  if (!sentState.scriptContent && !fs.existsSync(outputFile)) {
    res.status(404).send("File mikrotik_list.rsc belum dibuat.");
    return;
  }

  const scriptContent =
    sentState.scriptContent || fs.readFileSync(outputFile, "utf8");
  const entriesToMark = sentState.pendingEntries;

  res.on("finish", () => {
    if (res.statusCode >= 400 || entriesToMark.length === 0) return;

    try {
      markEntriesAsEmitted(entriesToMark, Date.now());
    } catch (error) {
      console.error(`[ERROR] Cache IP lama tidak bisa disimpan: ${error.message}`);
      return;
    }

    if (outputState.batchId === sentState.batchId) {
      outputState = {
        ...outputState,
        pendingEntries: [],
      };
    }
  });

  res
    .type("text/plain")
    .send(scriptContent);
});

// Jalankan server
app.listen(port, () => {
  console.log(`Express server running at http://localhost:${port}`);
  console.log("Menunggu pembaruan awal file mikrotik_list.rsc...");
  loadRecentlyEmittedEntries();
  generateMikrotikScript();
});
