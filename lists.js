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

let isGenerating = false;
let pendingEntries = [];
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
  "vpn",
  "arcai",
  "netcut",
  "xhamster",
  "javhd",
  "bokep",
];

const domainLists = [
  { name: "Sosmed", keywords: domainsSosmed },
  { name: "Block", keywords: domainsBlock },
];

function normalizeDomain(domain) {
  if (!domain) return "";
  return domain.endsWith(".") ? domain.slice(0, -1) : domain;
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
  fs.writeFileSync(emittedCacheFile, JSON.stringify(cache, null, 2));
}

function markEntriesAsEmitted(entries, now) {
  for (const entry of entries) {
    recentlyEmittedEntries.set(
      buildEntryKey(entry.listName, entry.ipAddress),
      now + addressListTimeoutMs
    );
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
    const response = await axios.get(adguardApiUrl, { auth: adguardAuth });
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

    fs.writeFileSync(outputFile, scriptContent);
    pendingEntries = entries;
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
  if (fs.existsSync(outputFile)) {
    const entriesToMark = pendingEntries;
    res.sendFile(outputFile, (error) => {
      if (error) {
        console.error(`[ERROR] Gagal mengirim file Mikrotik: ${error.message}`);
        if (!res.headersSent) {
          res.status(error.statusCode || 500).send("Gagal mengirim file Mikrotik.");
        }
        return;
      }

      if (entriesToMark.length > 0) {
        markEntriesAsEmitted(entriesToMark, Date.now());
      }
    });
  } else {
    res.status(404).send("File mikrotik_list.rsc belum dibuat.");
  }
});

// Jalankan server
app.listen(port, () => {
  console.log(`Express server running at http://localhost:${port}`);
  console.log("Menunggu pembaruan awal file mikrotik_list.rsc...");
  loadRecentlyEmittedEntries();
  generateMikrotikScript();
});
