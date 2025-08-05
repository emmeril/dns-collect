require("dotenv").config();
const express = require("express");
const axios = require("axios");
const fs = require("fs");

const app = express();
const port = process.env.SERVER_PORT || 8521;
const intervalTime = 1 * 60 * 1000; // 1 menit

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

async function generateMikrotikScript() {
  let scriptContent = `# Mikrotik Address-List generated on ${new Date().toISOString()}\n\n`;

  try {
    const response = await axios.get(adguardApiUrl, { auth: adguardAuth });
    const queries = response.data.data;
    if (!queries || queries.length === 0) {
      console.log("[INFO] Tidak ada query dari AdGuard.");
      return;
    }

    console.log(`[INFO] Jumlah query dari AdGuard: ${queries.length}`);

    const processedDomains = new Set();

    for (const query of queries) {
      if (query.status !== "NOERROR") continue;

      const possibleDomains = new Set();

      // Dari field question.name
      if (query.question?.name) {
        let name = query.question.name;
        if (name.endsWith(".")) name = name.slice(0, -1);
        possibleDomains.add(name);
      }

      // Dari field answer[] type CNAME
      if (Array.isArray(query.answer)) {
        for (const ans of query.answer) {
          if (ans.type === "CNAME" || ans.type === "A") {
            let cname = ans.data;
            if (cname && cname.endsWith(".")) cname = cname.slice(0, -1);
            if (cname) possibleDomains.add(cname);
          }
        }
      }

      // Proses setiap domain yang ditemukan
      for (const domain of possibleDomains) {
        if (processedDomains.has(domain)) continue;

        // Debug: tampilkan domain yang sedang diproses
        console.log(`[CHECK] ${domain}`);

        if (domainsSosmed.some((d) => domain.includes(d))) {
          console.log(`[MATCH] Sosmed: ${domain}`);
          scriptContent += `:local exists [/ip firewall address-list find address="${domain}" list="Sosmed"]\n`;
          scriptContent += `:if (\$exists = "") do={ /ip firewall address-list add list="Sosmed" address="${domain}" comment="${domain}" timeout=1d00:00:00 }\n`;
          processedDomains.add(domain);
        } else if (domainsBlock.some((d) => domain.includes(d))) {
          console.log(`[MATCH] Block: ${domain}`);
          scriptContent += `:local exists [/ip firewall address-list find address="${domain}" list="Block"]\n`;
          scriptContent += `:if (\$exists = "") do={ /ip firewall address-list add list="Block" address="${domain}" comment="${domain}" timeout=1d00:00:00 }\n`;
          processedDomains.add(domain);
        } else {
          console.log(`[SKIP] Tidak cocok filter: ${domain}`);
        }
      }
    }

    // Jika tidak ada domain yang cocok
    if (processedDomains.size === 0) {
      scriptContent += `# Tidak ada domain yang cocok dengan filter pada ${new Date().toISOString()}\n`;
    }

    fs.writeFileSync("mikrotik_list.rsc", scriptContent);
    console.log(`[SUCCESS] File mikrotik_list.rsc diperbarui (${processedDomains.size} entri)`);
  } catch (error) {
    console.error(`[ERROR] Gagal mengambil query dari AdGuard: ${error.message}`);
  }
}

// Interval setiap 1 menit
setInterval(generateMikrotikScript, intervalTime);

// Endpoint HTTP
app.get("/mikrotik_list.rsc", (req, res) => {
  if (fs.existsSync("mikrotik_list.rsc")) {
    res.sendFile("mikrotik_list.rsc", { root: "." });
  } else {
    res.status(404).send("File mikrotik_list.rsc belum dibuat.");
  }
});

// Start server
app.listen(port, () => {
  console.log(`✅ Express server running at http://localhost:${port}`);
  console.log("⏳ Menunggu pembaruan awal file mikrotik_list.rsc...");
  generateMikrotikScript(); // panggil langsung saat start
});
