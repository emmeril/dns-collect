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

// Kata kunci domain
const domainsSosmed = [
  "youtube", "ytimg", "facebook", "instagram", "akamai",
  "googlevideo", "lazada", "shopee", "snackvideo",
  "bukalapak", "tokopedia", "netflix", "twitter", "tiktok",
];

const domainsBlock = [
  "speedtest", "xnxx", "vpn", "arcai", "netcut",
  "xhamster", "javhd", "bokep",
];

// Baca file lama dan ambil daftar domain yang sudah pernah ditulis
const getExistingDomains = () => {
  const filePath = "mikrotik_list.rsc";
  const existing = new Set();

  if (fs.existsSync(filePath)) {
    const lines = fs.readFileSync(filePath, "utf-8").split("\n");
    for (const line of lines) {
      const match = line.match(/address="([^"]+)"/);
      if (match) {
        existing.add(match[1]);
      }
    }
  }

  return existing;
};

// Fungsi utama
const generateMikrotikScript = async () => {
  try {
    const response = await axios.get(adguardApiUrl, { auth: adguardAuth });
    const queries = response.data.data;
    const processedDomains = getExistingDomains();
    const possibleDomains = new Set();

    for (const query of queries) {
      if (query.question?.name) {
        let name = query.question.name;
        if (name.endsWith(".")) name = name.slice(0, -1);
        if (name) possibleDomains.add(name);
      }

      if (Array.isArray(query.answer)) {
        for (const ans of query.answer) {
          if (ans.type === "CNAME" || ans.type === "A") {
            let cname = ans.data;
            if (cname && cname.endsWith(".")) cname = cname.slice(0, -1);
            if (cname) possibleDomains.add(cname);
          }
        }
      }
    }

    for (const domain of possibleDomains) {
      if (processedDomains.has(domain)) continue;

      let scriptLine = "";
      if (domainsSosmed.some((d) => domain.includes(d))) {
        scriptLine += `:local exists [/ip firewall address-list find address="${domain}" list="Sosmed"]\n`;
        scriptLine += `:if (\$exists = "") do={ /ip firewall address-list add list="Sosmed" address="${domain}" comment="${domain}" timeout=1d00:00:00 }\n`;
      } else if (domainsBlock.some((d) => domain.includes(d))) {
        scriptLine += `:local exists [/ip firewall address-list find address="${domain}" list="Block"]\n`;
        scriptLine += `:if (\$exists = "") do={ /ip firewall address-list add list="Block" address="${domain}" comment="${domain}" timeout=1d00:00:00 }\n`;
      }

      if (scriptLine !== "") {
        fs.appendFileSync("mikrotik_list.rsc", scriptLine);
        console.log(`[ADD] ${domain}`);
        processedDomains.add(domain); // supaya nggak dobel
      }
    }

  } catch (error) {
    console.error(`[Error] Gagal ambil log dari AdGuard: ${error.message}`);
  }
};

setInterval(generateMikrotikScript, intervalTime);

// Endpoint untuk ambil file
app.get("/mikrotik_list.rsc", (req, res) => {
  if (fs.existsSync("mikrotik_list.rsc")) {
    res.sendFile("mikrotik_list.rsc", { root: "." });
  } else {
    res.status(404).send("File belum tersedia. Tunggu proses pertama selesai.");
  }
});

app.listen(port, () => {
  console.log(`Server jalan di http://localhost:${port}`);
  console.log("Script akan update setiap 1 menit.");
  generateMikrotikScript(); // langsung jalan di awal
});
