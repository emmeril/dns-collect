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

    const processedIps = new Set();
    const processedDomains = new Set();

    for (const query of queries) {
      if (query.status !== "NOERROR") continue;

      let matchedList = null;
      let matchedDomain = null;

      // Pertama, cari domain yang cocok dengan kata kunci kita
      if (query.question?.name) {
        let name = query.question.name.endsWith(".")
          ? query.question.name.slice(0, -1)
          : query.question.name;
        if (domainsSosmed.some((d) => name.includes(d))) {
          matchedList = "Sosmed";
          matchedDomain = name;
        } else if (domainsBlock.some((d) => name.includes(d))) {
          matchedList = "Block";
          matchedDomain = name;
        }
      }

      // Jika domain yang cocok ditemukan, proses alamat IP-nya
      if (matchedList && matchedDomain) {
        if (processedDomains.has(matchedDomain)) continue;
        processedDomains.add(matchedDomain);

        console.log(`[MATCH] ${matchedList}: ${matchedDomain}`);

        if (Array.isArray(query.answer)) {
          for (const ans of query.answer) {
            // PERBAIKAN: Menggunakan 'ans.value' yang ada di log Anda
            if (ans.type === "A" && ans.value) {
              const ipAddress = ans.value;
              if (processedIps.has(ipAddress)) continue;

              console.log(`  [IP FOUND] Menambahkan IP: ${ipAddress}`);
              scriptContent += `:local exists [/ip firewall address-list find address="${ipAddress}" list="${matchedList}"]\n`;
              scriptContent += `:if (\$exists = "") do={ /ip firewall address-list add list="${matchedList}" address="${ipAddress}" comment="${matchedDomain}" timeout=01:00:00}\n`;
              processedIps.add(ipAddress);
            }
          }
        }
      } else {
        // Jika tidak ada domain yang cocok, periksa CNAME sebagai alternatif
        if (Array.isArray(query.answer)) {
          for (const ans of query.answer) {
            // PERBAIKAN: Menggunakan 'ans.value' untuk CNAME
            if (ans.type === "CNAME" && ans.value) {
              let cname = ans.value.endsWith(".")
                ? ans.value.slice(0, -1)
                : ans.value;
              if (domainsSosmed.some((d) => cname.includes(d))) {
                matchedList = "Sosmed";
                matchedDomain = cname;
                break;
              } else if (domainsBlock.some((d) => cname.includes(d))) {
                matchedList = "Block";
                matchedDomain = cname;
                break;
              }
            }
          }

          // Jika CNAME cocok, proses IP dari query asli (atau A records di jawaban)
          if (
            matchedList &&
            matchedDomain &&
            !processedDomains.has(matchedDomain)
          ) {
            processedDomains.add(matchedDomain);
            console.log(`[MATCH] (via CNAME) ${matchedList}: ${matchedDomain}`);
            for (const ans of query.answer) {
              // PERBAIKAN: Menggunakan 'ans.value' untuk IP
              if (ans.type === "A" && ans.value) {
                const ipAddress = ans.value;
                if (processedIps.has(ipAddress)) continue;

                console.log(`  [IP FOUND] Menambahkan IP: ${ipAddress}`);
                scriptContent += `:local exists [/ip firewall address-list find address="${ipAddress}" list="${matchedList}"]\n`;
                scriptContent += `:if (\$exists = "") do={ /ip firewall address-list add list="${matchedList}" address="${ipAddress}" comment="${matchedDomain}" timeout=01:00:00}\n`;
                processedIps.add(ipAddress);
              }
            }
          }
        }
      }
    }

    // Jika tidak ada IP yang ditambahkan
    if (processedIps.size === 0) {
      scriptContent += `# Tidak ada IP yang cocok dengan filter pada ${new Date().toISOString()}\n`;
    }

    fs.writeFileSync("mikrotik_list.rsc", scriptContent);
    console.log(
      `[SUCCESS] File mikrotik_list.rsc diperbarui (${processedIps.size} entri)`
    );
  } catch (error) {
    console.error(
      `[ERROR] Gagal mengambil query dari AdGuard: ${error.message}`
    );
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

// Jalankan server
app.listen(port, () => {
  console.log(`✅ Express server running at http://localhost:${port}`);
  console.log("⏳ Menunggu pembaruan awal file mikrotik_list.rsc...");
  generateMikrotikScript(); // panggil langsung saat start
});
