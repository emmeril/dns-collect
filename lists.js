const express = require("express");
const axios = require("axios");
const fs = require("fs");

const app = express();
const port = 8521;
const intervalTime = 1 * 60 * 1000; // 1 menit

const adguardApiUrl = "http://16.20.20.20:2525/control/querylog";
const adguardAuth = {
  username: "Hafri",
  password: "Loveisproblem@2611",
};

// Fungsi untuk menghasilkan dan menyimpan file Mikrotik
const generateMikrotikScript = async () => {
  let scriptContent = `# Mikrotik Address-List generated on ${new Date().toISOString()}\n\n`;
  const processedDomains = new Set();

  try {
    const response = await axios.get(adguardApiUrl, { auth: adguardAuth });
    const queries = response.data.data;

    for (const query of queries) {
      if (
        query.status === "NOERROR" &&
        query.question &&
        query.question.type === "A"
      ) {
        let domain = query.question.name;
        if (domain.endsWith(".")) domain = domain.slice(0, -1);
        if (processedDomains.has(domain)) continue;

        // Kategorisasi otomatis berdasarkan isi domain
        if (
          domain.includes("youtube") ||
          domain.includes("facebook") ||
          domain.includes("instagram") ||
          domain.includes("tiktok") ||
          domain.includes("shopee") ||
          domain.includes("tokopedia") ||
          domain.includes("googlevideo") ||
          domain.includes("twitter") ||
          domain.includes("netflix")
        ) {
          scriptContent += `:local exists [/ip firewall address-list find address="${domain}" list="Sosmed"]\n`;
          scriptContent += `:if (\$exists = "") do={ /ip firewall address-list add list="Sosmed" address="${domain}" comment="${domain}" timeout=1d00:00:00 }\n`;
          processedDomains.add(domain);
        } else if (
          domain.includes("xnxx") ||
          domain.includes("xhamster") ||
          domain.includes("javhd") ||
          domain.includes("bokep") ||
          domain.includes("vpn") ||
          domain.includes("netcut") ||
          domain.includes("arcai") ||
          domain.includes("speedtest")
        ) {
          scriptContent += `:local exists [/ip firewall address-list find address="${domain}" list="Block"]\n`;
          scriptContent += `:if (\$exists = "") do={ /ip firewall address-list add list="Block" address="${domain}" comment="${domain}" timeout=1d00:00:00 }\n`;
          processedDomains.add(domain);
        }
      }
    }

    fs.writeFileSync("mikrotik_list.rsc", scriptContent);
    console.log(`[OK] File mikrotik_list.rsc diperbarui`);
  } catch (error) {
    console.error(`[ERROR] Gagal ambil data AdGuard: ${error.message}`);
  }
};

// Jalankan interval
setInterval(generateMikrotikScript, intervalTime);

// Serve file via HTTP
app.get("/mikrotik_list.rsc", (req, res) => {
  if (fs.existsSync("mikrotik_list.rsc")) {
    res.sendFile("mikrotik_list.rsc", { root: "." });
  } else {
    res.status(404).send("File belum tersedia, tunggu beberapa menit.");
  }
});

app.listen(port, () => {
  console.log(`Express server jalan di http://localhost:${port}`);
  console.log("Auto-update script setiap 1 menit...");
  generateMikrotikScript();
});
