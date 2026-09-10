# dns-collect

Mengambil query log AdGuard Home, mencocokkan domain yang dikonfigurasi, lalu
menyediakan script address-list MikroTik. Entri disimpan sampai RouterOS selesai
mengimpor script dan mengirim acknowledgement otomatis.

## Konfigurasi

Salin `env.example` ke `.env`, lalu isi semua variabel wajib. Buat token acak
minimal 32 karakter, misalnya dengan `openssl rand -hex 32`.

- `ADGUARD_API_URL`, `ADGUARD_USERNAME`, dan `ADGUARD_PASSWORD`: akses query log.
- `MIKROTIK_PUBLIC_BASE_URL`: URL yang dapat dijangkau router, tanpa path akhir.
- `MIKROTIK_API_TOKEN`: token Bearer untuk mengunduh script.
- `ALLOW_INSECURE_*_HTTP=true`: hanya untuk HTTP pada jaringan lokal yang benar-benar
  tepercaya. HTTPS adalah default yang diwajibkan.

Jalankan service dengan `npm start`.

## MikroTik

Contoh pengambilan dan impor di RouterOS (ganti URL dan token):

```routeros
/tool fetch url="https://dns-collect.example.local/mikrotik_list.rsc" http-header-field="Authorization: Bearer TOKEN" dst-path=mikrotik_list.rsc
/import file-name=mikrotik_list.rsc
```

Baris terakhir script mengirim acknowledgement dengan token sekali pakai. Jika
download atau impor gagal sebelum baris itu, batch tetap tersimpan dan akan
dikirim ulang. Perintah address-list bersifat idempotent sehingga retry tidak
membuat duplikat.

Endpoint `GET /healthz` tersedia untuk health check dan tidak mengonsumsi batch.

## Pengembangan

```sh
npm test
npm run check
```
