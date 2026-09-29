# HTTP API syPanel

Semua endpoint berawalan `/api`. Body JSON, kecuali respons unduhan. Autentikasi memakai sesi cookie, tanpa API token eksternal. Ambil `/api/me` untuk memperoleh token CSRF, lalu kirim sebagai `X-CSRF-Token` pada POST/PATCH/DELETE.

| Metode | Path | Fungsi / role |
| --- | --- | --- |
| GET | /me | User dan CSRF, publik |
| POST | /login | username, password, code opsional |
| POST | /logout | Cabut sesi |
| GET | /overview | Metrik, jumlah resource, pekerjaan |
| GET | /resources/KIND | Daftar objek |
| POST | /resources/KIND | Buat objek, admin/operator, HTTP 202 |
| PATCH | /resources/ID | Ubah objek, admin/operator, HTTP 202 |
| DELETE | /resources/ID | Hapus, body confirm harus nama objek |
| GET | /jobs | Status pekerjaan, tanpa payload rahasia |
| POST | /jobs/ID/retry | Retry pekerjaan gagal yang masih terbaru untuk objeknya, admin |
| POST | /ssl | domain, email, admin/operator |
| POST | /service | service, op restart/reload, admin |
| GET | /logs?service=nginx | Journal, admin/operator |
| GET | /logs?domain=contoh.id | Error situs, admin/operator |
| GET | /files?domain=...&path=. | Daftar direktori, admin/operator |
| GET | /file?domain=...&path=... | Isi file base64, admin/operator |
| POST | /file | domain, path, op, content base64 untuk write |
| GET | /download/backups/ID | Arsip file |
| GET | /download/databases/ID | SQL export |
| POST | /restore/ID | Pemulihan, admin, confirm nama backup |
| GET | /audit | Audit, admin |
| GET/POST | /users | Daftar/buat akun, admin |
| DELETE | /users/ID | Hapus akun selain diri sendiri, admin |
| POST | /password | current, password, akun sendiri |
| POST | /mfa/setup | Mulai pendaftaran TOTP |
| POST | /mfa/confirm | password, code |

KIND: `sites`, `databases`, `dns`, `mailboxes`, `forwarders`, `cron`, `sshkeys`, `redirects`, `backups`.

## Contoh payload

```json
{"domain":"contoh.id","php":"8.3"}
```

Untuk database:

```json
{"domain":"contoh.id","name":"portal","password":"PASSWORD-UNIK-MINIMAL-12-KARAKTER"}
```

Untuk DNS:

```json
{"domain":"contoh.id","host":"ns1","type":"A","value":"203.0.113.10","ttl":3600}
```

Untuk cron:

```json
{"domain":"contoh.id","script":"jobs/sinkron.php","schedule":"*/5 * * * *"}
```

Untuk file:

```json
{"domain":"contoh.id","path":"catatan.txt","op":"write","content":"SGFsbw=="}
```

Respons create/update/delete berisi ID job. HTTP 202 berarti diterima antrean, bukan selesai pada server. Poll `/jobs` atau lihat antarmuka sampai status `done` atau `failed`.

## Penanganan kesalahan

400: input salah atau operasi layanan ditolak. 401: sesi tidak valid. 403: CSRF/role ditolak. 409: konflik unik. 413: body melebihi batas. 429: pembatasan login. 500: kesalahan internal. Pesan tidak menyertakan kredensial yang sengaja dikirim pengguna.
