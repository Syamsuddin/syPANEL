# Hasil verifikasi

Tanggal pengemasan: 29 September 2026.

## Pengujian yang dijalankan

| Pemeriksaan | Hasil |
| --- | --- |
| Unit/integration test Python pada sandbox | 24 lulus |
| Validasi sintaks JavaScript dengan `node --check` | Lulus |
| Validasi sintaks installer Bash dengan `bash -n` | Lulus |
| Kompilasi modul Python | Lulus |
| Browser headless, 18 halaman | Lulus, tanpa page error JavaScript |
| Membuat website melalui form browser | Lulus |
| Membuat dan menyimpan file melalui editor browser | Lulus |
| Tampilan desktop 1440 px | Diperiksa visual |
| Tampilan mobile 390 px | Tidak ada luapan horizontal, sidebar tertutup sesuai keadaan |
| Integritas database setelah uji browser | `PRAGMA integrity_check`: ok |

## Cakupan tes Python

Login, logout, CSRF, rate limit, pembatasan role viewer, CRUD file, penolakan traversal dan symlink, backup dan restore file, ekspor, penghapusan payload rahasia setelah pekerjaan selesai, DNS, email sandbox, forwarder, redirect, SSH key, cron, konfirmasi penghapusan, dependensi situs, input berbahaya, allowlist agent, TOTP dan replay, pencabutan sesi, status pekerjaan gagal, serta perubahan konfigurasi/password.

Perbaikan selama verifikasi mencakup konsistensi nama backup antara API dan agent, penutupan koneksi SQLite, hak akses direktori website dan venv, serta permission map Postfix. Tes diulang setelah perubahan aplikasi.

## Belum diuji di lingkungan target

- Instalasi penuh pada VM Ubuntu 22.04/24.04.
- Validasi konfigurasi oleh binary Nginx/PHP-FPM/BIND pada VPS nyata.
- Pembuatan, penghapusan, dan ekspor MariaDB sungguhan.
- Koneksi SFTP dari klien ke akun hasil provisioning.
- Penerbitan/renewal Let's Encrypt melalui domain publik.
- SMTP/IMAP, delivery eksternal, reputasi IP, PTR, dan pencegahan open relay pada deployment nyata.
- Kegagalan daya saat provisioning, restore skala besar, stress test, pentest independen.

Hasil sandbox dan browser tidak menggantikan pengujian integrasi di VPS. Label rilis: Developer Preview.

## Mengulang pengujian

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest tests -q
node --check sypanel/static/app.js
bash -n deploy/install.sh deploy/mail.sh deploy/enable-panel-ssl.sh
```

Untuk browser opsional, jalankan sandbox dari `manage.py dev`, pasang Playwright di lingkungan pengujian, lalu jalankan `tests/browser_smoke.cjs`. Gunakan variabel `SYPANEL_TEST_URL`, `SYPANEL_TEST_USER`, dan `SYPANEL_TEST_PASSWORD`. Skrip menolak mode live dan meninggalkan situs uji di sandbox.

Gambar `preview-desktop.png` menunjukkan aplikasi berjalan dalam sandbox dengan data contoh, bukan VPS produksi.
