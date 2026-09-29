# Instalasi syPanel pada VPS Ubuntu

## 1. Lingkungan target

- Ubuntu Server 22.04 LTS atau 24.04 LTS, arsitektur yang didukung paket APT dan dependensi Python.
- VPS baru, akses root/sudo, IP publik tetap, akses repositori Ubuntu, PyPI, dan ACME.
- Alokasi awal untuk pengujian: 2 vCPU, RAM 2-4 GB, ruang 20 GB atau lebih. Sesuaikan setelah mengukur beban website dan email.
- Jangan memasang pada server yang sudah dikelola cPanel, Plesk, Hestia, atau panel lain.
- Installer menyalin konfigurasi BIND sebelum mengubahnya, tetapi bukan alat migrasi server yang sudah berisi layanan produksi.
- Ubuntu 22.04 memakai PHP 8.1 bawaan, Ubuntu 24.04 memakai PHP 8.3. Installer tidak menambahkan PPA atau versi PHP pihak ketiga. UI hanya menawarkan versi yang ditemukan agent.

## 2. Unggah dan pasang

Salin ZIP ke VPS menggunakan SCP atau SFTP, lalu:

```bash
sudo apt-get update
sudo apt-get install -y unzip
unzip syPanel_v1.0_Developer_Preview.zip
cd syPanel
sudo bash deploy/install.sh
```

Ketik `INSTALL`. Buat password admin, minimal 12 karakter. Password diminta secara interaktif, tidak ditulis sebagai argumen proses atau konfigurasi.

Installer memasang Nginx, MariaDB, BIND, PHP-FPM, Certbot, ACL, SSH, cron, dan Python venv. Email dipasang terpisah. Kode berada di `/opt/sypanel` dan hanya dapat ditulis root. Aplikasi web berjalan sebagai user `sypanel`.

## 3. Firewall dan akses

Installer tidak mengubah firewall atau security group milik penyedia VPS. Pastikan aturan akses sesuai layanan yang digunakan:

| Port | Kebutuhan |
| --- | --- |
| 22/TCP | SSH administrator dan SFTP situs |
| 80/TCP | Website HTTP dan tantangan ACME |
| 443/TCP | Website HTTPS |
| 2083/TCP | Panel HTTPS, sebaiknya batasi ke IP administrator atau VPN |
| 53/UDP dan TCP | DNS otoritatif jika menggunakan BIND syPanel |
| 25/TCP | SMTP antarpeladen, khusus integrasi email |
| 587/TCP | Pengiriman email klien, STARTTLS |
| 993/TCP | IMAP melalui TLS |

Port 8090 hanya terikat pada loopback. MariaDB tidak perlu dibuka ke internet. Pertahankan akses SSH saat mengubah firewall.

Masuk ke `https://IP-SERVER:2083`. Sertifikat awal dibuat sendiri dengan masa 30 hari. Ganti menggunakan domain dan sertifikat sah sebelum digunakan tim.

## 4. Sertifikat domain panel

Arahkan DNS A domain panel ke IP VPS. Jika menambahkan AAAA, alamat IPv6 harus benar-benar dapat dijangkau. Buka port 80, lalu:

```bash
sudo bash /opt/sypanel/deploy/enable-panel-ssl.sh panel.contoh.id admin@contoh.id
```

Skrip ini menyetujui ketentuan ACME Let's Encrypt dan meminta sertifikat menggunakan email tersebut. Akses panel menjadi `https://panel.contoh.id:2083`. Domain panel harus khusus panel, jangan dibuat lagi sebagai website dari menu Website & domain. Renewal hook memuat ulang Nginx.

## 5. Periksa layanan

```bash
sudo systemctl status sypanel-agent sypanel-web sypanel-worker
sudo sypanel-admin check
sudo journalctl -u sypanel-web -n 80 --no-pager
sudo journalctl -u sypanel-agent -n 80 --no-pager
sudo journalctl -u sypanel-worker -n 80 --no-pager
sudo nginx -t
sudo named-checkconf
sudo certbot certificates
```

`SYPANEL_MODE=live` disetel installer. Jangan menjalankan panel produksi dalam mode sandbox.

## 6. Pengguna dan pemulihan akses

```bash
sudo sypanel-admin create-admin --username admin_kedua
sudo sypanel-admin reset-password --username admin
sudo sypanel-admin reset-mfa --username admin
```

Reset password atau MFA mencabut sesi akun tersebut. Reset MFA dilakukan melalui SSH administrator dan harus diikuti pendaftaran ulang autentikator.

## 7. DNS otoritatif

Untuk mengelola zona `contoh.id`, buat situs `contoh.id` terlebih dahulu. Pada DNS zone editor:

1. Buat rekaman `ns1`, tipe A, IP publik VPS. Ini harus menjadi rekaman pertama agar NS zona memiliki alamat.
2. Buat rekaman `@`, tipe A, IP VPS.
3. Tambahkan `www` tipe CNAME ke `contoh.id` jika diperlukan.
4. Daftarkan host/glue `ns1.contoh.id` pada registrar bila nameserver berada di dalam zona sendiri.
5. Atur delegasi nameserver pada registrar. Jika registrar mensyaratkan dua nameserver, sediakan server sekunder terpisah. Versi ini belum mengelola DNS sekunder.
6. Periksa dengan `dig @IP-VPS contoh.id A` dan `dig +trace contoh.id`.

Server BIND dipasang sebagai otoritatif, dengan recursion dan zone transfer publik dinonaktifkan. Menulis rekaman di syPanel tidak mengubah DNS registrar atau Cloudflare secara otomatis. Bila menggunakan DNS eksternal, kelola DNS di penyedia tersebut dan gunakan syPanel untuk website.

## 8. Email opsional

Integrasi ini menggunakan Postfix dan Dovecot 2.3 dari Ubuntu target. Urutan:

1. Buat situs `mail.contoh.id` dengan runtime static.
2. Arahkan DNS-nya ke VPS dan terbitkan SSL melalui syPanel.
3. Jalankan:

```bash
sudo bash /opt/sypanel/deploy/mail.sh mail.contoh.id
```

4. Ketik `MAIL`. Installer menyiapkan virtual mail user UID/GID 5000. Proses berhenti jika ID tersebut telah digunakan akun lain.
5. Tambahkan akun melalui menu Akun email. Buat situs/domain `contoh.id` jika alamat yang diinginkan adalah `nama@contoh.id`.
6. Buat MX domain menuju `mail.contoh.id`, SPF sesuai sumber pengiriman, dan DMARC sesuai kebijakan organisasi.
7. Minta PTR IP ke penyedia VPS. Pastikan port 25 keluar/masuk tidak diblokir.
8. Konfigurasikan DKIM dan antispam secara terpisah sebelum layanan email publik. Versi ini belum menyediakan penandatangan DKIM atau filter spam.

Klien email: hostname `mail.contoh.id`, IMAPS port 993, SMTP submission port 587 STARTTLS. Username adalah alamat email lengkap. Webmail tidak disertakan. Penerusan dilakukan ke satu alamat tujuan. Hindari rantai penerusan berulang.

## 9. Lokasi penting

| Lokasi | Isi |
| --- | --- |
| `/opt/sypanel` | Kode, venv, installer, dokumentasi |
| `/var/lib/sypanel` | SQLite panel, kunci enkripsi dan sesi |
| `/var/lib/sypanel-agent/state.json` | Catatan objek yang telah dikelola agent |
| `/srv/sypanel/sites/DOMAIN/public_html` | Berkas website |
| `/var/backups/sypanel` | Arsip file website |
| `/etc/nginx/conf.d/sypanel-*` | Virtual host |
| `/etc/php/VERSION/fpm/pool.d/sy*.conf` | Pool PHP per situs |
| `/etc/bind/sypanel` | Zona DNS |
| `/etc/ssh/sypanel` | Public key SFTP |
| `/var/vmail` | Maildir email |
| `/etc/postfix/sypanel` | Peta domain, kotak, dan alias |

## 10. Cadangan administrator

Backup panel saat ini hanya mengarsip file website. Ekspor database tersedia terpisah. Untuk pemulihan server lengkap, administrator perlu mencadangkan SQLite panel bersama kunci enkripsinya, state agent, konfigurasi layanan, seluruh website, MariaDB, sertifikat, dan maildir. Hentikan worker/web sementara atau gunakan API backup SQLite agar snapshot konsisten. Simpan salinan di luar VPS.

Jangan menghapus `encryption.key` bila terdapat pekerjaan gagal yang masih berisi payload terenkripsi. Mengganti kunci tanpa migrasi membuat payload dan TOTP lama tidak dapat dibaca.

## 11. Pembaruan kode

Belum tersedia pembaruan otomatis atau migrasi skema berversi. Sebelum memperbarui, simpan snapshot, hentikan web dan worker, tinjau perubahan skema, salin kode sebagai root, pasang dependensi, jalankan tes pada staging, lalu hidupkan kembali layanan. Jangan menjalankan installer baru di atas instalasi lama.
