# syPanel 1.0.0 Developer Preview

Panel pengelolaan hosting mandiri untuk Ubuntu 22.04 dan 24.04 LTS.

Nama aplikasi: syPanel. Implementasi mandiri, tanpa kode, logo, atau aset milik cPanel. Versi ini membangun modul inti panel hosting. Belum merupakan pengganti dengan kesetaraan seluruh fitur cPanel/WHM.

## Isi utama

- Dashboard kesehatan CPU, memori, disk, uptime, dan layanan.
- Situs/domain/subdomain Nginx, static HTML, PHP-FPM per situs, perubahan runtime PHP.
- File manager: daftar folder, baca, edit teks, unggah, unduh, tambah folder, hapus file/folder kosong.
- MariaDB: database dan user terpisah, password, ganti password, ekspor SQL, hapus database.
- BIND DNS: A, AAAA, CNAME, MX, TXT, CAA, tambah/ubah/hapus rekaman.
- Email opsional: Postfix, Dovecot IMAP/LMTP, kotak email, password, penerusan.
- Let's Encrypt: penerbitan sertifikat, HTTPS, pembaruan melalui certbot.timer.
- SFTP per situs dengan public key, chroot, tanpa shell interaktif.
- Cron untuk skrip PHP milik situs.
- Redirect HTTP 302.
- Backup arsip file situs, unduh, pemulihan, hapus arsip.
- Restart/reload layanan yang diizinkan, log layanan dan error situs.
- Akun admin/operator/viewer, TOTP, CSRF, sesi tersimpan dan dapat dicabut.
- Antrean worker, hasil eksekusi, retry manual, audit aktivitas.

## Mulai dari sini

1. Baca `docs/INSTALL.md` untuk pemasangan pada VPS Ubuntu baru.
2. Baca `docs/USER_GUIDE.md` untuk langkah penggunaan.
3. Baca `docs/FEATURE_MATRIX.md` untuk batas fitur dan status integrasi.
4. Baca `docs/VERIFICATION.md` untuk hasil pengujian.

Instalasi VPS:

```bash
unzip syPanel_v1.0_Developer_Preview.zip
cd syPanel
sudo bash deploy/install.sh
```

Installer meminta konfirmasi `INSTALL`, kemudian password admin. Tidak ada password admin bawaan. Setelah selesai, buka `https://IP-SERVER:2083`.

## Menjalankan sandbox lokal

Mode ini mengelola file dan metadata lokal. Tidak memasang atau mengubah layanan Ubuntu. DNS, email, database, SSL, dan perubahan layanan disimulasikan secara eksplisit.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python manage.py create-admin
python manage.py dev
```

Buka `http://127.0.0.1:8080`. Data disimpan di `./var`. Perintah `dev` menjalankan web dan worker. File sandbox berada di `var/sandbox/sites/`.

## Pengujian

```bash
pip install -r requirements-dev.txt
python -m pytest tests -q
```

Pengujian menggunakan direktori sementara dan mode sandbox, tidak menyentuh layanan server host.

## Struktur

```text
syPanel/
  manage.py
  requirements.txt
  requirements-dev.txt
  sypanel/
    app.py          HTTP API, autentikasi, RBAC, audit
    core.py         model data, validasi, kriptografi, transport agent
    agent.py        operasi terbatas pada layanan Ubuntu
    worker.py       antrean pekerjaan
    fileops.py      operasi file di bawah UID situs
    templates/     antarmuka HTML
    static/        CSS dan JavaScript lokal
  deploy/
    install.sh
    enable-panel-ssl.sh
    mail.sh
  tests/
  docs/
```

## Status rilis

Kode aplikasi dan adapter layanan telah disertakan. Uji otomatis dilaksanakan pada sandbox. Installer, konfigurasi layanan, pengiriman email, delegasi DNS, dan penerbitan sertifikat belum diuji end-to-end pada VPS Ubuntu nyata dalam pembuatan paket ini. Gunakan VPS pengujian terlebih dahulu.

CloudLinux/CageFS, reseller, billing, kuota OS, WordPress Toolkit, webmail, spam filtering, PostgreSQL, terminal web, API token eksternal, DNSSEC, remote backup, serta pemulihan penuh server belum diimplementasikan. Rincian ada dalam matriks fitur.
