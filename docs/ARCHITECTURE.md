# Arsitektur

## Komponen dan alur

Browser mengakses Nginx HTTPS pada 2083. Nginx meneruskan permintaan ke Gunicorn pada loopback 8090. Flask memverifikasi sesi, CSRF, dan role. Perubahan dicatat sebagai resource pending dan job terenkripsi dalam SQLite. Worker mengambil satu pekerjaan melalui transaksi `BEGIN IMMEDIATE`, lalu mengirim operasi ke agent melalui Unix socket.

Agent berjalan sebagai root. Ia menerima koneksi hanya dari UID `sypanel` berdasarkan Linux `SO_PEERCRED`, memvalidasi ulang data, dan menjalankan operasi yang tercantum dalam allowlist. Tidak ada endpoint perintah root bebas. Permintaan baca (metrik, log, file manager, unduhan) dilayani paralel, sedangkan operasi yang mengubah server dijalankan berurutan. Agent memegang state sendiri, hanya dapat ditulis root. Worker menandai resource aktif setelah agent berhasil.

Akses file, termasuk pembuatan dan pemulihan backup serta file awal situs, dilakukan agent melalui proses `runuser` dengan UID situs. Root tidak membaca atau menulis di dalam public_html. Helper menggunakan descriptor relatif, `O_NOFOLLOW`, pemeriksaan tipe file dan penolakan hardlink saat menulis. Proses PHP setiap situs juga memakai user OS yang berbeda. SFTP memakai chroot milik root dengan subdirektori public_html milik user situs.

## Batas kepercayaan

Admin dan operator panel merupakan pengelola server yang dipercaya mengelola semua situs. Panel tidak menerima pelanggan hosting yang tidak dipercaya sebagai akun tenant. Pemisahan UID dan chroot SFTP belum setara isolasi container atau CageFS. PHP memiliki open_basedir, tetapi tidak ada batas resource per tenant, sandbox syscall, atau jaminan isolasi multi-tenant. Jangan menganggap open_basedir sebagai batas keamanan setara container.

Root agent mempercayai UID aplikasi untuk meminta operasi yang diizinkan. Kompromi proses aplikasi dapat mengubah konfigurasi hosting yang dikelola. Kode/venv harus tetap dimiliki root dan tidak ditulis UID aplikasi atau situs. Agent tidak memakai sudo wildcard.

## Penyimpanan

SQLite panel memakai WAL, foreign keys, transaksi, dan timeout lock 30 detik. Cocok untuk satu panel server dengan antrean serial. Bukan database aplikasi website. Website menggunakan MariaDB.

| Tabel | Tujuan |
| --- | --- |
| users | Identitas, hash password, role, TOTP terenkripsi |
| sessions | Token sesi acak, user, waktu habis |
| resources | Jenis, nama unik, metadata publik, status |
| jobs | Aksi, payload terenkripsi, status, pesan, waktu |
| audit | Aktor, aksi, detail ringkas, IP, waktu |
| attempts | Pembatasan percobaan login |

Password akun di-hash oleh Werkzeug scrypt. Password database/email transit dalam payload Fernet dan dihapus dari job setelah keberhasilan. Payload pekerjaan gagal dipertahankan terenkripsi untuk retry, sehingga kunci aplikasi harus diproteksi. Password email disimpan sebagai hash SHA512-CRYPT yang kompatibel dengan Dovecot. Password database diberikan melalui stdin klien MariaDB, bukan argumen proses.

## Kegagalan dan konsistensi

Worker memproses satu pekerjaan pada satu waktu. Pekerjaan berstatus running saat startup ulang ditandai failed agar mutasi tidak diulang otomatis. Operasi lintas OS dan database tidak berada dalam satu transaksi ACID. File konfigurasi Nginx/PHP diuji sebelum reload, dan konfigurasi lama dicoba dipulihkan jika validasi/reload gagal.

Pembuatan user OS, database, file dan sertifikat dapat meninggalkan efek parsial saat kegagalan. State perlu direkonsiliasi administrator jika agent berhenti di antara perubahan layanan dan penulisan state. Retry bukan jaminan exactly-once. Backup/restore tidak memiliki snapshot filesystem atau transaksi seluruh server.

## HTTP

Sesi cookie HttpOnly, SameSite Strict dan Secure pada mode live. CSRF wajib pada mutasi termasuk login. CSP melarang skrip inline, objek, framing, dan koneksi eksternal. File statis, CSS, dan JavaScript tersedia lokal. Nginx mengganti header proxy, dan Flask mempercayai tepat satu proxy pada mode live. Gunicorn harus tetap hanya listen di loopback. Rate limit dihitung per IP terusan (IPv6 per prefiks /64), lima kegagalan per lima menit. Username sengaja tidak dikunci agar pihak luar tidak dapat mengunci akun admin; lindungi akun dengan password kuat dan TOTP.

## Referensi implementasi

- Nginx virtual host dan FastCGI: https://nginx.org/en/docs/http/request_processing.html
- Nginx FastCGI: https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html
- Flask web security: https://flask.palletsprojects.com/en/stable/web-security/
- Certbot webroot: https://eff-certbot.readthedocs.io/en/stable/using.html
- Dovecot passwd-file: https://doc.dovecot.org/2.3/configuration_manual/authentication/passwd_file/
- Dovecot password schemes: https://doc.dovecot.org/2.3/configuration_manual/authentication/password_schemes/

Dokumentasi rujukan mendasari struktur konfigurasi. Kompatibilitas akhir perlu diuji pada paket Ubuntu target.
