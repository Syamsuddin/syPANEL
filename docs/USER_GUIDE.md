# Panduan pengguna syPanel

## Alur membuat website PHP

1. Masuk sebagai admin atau operator.
2. Pilih Website & domain, klik Tambah website.
3. Isi domain tanpa `http://`, pilih PHP yang tersedia.
4. Buka Antrean pekerjaan. Tunggu status Selesai dan situs Aktif.
5. Arahkan DNS domain ke IP VPS.
6. Buka File manager atau gunakan SFTP. Unggah aplikasi ke `public_html`.
7. Buat database. Nama database dan user menggunakan awalan `sy_`, host `localhost`.
8. Simpan password database pada konfigurasi aplikasi. Password tidak dapat dibaca kembali melalui panel.
9. Pilih SSL & HTTPS, terbitkan sertifikat setelah DNS aktif.
10. Periksa situs dan log error.

Masing-masing domain atau subdomain dibuat sebagai situs tersendiri. Domain alias dengan document root bersama belum tersedia. Framework seperti Laravel memerlukan penyesuaian struktur direktori dan konfigurasi deployment oleh administrator, karena document root versi ini tetap pada `public_html`.

## Mengubah dan menghapus

Tombol Ubah tersedia untuk runtime situs, password database/email, DNS, penerusan, cron, kunci SFTP, dan redirect. Domain induk objek tidak dapat dipindahkan. Untuk database dan email, nama objek tetap saat penggantian password.

Penghapusan meminta pengetikan nama objek. Database dihapus dari MariaDB. Backup dihapus dari disk. Penghapusan situs menonaktifkan konfigurasi Nginx/PHP dan akses SFTP, tetapi direktori situs dan akun OS dipertahankan. Hapus objek terkait sebelum menonaktifkan situs.

Email yang dihapus tidak otomatis menghapus Maildir lama. Pembersihan file situs, user OS, dan Maildir dilakukan administrator setelah masa retensi yang ditetapkan organisasi.

## File manager

- Pilih situs aktif lalu jelajahi folder.
- Folder baru dibuat di lokasi saat ini.
- Editor ditujukan untuk teks UTF-8, sekitar 2 MiB maksimum pada antarmuka.
- Unggah/unduh file melalui panel maksimal 16 MiB per file.
- File dengan nama sama akan ditimpa saat penyimpanan atau unggah.
- Folder hanya dapat dihapus jika kosong.
- Link simbolik tidak dapat dibuka melalui panel. Traversal keluar direktori situs ditolak.
- Gunakan SFTP untuk transfer file yang lebih besar. Ekstraksi ZIP belum tersedia melalui UI.

## SFTP

1. Buat pasangan kunci di komputer sendiri, misalnya `ssh-keygen -t ed25519`.
2. Tambahkan isi file `.pub` pada menu SFTP & SSH keys.
3. Lihat user OS pada daftar Website & domain. Bentuknya `sy` diikuti hash domain.
4. Pada klien SFTP, isi host IP VPS, port 22, username OS tersebut, dan private key.
5. File tersedia di `/public_html` dalam lingkungan chroot.

Kunci ini hanya untuk SFTP. Akun situs tidak mendapat terminal SSH interaktif, tunneling, atau login password. Admin server tetap mengakses SSH menggunakan akun administrasi Ubuntu yang sudah ada.

## Cron

Buat file PHP terlebih dahulu. Contoh path `jobs/sinkron.php`, jadwal `*/5 * * * *` untuk setiap lima menit. Jadwal mengikuti zona waktu server. Cron memakai `/usr/bin/php`, yakni versi CLI default server. Versi CLI belum dapat dipilih per jadwal. Output dibuang, sehingga aplikasi harus mencatat hasil ke file/log sendiri.

## Backup dan pemulihan

Backup mengarsip file website biasa dan folder. Symlink serta file khusus tidak diikutkan. Arsip tersimpan lokal pada VPS. Backup tidak mencakup database, email, sertifikat, atau seluruh akun panel.

Pemulihan menimpa file bernama sama. File tambahan setelah backup tetap ada. Folder dibuat bila belum ada. Pemulihan tidak transaksional, sehingga kegagalan di tengah proses dapat menghasilkan sebagian file sudah dipulihkan. Buat cadangan sebelum pemulihan.

Batas restore panel: ukuran terurai total 2 GiB, maksimal 16 MiB per file. Arsip unduhan panel maksimal 64 MiB. Ambil arsip lebih besar melalui SSH administrator. Untuk database, gunakan Ekspor SQL pada menu Database. Impor/pemulihan SQL dilakukan administrator secara terpisah.

## Pengguna

| Role | Akses |
| --- | --- |
| Admin | Semua situs, operasi layanan, pengguna, audit, pemulihan, retry pekerjaan |
| Operator | Semua situs dan layanan hosting, file, log. Tidak mengelola pengguna atau restart layanan |
| Viewer | Ringkasan, inventaris, status, antrean, pengaturan akun sendiri. Tidak membaca isi file/log |

Role ini untuk tim pengelola satu server. Bukan akun hosting pelanggan. Seluruh admin/operator dipercaya mengelola seluruh situs.

## Autentikator dan sesi

Dari Pengaturan akun, pasang TOTP dengan memasukkan secret secara manual ke aplikasi autentikator. Gunakan SHA-1, 6 digit, periode 30 detik. Konfirmasi memakai password akun dan kode. Kode yang telah dipakai ditolak untuk mencegah replay. Tidak ada kode pemulihan otomatis, gunakan CLI administrator jika perangkat hilang.

Sesi aktif berlaku delapan jam. Ganti password mencabut sesi lain. Logout mencabut sesi saat ini.

## Antrean gagal

Status Aktif hanya diberikan setelah agent melaporkan operasi selesai. Periksa pesan pada Antrean pekerjaan jika status gagal. Retry hanya tersedia bagi admin. Jangan mengulang pekerjaan yang sempat terputus tanpa memeriksa efeknya di server, karena sebagian operasi layanan tidak transaksional.

Contoh: pembuatan database dapat berhasil pada CREATE DATABASE tetapi gagal pada CREATE USER. Administrator perlu meninjau dan membersihkan objek parsial sebelum retry. Gangguan listrik setelah layanan berubah namun sebelum state tersimpan memerlukan rekonsiliasi manual. Versi ini tidak mengklaim eksekusi exactly-once.
