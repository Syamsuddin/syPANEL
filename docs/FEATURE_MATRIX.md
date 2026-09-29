# Matriks fitur syPanel 1.0.0

Status "diimplementasikan" berarti kode aplikasi dan adapter tersedia. Integrasi live memerlukan pemasangan dan pengujian pada VPS target. Sandbox tidak membuktikan bahwa layanan eksternal sudah bekerja.

| Kelompok | Fitur | Status versi ini |
| --- | --- | --- |
| Dashboard | CPU, RAM, disk, uptime, hostname | Diimplementasikan dengan psutil |
| Dashboard | Status layanan | Diimplementasikan dengan systemd |
| Dashboard | Statistik trafik/AWStats per domain | Belum tersedia |
| Website | Buat/hapus domain dan subdomain | Diimplementasikan, satu virtual host per domain |
| Website | Domain alias/shared document root | Belum tersedia |
| Website | PHP-FPM per situs | Diimplementasikan, user OS per situs |
| Website | Pilih/ubah PHP 8.1 atau 8.3 | Diimplementasikan jika versi terpasang |
| Website | PHP INI editor | Belum tersedia |
| Website | Redirect HTTP 302 | Diimplementasikan |
| Website | Pilihan 301, path redirect, wildcard | Belum tersedia |
| File | Baca, edit teks, unggah, unduh | Diimplementasikan |
| File | Folder baru, hapus folder kosong | Diimplementasikan |
| File | Rename/move/copy, ZIP extract | Belum tersedia |
| File | Editor permission/chmod | Belum tersedia |
| Transfer | SFTP SSH key + chroot | Diimplementasikan |
| Transfer | FTP/FTPS, WebDAV/Web Disk | Belum tersedia |
| Database | MariaDB create/drop dan user | Diimplementasikan |
| Database | Ganti password user aplikasi | Diimplementasikan |
| Database | Ekspor SQL | Diimplementasikan |
| Database | Impor SQL melalui UI | Belum tersedia |
| Database | phpMyAdmin atau SQL browser | Belum disertakan |
| Database | PostgreSQL/phpPgAdmin | Belum tersedia |
| DNS | A, AAAA, CNAME, MX, TXT, CAA | Diimplementasikan pada BIND |
| DNS | Tambah/ubah/hapus rekaman | Diimplementasikan |
| DNS | Nameserver sekunder, cluster | Belum tersedia |
| DNS | DNSSEC, SRV, registrar API | Belum tersedia |
| DNS | Cloudflare API | Belum tersedia |
| Email | Kotak email virtual | Diimplementasikan, installer opsional |
| Email | Ganti password email | Diimplementasikan |
| Email | SMTP submission dan IMAPS | Adapter konfigurasi disertakan |
| Email | Penerusan satu tujuan | Diimplementasikan |
| Email | Webmail | Belum tersedia |
| Email | Autoresponder, mailing list | Belum tersedia |
| Email | DKIM signing, SPF/DMARC wizard | Belum tersedia, TXT DNS ditulis manual |
| Email | SpamAssassin/Rspamd, antivirus | Belum tersedia |
| Email | Kuota mailbox, delivery tracking | Belum tersedia |
| SSL | Let's Encrypt webroot | Diimplementasikan |
| SSL | Renewal timer dan reload hook | Disertakan dalam installer |
| SSL | Wildcard DNS challenge | Belum tersedia |
| SSL | Sertifikat custom/upload CSR | Belum tersedia |
| Backup | Arsip file website lokal | Diimplementasikan |
| Backup | Unduh dan restore file situs | Diimplementasikan dengan batas ukuran |
| Backup | Backup seluruh akun/server | Belum tersedia |
| Backup | Remote S3/SFTP, jadwal/retensi | Belum tersedia |
| Otomasi | Cron skrip PHP | Diimplementasikan |
| Otomasi | Perintah shell bebas | Tidak diberikan melalui panel |
| Developer | Git repository dan deployment | Belum tersedia |
| Developer | Node.js/Python application manager | Belum tersedia |
| Developer | WordPress Toolkit/installer CMS | Belum tersedia |
| Keamanan | Hash password, CSRF, cookie aman | Diimplementasikan |
| Keamanan | TOTP, rate limit login | Diimplementasikan |
| Keamanan | Sesi dapat dicabut, audit | Diimplementasikan |
| Keamanan | Root agent Unix socket peer UID | Diimplementasikan |
| Keamanan | WAF, ModSecurity, malware scanner | Belum tersedia |
| Keamanan | IP blocker, hotlink, directory auth | Belum tersedia |
| Server | Layanan allowlist, restart/reload | Diimplementasikan |
| Server | Journal dan error log situs | Diimplementasikan |
| Server | Terminal web | Belum tersedia |
| Pengguna | Admin/operator/viewer | Diimplementasikan untuk tim server |
| Hosting | Pelanggan per tenant, reseller | Belum tersedia |
| Hosting | Paket/kuota/billing | Belum tersedia |
| Hosting | Isolasi setara CageFS/LVE | Belum tersedia |
| Migrasi | Impor backup cPanel | Belum tersedia |
| Platform | REST API berbasis sesi UI | Diimplementasikan |
| Platform | API token, webhook, plugin system | Belum tersedia |

## Tahap pengembangan berikutnya

1. Validasi integrasi pada VM Ubuntu 22.04 dan 24.04, termasuk restart, renewal, dan pemulihan saat kegagalan.
2. Migrasi skema database, rekonsiliasi state, idempotency dan rollback operasi multi-layanan.
3. Akun pelanggan, ownership per resource, quota OS, pembatasan proses/memori dan pengujian isolasi.
4. Backup penuh yang konsisten, retensi, storage di luar server, pemulihan teruji.
5. DKIM, antispam, kuota email, webmail dan delivery tracking.
6. Git deployment, installer CMS, PHP INI dan database browser.
7. WAF, pemindaian malware, security monitoring dan audit independen.

Urutan ini memprioritaskan keandalan operasi server sebelum memperluas fitur hosting publik.
