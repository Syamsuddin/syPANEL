#!/usr/bin/env bash
set -Eeuo pipefail
umask 027
[[ ${EUID} -eq 0 ]] || { echo 'Jalankan installer sebagai root.'; exit 1; }
source /etc/os-release
[[ "$ID" == ubuntu && ( "$VERSION_ID" == 22.04 || "$VERSION_ID" == 24.04 ) ]] || { echo 'Dukungan installer: Ubuntu 22.04 / 24.04 LTS.'; exit 1; }
[[ ! -e /opt/sypanel ]] || { echo '/opt/sypanel sudah ada. Installer baru tidak menimpa instalasi.'; exit 1; }
for conflict in /usr/local/cpanel /usr/local/psa /usr/local/hestia /usr/local/CyberCP; do
  [[ ! -e "$conflict" ]] || { echo 'Panel hosting lain terdeteksi. Gunakan VPS baru.'; exit 1; }
done
printf '%s\n' 'syPanel akan memasang Nginx, MariaDB, BIND, PHP, SSH, dan layanan panel pada VPS ini.' 'Gunakan VPS Ubuntu baru yang dikhususkan untuk syPanel.'
read -r -p 'Ketik INSTALL untuk melanjutkan: ' install_reply
[[ "$install_reply" == INSTALL ]] || exit 1
src_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3-venv python3-dev nginx mariadb-server bind9 bind9utils dnsutils certbot python3-certbot-nginx acl rsync php-fpm php-cli php-mysql php-xml php-mbstring php-curl php-zip php-gd php-bcmath php-intl unzip cron openssh-server openssl ca-certificates build-essential
getent group sypanel-sites >/dev/null || groupadd --system sypanel-sites
id sypanel >/dev/null 2>&1 || useradd --system --user-group --create-home --home-dir /var/lib/sypanel --shell /usr/sbin/nologin sypanel
install -d -m 0755 /opt/sypanel /srv/sypanel/sites /etc/ssh/sypanel /etc/nginx/conf.d /etc/bind/sypanel
install -d -m 0700 /var/lib/sypanel-agent /var/backups/sypanel
install -d -m 0700 -o sypanel -g sypanel /var/lib/sypanel
rsync -a --exclude '.venv' --exclude 'var' --exclude '__pycache__' --exclude '.pytest_cache' --exclude 'tests' --exclude '*.pyc' "$src_dir/" /opt/sypanel/
chown -R root:root /opt/sypanel
python3 -m venv /opt/sypanel/.venv
/opt/sypanel/.venv/bin/pip install --upgrade pip
/opt/sypanel/.venv/bin/pip install -r /opt/sypanel/requirements.txt
chmod -R go+rX /opt/sypanel
install -d -m 0750 -o root -g sypanel /etc/sypanel
cat > /etc/sypanel/panel.env <<'ENV'
SYPANEL_MODE=live
SYPANEL_DATA=/var/lib/sypanel
SYPANEL_SOCKET=/run/sypanel/agent.sock
PYTHONDONTWRITEBYTECODE=1
ENV
chmod 0640 /etc/sypanel/panel.env
chown root:sypanel /etc/sypanel/panel.env
cat > /etc/bind/sypanel/zones.conf <<'BIND'
// Zones managed by syPanel.
BIND
chmod 0644 /etc/bind/sypanel/zones.conf
if ! grep -qF 'include "/etc/bind/sypanel/zones.conf";' /etc/bind/named.conf.local; then
  printf '\ninclude "/etc/bind/sypanel/zones.conf";\n' >> /etc/bind/named.conf.local
fi
cp -a /etc/bind/named.conf.options /etc/bind/named.conf.options.before-sypanel
cat > /etc/bind/named.conf.options <<'BIND'
options {
 directory "/var/cache/bind";
 recursion no;
 allow-query { any; };
 allow-transfer { none; };
 listen-on { any; };
 listen-on-v6 { any; };
 dnssec-validation auto;
};
BIND
named-checkconf
# Initial certificate. Replace through enable-panel-ssl.sh after DNS is ready.
openssl req -x509 -nodes -newkey rsa:3072 -days 30 -keyout /etc/sypanel/panel.key -out /etc/sypanel/panel.crt -subj '/CN=syPanel.local'
chmod 0600 /etc/sypanel/panel.key
cat > /etc/nginx/conf.d/sypanel-control.conf <<'NGINX'
server {
 listen 2083 ssl;
 server_name _;
 ssl_certificate /etc/sypanel/panel.crt;
 ssl_certificate_key /etc/sypanel/panel.key;
 ssl_protocols TLSv1.2 TLSv1.3;
 client_max_body_size 24m;
 location / {
  proxy_pass http://127.0.0.1:8090;
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $remote_addr;
  proxy_set_header X-Forwarded-Proto https;
  proxy_read_timeout 250s;
 }
}
NGINX
cat > /etc/systemd/system/sypanel-agent.service <<'UNIT'
[Unit]
Description=syPanel privileged hosting agent
After=network.target nginx.service mariadb.service
[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/sypanel
Environment=SYPANEL_DATA=/var/lib/sypanel-agent
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/opt/sypanel/.venv/bin/python -m sypanel.agent
Restart=on-failure
RestartSec=5
RuntimeDirectory=sypanel
RuntimeDirectoryMode=0755
UMask=0027
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/sypanel-web.service <<'UNIT'
[Unit]
Description=syPanel web application
After=network.target sypanel-agent.service
[Service]
User=sypanel
Group=sypanel
WorkingDirectory=/opt/sypanel
EnvironmentFile=/etc/sypanel/panel.env
ExecStart=/opt/sypanel/.venv/bin/gunicorn --workers 2 --threads 4 --bind 127.0.0.1:8090 --timeout 250 --access-logfile - sypanel.app:app
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/sypanel
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/sypanel-worker.service <<'UNIT'
[Unit]
Description=syPanel server job worker
After=sypanel-agent.service
[Service]
User=sypanel
Group=sypanel
WorkingDirectory=/opt/sypanel
EnvironmentFile=/etc/sypanel/panel.env
ExecStart=/opt/sypanel/.venv/bin/python -m sypanel.worker
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/sypanel
[Install]
WantedBy=multi-user.target
UNIT
cat > /usr/local/bin/sypanel-admin <<'CLI'
#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Gunakan sudo.'; exit 1; }
cd /opt/sypanel
exec runuser -u sypanel -- env SYPANEL_MODE=live SYPANEL_DATA=/var/lib/sypanel SYPANEL_SOCKET=/run/sypanel/agent.sock /opt/sypanel/.venv/bin/python manage.py "$@"
CLI
chmod 0755 /usr/local/bin/sypanel-admin
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/sypanel-nginx <<'HOOK'
#!/bin/sh
/usr/sbin/nginx -t && /bin/systemctl reload nginx
HOOK
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/sypanel-nginx
# Initialize panel DB before workers start.
sypanel-admin init
printf '\nBuat akun administrator panel.\n'
sypanel-admin create-admin --username admin
nginx -t
systemctl daemon-reload
systemctl enable --now nginx mariadb named ssh cron certbot.timer sypanel-agent sypanel-web sypanel-worker
systemctl reload nginx
systemctl restart named
printf '\nsyPanel terpasang. Buka https://IP-SERVER:2083\nSertifikat awal bersifat sementara. Pasang sertifikat domain dengan deploy/enable-panel-ssl.sh.\nAturan firewall tidak diubah. Lihat docs/INSTALL.md untuk port yang diperlukan.\n'
