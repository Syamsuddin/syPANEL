#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 && $# -eq 2 ]] || { echo 'Penggunaan: sudo bash deploy/enable-panel-ssl.sh panel.contoh.id admin@contoh.id'; exit 1; }
panel_domain="$1"
panel_email="$2"
/opt/sypanel/.venv/bin/python - "$panel_domain" "$panel_email" <<'PY'
import re,sys
sys.path.insert(0,'/opt/sypanel')
from sypanel.core import domain
if domain(sys.argv[1])!=sys.argv[1]: raise SystemExit('Gunakan domain huruf kecil tanpa titik akhir.')
if not re.fullmatch(r'[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+',sys.argv[2]): raise SystemExit('Email tidak valid.')
PY
install -d -m 0755 /var/lib/sypanel-acme
cp -a /etc/nginx/conf.d/sypanel-control.conf /etc/sypanel/control.before-ssl.conf
cat > /etc/nginx/conf.d/sypanel-acme.conf <<NGINX
server {
 listen 80;
 server_name $panel_domain;
 root /var/lib/sypanel-acme;
 location ^~ /.well-known/acme-challenge/ { allow all; }
 location / { return 301 https://$panel_domain:2083; }
}
NGINX
nginx -t
systemctl reload nginx
certbot certonly --webroot -w /var/lib/sypanel-acme -d "$panel_domain" --non-interactive --agree-tos --email "$panel_email"
cat > /etc/nginx/conf.d/sypanel-control.conf <<NGINX
server {
 listen 2083 ssl;
 server_name $panel_domain;
 ssl_certificate /etc/letsencrypt/live/$panel_domain/fullchain.pem;
 ssl_certificate_key /etc/letsencrypt/live/$panel_domain/privkey.pem;
 ssl_protocols TLSv1.2 TLSv1.3;
 client_max_body_size 24m;
 location / {
  proxy_pass http://127.0.0.1:8090;
  proxy_set_header Host \$host;
  proxy_set_header X-Real-IP \$remote_addr;
  proxy_set_header X-Forwarded-For \$remote_addr;
  proxy_set_header X-Forwarded-Proto https;
  proxy_read_timeout 250s;
 }
}
NGINX
nginx -t
systemctl reload nginx
printf 'Panel: https://%s:2083\n' "$panel_domain"
