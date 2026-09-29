#!/usr/bin/env bash
# Optional single-server mail integration on fresh Ubuntu 22.04/24.04 (Dovecot 2.3).
set -Eeuo pipefail
[[ $EUID -eq 0 && $# -eq 1 ]] || { echo 'Penggunaan: sudo bash deploy/mail.sh mail.contoh.id'; exit 1; }
mail_host="$1"
/opt/sypanel/.venv/bin/python - "$mail_host" <<'PY'
import sys
sys.path.insert(0,'/opt/sypanel')
from sypanel.core import domain
if domain(sys.argv[1])!=sys.argv[1]: raise SystemExit('Nama host harus huruf kecil.')
PY
[[ ! -e /etc/sypanel-mail.enabled ]] || { echo 'Integrasi email sudah ada.'; exit 1; }
[[ -f "/etc/letsencrypt/live/$mail_host/fullchain.pem" ]] || { echo 'Buat situs untuk hostname email lalu terbitkan SSL melalui syPanel terlebih dahulu.'; exit 1; }
printf '%s\n' 'Skrip ini memasang konfigurasi Postfix dan Dovecot untuk syPanel. Gunakan layanan email baru.'
read -r -p 'Ketik MAIL untuk melanjutkan: ' mail_reply
[[ "$mail_reply" == MAIL ]] || exit 1
# Fixed vmail ID is intentionally checked before provisioning.
if getent passwd 5000 >/dev/null && [[ "$(getent passwd 5000 | cut -d: -f1)" != vmail ]]; then echo 'UID 5000 sudah digunakan.'; exit 1; fi
if getent group 5000 >/dev/null && [[ "$(getent group 5000 | cut -d: -f1)" != vmail ]]; then echo 'GID 5000 sudah digunakan.'; exit 1; fi
export DEBIAN_FRONTEND=noninteractive
printf 'postfix postfix/mailname string %s\npostfix postfix/main_mailer_type select Internet Site\n' "$mail_host" | debconf-set-selections
apt-get install -y postfix dovecot-core dovecot-imapd dovecot-lmtpd
getent group vmail >/dev/null || groupadd -g 5000 vmail
id vmail >/dev/null 2>&1 || useradd -u 5000 -g vmail -d /var/vmail -s /usr/sbin/nologin vmail
[[ $(id -u vmail) == 5000 && $(id -g vmail) == 5000 ]] || { echo 'Akun vmail harus menggunakan UID/GID 5000.'; exit 1; }
install -d -m 0750 -o vmail -g vmail /var/vmail
install -d -m 0750 -o root -g postfix /etc/postfix/sypanel
cp -a /etc/postfix/main.cf /etc/postfix/main.cf.before-sypanel
cp -a /etc/postfix/master.cf /etc/postfix/master.cf.before-sypanel
postconf -e "myhostname = $mail_host" 'mydestination = localhost' 'inet_interfaces = all' 'mynetworks = 127.0.0.0/8 [::1]/128' \
 'virtual_mailbox_domains = hash:/etc/postfix/sypanel/domains' 'virtual_mailbox_maps = hash:/etc/postfix/sypanel/mailboxes' \
 'virtual_alias_maps = hash:/etc/postfix/sypanel/aliases' 'virtual_transport = lmtp:unix:private/dovecot-lmtp' \
 'smtpd_sasl_type = dovecot' 'smtpd_sasl_path = private/auth' 'smtpd_sasl_auth_enable = no' \
 'smtpd_tls_security_level = may' 'smtpd_tls_auth_only = yes' \
 "smtpd_tls_cert_file = /etc/letsencrypt/live/$mail_host/fullchain.pem" "smtpd_tls_key_file = /etc/letsencrypt/live/$mail_host/privkey.pem" \
 'smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination'
postconf -M 'submission/inet=submission inet n - y - - smtpd'
postconf -P 'submission/inet/syslog_name=postfix/submission' 'submission/inet/smtpd_tls_security_level=encrypt' 'submission/inet/smtpd_sasl_auth_enable=yes' 'submission/inet/smtpd_relay_restrictions=permit_sasl_authenticated,reject'
for map in domains mailboxes aliases; do touch "/etc/postfix/sypanel/$map"; postmap "/etc/postfix/sypanel/$map"; done
chown -R root:postfix /etc/postfix/sypanel
chmod 0640 /etc/postfix/sypanel/*
# Disable system user authentication. Only managed virtual mailboxes are accepted.
cp -a /etc/dovecot/conf.d/10-auth.conf /etc/dovecot/conf.d/10-auth.conf.before-sypanel
cat > /etc/dovecot/conf.d/10-auth.conf <<'AUTH'
disable_plaintext_auth = yes
auth_mechanisms = plain login
!include auth-sypanel.conf.ext
AUTH
cat > /etc/dovecot/conf.d/auth-sypanel.conf.ext <<'AUTH'
passdb {
 driver = passwd-file
 args = /etc/dovecot/sypanel-users
}
userdb {
 driver = passwd-file
 args = /etc/dovecot/sypanel-users
}
AUTH
cat > /etc/dovecot/conf.d/99-sypanel.conf <<MAIL
protocols = imap lmtp
mail_location = maildir:~/Maildir
first_valid_uid = 5000
ssl = required
ssl_cert = </etc/letsencrypt/live/$mail_host/fullchain.pem
ssl_key = </etc/letsencrypt/live/$mail_host/privkey.pem
service lmtp {
 unix_listener /var/spool/postfix/private/dovecot-lmtp {
  mode = 0600
  user = postfix
  group = postfix
 }
}
service auth {
 unix_listener /var/spool/postfix/private/auth {
  mode = 0660
  user = postfix
  group = postfix
 }
}
MAIL
touch /etc/dovecot/sypanel-users
chown root:dovecot /etc/dovecot/sypanel-users
chmod 0640 /etc/dovecot/sypanel-users
doveconf -n >/dev/null
postfix check
systemctl enable --now postfix dovecot
systemctl restart postfix dovecot
cat > /etc/letsencrypt/renewal-hooks/deploy/sypanel-mail <<'HOOK'
#!/bin/sh
/bin/systemctl reload postfix
/bin/systemctl reload dovecot
HOOK
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/sypanel-mail
touch /etc/sypanel-mail.enabled
printf 'Integrasi email siap. Host: %s, IMAPS: 993, SMTP submission: 587 STARTTLS.\n' "$mail_host"
