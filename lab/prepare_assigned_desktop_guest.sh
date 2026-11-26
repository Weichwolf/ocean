#!/bin/sh
# Run inside a newly provisioned disposable Debian desktop with the lab join password on stdin.
set -eu

test "$(id -u)" -eq 0
case "$1" in
    desk-one|desk-two) guest=$1 ;;
    *) exit 1 ;;
esac
hostnamectl set-hostname "$guest.ad.pair.ocean.test"
printf '127.0.1.1 %s.ad.pair.ocean.test %s\n' "$guest" "$guest" >> /etc/hosts
rm -f /etc/resolv.conf
printf '%s\n' 'nameserver 10.232.1.29' 'search ad.pair.ocean.test' > /etc/resolv.conf
sed -i 's/^hosts:.*/hosts: files dns/' /etc/nsswitch.conf
cat > /etc/krb5.conf <<'EOF'
[libdefaults]
    default_realm = AD.PAIR.OCEAN.TEST
    dns_lookup_kdc = true
    rdns = false
EOF
adcli join --domain=ad.pair.ocean.test --domain-controller=pair-dc.ad.pair.ocean.test \
    --login-user=Administrator --computer-name="$guest" --host-fqdn="$guest.ad.pair.ocean.test" --stdin-password
umask 077
cat > /etc/sssd/sssd.conf <<'EOF'
[sssd]
domains = ad.pair.ocean.test
services = nss, pam

[domain/ad.pair.ocean.test]
id_provider = ad
access_provider = ad
ad_domain = ad.pair.ocean.test
ad_server = pair-dc.ad.pair.ocean.test
krb5_realm = AD.PAIR.OCEAN.TEST
ad_gpo_map_remote_interactive = +xrdp-sesman
use_fully_qualified_names = True
ldap_id_mapping = True
default_shell = /bin/bash
fallback_homedir = /home/%u@%d
debug_level = 2
EOF
printf 'ldap_sasl_authid = %s$@AD.PAIR.OCEAN.TEST\n' "$guest" >> /etc/sssd/sssd.conf
chmod 0600 /etc/sssd/sssd.conf
DEBIAN_FRONTEND=noninteractive pam-auth-update --enable sss --enable mkhomedir
printf '%s\n' 'exec openbox-session' > /etc/skel/.xsession
chmod 0644 /etc/skel/.xsession
sed -i 's/^TerminalServerUsers=.*/TerminalServerUsers=domain users@ad.pair.ocean.test/; s/^AlwaysGroupCheck=.*/AlwaysGroupCheck=true/' /etc/xrdp/sesman.ini
systemctl restart sssd.service
