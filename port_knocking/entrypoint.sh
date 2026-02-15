#!/bin/sh
set -e

/usr/sbin/iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
/usr/sbin/iptables -A INPUT -p tcp --dport 2222 -j DROP

# Start sshd
/usr/sbin/sshd

# Start knockd
exec /usr/sbin/knockd -D -c /etc/knockd.conf
