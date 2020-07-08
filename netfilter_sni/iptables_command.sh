iptables -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 0
iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0
#iptables -A INPUT -j ACCEPT
#iptables -A OUTPUT -j ACCEPT
