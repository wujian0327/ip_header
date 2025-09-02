```bash
sudo iptables -I OUTPUT -p tcp -j NFQUEUE --queue-num 0
sudo iptables -A OUTPUT -p tcp --dport 8001 -j NFQUEUE --queue-num 0
sudo iptables -A OUTPUT -p tcp -d 106.54.227.154 -j NFQUEUE --queue-num 0
sudo iptables -A OUTPUT -p tcp -s 192.168.1.53 -j NFQUEUE --queue-num 0
```

```sql


```