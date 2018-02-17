# Offensive Security / PenTesting Cheatsheets
Disclaimer: I did not claim ownership of netcat and linux privilege escalation or reverse shell scripts.
Heavily inspired and based on https://github.com/dostoevskylabs/dostoevsky-pentest-notes

## Reconnaissance / Enumeration

##### DNS
```bash
whois domain.com
dig {a|txt|ns|mx} domain.com
dig {a|txt|ns|mx} domain.com @ns1.domain.com
```

##### Banner Grabbing
```bash
nc -v $TARGET 80
telnet $TARGET 80
amap -bqv1 1-65535 $TARGET
```




## Gaining Access



## Local Enumeration & Privilege Escalation
