# Offensive Security / PenTesting Cheatsheets
Disclaimer: I did not claim ownership of netcat and linux privilege escalation or reverse shell scripts.
Heavily inspired and based on https://github.com/dostoevskylabs/dostoevsky-pentest-notes

## Reconnaissance / Enumeration

##### DNS lookups, Zone Transfers & Brute-Force
```bash
whois domain.com
dig {a|txt|ns|mx} domain.com
dig {a|txt|ns|mx} domain.com @ns1.domain.com
host -l megacorpon.com ns1.megacorpone.com
dnsrecon -d domain.com -t axfr @ns1.domain.com
dnsenum domain.com
nslookup -> set type=any -> ls -d domain.com
for sub in $(cat subdomains.txt);do host $sub.domain.com|grep "has.address";done
dnsrecon -d $TARGET -D wordlist.txt -t std --xml output.xml
```

##### Banner Grabbing
```bash
nc -v $TARGET 80
telnet $TARGET 80
curl -vX $TARGET
```

##### Port Scanning with NetCat
```bash
nc -nvv -w 1 -z host 1000-2000
nc -nv -u -z -w 1 host 160-162
```

##### HTTP Brute-Force & Vulnerability Scanning
```bash
target=10.0.0.1; gobuster -u http://$target -r -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 150 -l | tee /root/tools/$target/$target-gobuster
target=10.0.0.1; nikto -h http://$target:80 | tee $target/$target-nikto
target=10.0.0.1; wpscan --url http://$target:80 --enumerate u,t,p | tee $target/$target-wpscan-enum
```

##### RPC / NetBios / SMB
```bash
rpcinfo -p $TARGET
nbtscan $TARGET

#list shares
smbclient -L //$TARGET

# null session
rpcclient -v "" $TARGET
smbclient -L //$TARGET
```




## Gaining Access



## Local Enumeration & Privilege Escalation

##### Searching files

```bash
# query the local db for a quick file find. Run updatedb before executing locate.
locate passwd 

# show which directory, defined in $PATH, the file is located
which nc wget curl php perl python netcat tftp telnet ftp

# search agressively and recursively across the filesystem
find /etc -iname *conf
```
