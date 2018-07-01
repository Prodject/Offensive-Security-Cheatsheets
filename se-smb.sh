#!/bin/bash
mkdir -p /root/tools/$1 2>/dev/null
resultsFolder=/root/tools/$1

# SMB *****************************************************************************************************
# https://monkeysm8.gitbooks.io/pentesting-methodology/common_portsservices_and_how_to_use_them/port_139_and_445-_smbsamba_shares.html
# https://labs.mwrinfosecurity.com/blog/digging-into-ms14-068-exploitation-and-defence/ check for MS14-068 with an authenticated user
nmap $1 -vv -Pn -p445 --script=smb-enum-shares.nse,smb-ls.nse,smb-enum-users.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-security-mode.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse,smb-vuln-regsvc-dos.nse -oN $resultsFolder/$1-smb
smbmap -H $1 | tee -a $resultsFolder/$1-smb
showmount -e $1 | tee -a $resultsFolder/$1-showmount
enum4linux -R 500-550,1000-1050,2000-2050 -a $1 | tee $resultsFolder/$1-enum4linux

# smb users bruteforce
# nmap $1 -vv -Pn -p445 --script=smb-brute.nse --script-args passdb=/usr/share/wordlists/rockyou.txt,userdb=/usr/share/wordlists/names.txt -oN $resultsFolder/$1-nmap-smb-brute
