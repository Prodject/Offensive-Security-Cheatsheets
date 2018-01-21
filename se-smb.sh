#!/bin/bash
mkdir $1 2>/dev/null

# SMB *****************************************************************************************************
# https://monkeysm8.gitbooks.io/pentesting-methodology/common_portsservices_and_how_to_use_them/port_139_and_445-_smbsamba_shares.html
showmount -e $1 | tee $1/$1-showmount
enum4linux -a $1 | tee $1/$1-enum4linux
nmap $1 -vv -Pn -p445 --script=smb-enum-shares.nse,smb-ls.nse,smb-enum-users.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-security-mode.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse,smbv2-enabled.nse -oN $1/$1-nmap-smb