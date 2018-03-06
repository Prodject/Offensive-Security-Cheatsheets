#!/bin/bash
mkdir -p /root/tools/$1 2>/dev/null
resultsFolder=/root/tools/$1

nmap $1 -vv -Pn -p21 --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN $resultsFolder/$1-nmap-ftp
