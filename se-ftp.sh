#!/bin/bash
mkdir $1 2>/dev/null

nmap $1 -vv -Pn -p21 --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN $1/$1-nmap-ftp
