#!/bin/bash
mkdir $1
nmap $1 -sV -Pn -vv| tee $1/$1-nmap-quick
gobuster -e php,html -u http://$1:80 -l /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee $1/$1-dirbuster
nmap $1 -Pn -A -vv -sC -sS -T4 -p- | tee $1/$1-nmap-full
nikto -h http://$1:80 | tee $1/$1-nikto
sdsd

# wpscan?
# smb scan
# smtp scan
# snmp scan
