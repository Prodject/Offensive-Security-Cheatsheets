#!/bin/bash
mkdir $1 2>/dev/null
nmap $1 -vv -Pn -sV -A -oN $1/$1-nmap-quick

gobuster -u http://$1 -r -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 200 -l | tee /root/tools/$1/$1-gobuster

#java -jar /usr/share/dirbuster/DirBuster-1.0-RC1.jar -e php,html -u http://$1:80 -l /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee $1/$1-dirbuster

# DNS *****************************************************************************************************
# dig axfr @nameserver domain.net | tee $1/$1-dns-zone-transfer

# NMAP extended - full and udp top 200 *****************************************************************************************************
nmap $1 -vv -Pn -A -sC -sS -T4 -p- -oN $1/$1-nmap-full
nmap $1 -vv -Pn -A -sC -sU -T4 --top-ports 200 -oN $1/$1-nmap-udp-top200
