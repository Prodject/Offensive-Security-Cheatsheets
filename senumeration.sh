#!/bin/bash
mkdir -p /root/tools/$1 2>/dev/null
resultsFolder=/root/tools/$1
mkdir $resultsFolder/exploits 2>/dev/null
mkdir $resultsFolder/loot 2>/dev/null
mkdir $resultsFolder/post 2>/dev/null
touch $resultsFolder/$1-vectors.txt

nmap $1 -vv -Pn -sV --top-ports=1000 -oN $resultsFolder/$1-nmap-quick
# nmap $1 -vv -Pn -A -sC --top-ports=500 -oN $resultsFolder/$1-nmap-quick
nmap $1 -vv -Pn -sV -T3 -p- -oN $resultsFolder/$1-nmap-full
# nmap $1 -vv -Pn -sU -T4 --top-ports 50 -oN $resultsFolder/$1-nmap-udp-top200

# for ip in {192.168.30.67,192.168.30.53,192.168.30.161,192.168.30.111,192.168.30.112,192.168.30.55}; do /bin/senumeration.sh $ip; done

# 192.168.30.67,192.168.30.53,192.168.30.161,192.168.30.111,192.168.30.112,192.168.30.55
