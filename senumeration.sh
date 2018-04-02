#!/bin/bash
mkdir -p /root/tools/$1 2>/dev/null
resultsFolder=/root/tools/$1
mkdir $resultsFolder/exploits
mkdir $resultsFolder/loot
mkdir $resultsFolder/post
touch $resultsFolder/$1-vectors.txt

# nmap $1 -vv -Pn -A --top-ports=100 -oN $resultsFolder/$1-nmap-quick
nmap $1 -vv -Pn -T3 --top-ports=1000 -oN $resultsFolder/$1-nmap-quick
nmap $1 -vv -Pn -T3 -p- -oN $resultsFolder/$1-nmap-full
nmap $1 -vv -Pn -sU -T4 --top-ports 50 -oN $resultsFolder/$1-nmap-udp-top200