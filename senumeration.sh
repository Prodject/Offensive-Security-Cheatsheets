#!/bin/bash
mkdir -p /root/tools/$1 2>/dev/null
resultsFolder=/root/tools/$1
mkdir $resultsFolder/exploits
mkdir $resultsFolder/loot

nmap $1 -vv -Pn -sV -A -oN $resultsFolder/$1-nmap-quick
nmap $1 -vv -Pn -T4 -p- -oN $resultsFolder/$1-nmap-full
nmap $1 -vv -Pn -sU -T4 --top-ports 200 -oN $resultsFolder/$1-nmap-udp-top200
