#!/bin/bash
mkdir -p /root/tools/$1 2>/dev/null
resultsFolder=/root/tools/$1

nmap $1 -vv -Pn -p25  --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -oN $resultsFolder/$1-nmap-smtp
smtp-user-enum -M VRFY -U /usr/share/wordlists/names.txt -t $1 | tee $resultsFolder/$1-smtp-user-enum
