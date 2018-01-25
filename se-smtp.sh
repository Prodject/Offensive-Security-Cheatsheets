#!/bin/bash
mkdir $1 2>/dev/null

nmap $1 -vv -Pn -p25  --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -oN $1/$1-nmap-smtp
smtp-user-enum -M VRFY -U /usr/share/wordlists/nmap.lst -t $1 | tee $1/$1-smtp-user-enum
