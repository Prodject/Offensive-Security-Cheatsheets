#!/bin/bash
mkdir -p /root/tools/$1 2>/dev/null
resultsFolder=/root/tools/$1

nmap $1 -vv -p88 --script krb5-enum-users --script-args=krb5-enum-users.realm=htb,userdb=/usr/share/wordlists/names -vv -oN $resultsFolder/$1-kerberos-enum
