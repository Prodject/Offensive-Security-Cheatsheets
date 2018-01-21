#!/bin/bash
mkdir $1 2>/dev/null

nmap $1 -vv -p88 --script krb5-enum-users --script-args krb5-enum-users.realm=htb,userdb=/usr/share/wordlists/names.txt -vv -oN /root/tools/$1/$1-kerberos-enum
