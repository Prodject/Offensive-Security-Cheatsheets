#!/bin/bash
mkdir -p /root/tools/$1 2>/dev/null
resultsFolder=/root/tools/$1

nmap $1 -vv -Pn -p1433 --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa -oN $resultsFolder/$1-nmap-sql
nmap $1 -vv -Pn -p1433 --script=ms-sql-tables --script-args=mssql.username=admin,mssql.password='pass',ms-sql-tables.maxtables='0' -oN $resultsFolder/$1-nmap-sql-tables-databases
nmap $1 -vv -Pn -p1433 --script=ms-sql-dump-hashes --script-args=mssql.username=admin,mssql.password='pass' -oN $resultsFolder/$1-nmap-sql-dumped-hashes
nmap $1 -vv -Pn -p1433 --script=ms-sql-config --script-args=mssql.username=admin,mssql.password='pass' -oN $resultsFolder/$1-nmap-sql-config
