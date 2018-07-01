#!/bin/bash
mkdir -p /root/tools/$1 2>/dev/null
resultsFolder=/root/tools/$1

username='sa'
password='password'
port=1433,3306

# mssql
nmap $1 -vv -Pn -p$port --script=ms-sql-info,ms-sql-config,ms-sql-tables,ms-sql-dump-hashes --script-args=mssql.instance-port=$port,mssql.username=$username,mssql.password=$username -oN $resultsFolder/$1-nmap-mssql

# mysql
nmap $1 -vv -Pn -p$port --script=mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 --script-args=mysqluser=$username,mysqlpass=$password,mysql-audit.username=$username,mysql-audit.password=$password,username=$username,password=$password -oN $resultsFolder/$1-nmap-mysql

