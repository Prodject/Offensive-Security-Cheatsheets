#!/bin/bash
mkdir $1
nmap $1 -vv -Pn -sV -oN $1/$1-nmap-quick
java -jar /usr/share/dirbuster/DirBuster-1.0-RC1.jar -e php,html -u http://$1:80 -l /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee $1/$1-dirbuster

# HTTP *****************************************************************************************************
# nmap $1 -vv -Pn -p80,443 --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635 -oN $1/$1-nmap-http


# DNS *****************************************************************************************************
# dig axfr @nameserver domain.net | tee $1/$1-dns-zone-transfer

# SMTP *****************************************************************************************************
# nmap $1 -vv -Pn -p25  --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -oN $1/$1-nmap-smtp
# smtp-user-enum -M VRFY -U /usr/share/wordlists/nmap.lst -t $1 | tee $1/$1-smtp-user-enum


# SQL *****************************************************************************************************
# nmap $1 -vv -Pn -p1433 --script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes --script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa -oN $1/$1-nmap-sql


# KERBEROS *****************************************************************************************************
# nmap $1 -vv -p88 --script krb5-enum-users --script-args krb5-enum-users.realm=htb,userdb=/usr/share/wordlists/names.txt -vv -oN /root/tools/$1/$1-kerberos-enum


# SMB *****************************************************************************************************
# https://monkeysm8.gitbooks.io/pentesting-methodology/common_portsservices_and_how_to_use_them/port_139_and_445-_smbsamba_shares.html
# nmap $1 -vv -Pn -p445 --script=smb-enum-shares.nse,smb-ls.nse,smb-enum-users.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-security-mode.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-regsvc-dos.nse,smbv2-enabled.nse -oN $1/$1-nmap-smb
# showmount -e $1 | tee $1/$1-showmount
# enum4linux -a $1 | tee $1/$1-enum4linux


# FTP enum *****************************************************************************************************
# nmap $1 -vv -Pn -p21 --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 -oN $1/$1-nmap-ftp


# NMAP extended - full and udp top 200 *****************************************************************************************************
nmap $1 -vv -Pn -A -sC -sS -T4 -p- -oN $1/$1-nmap-full
nmap $1 -vv -Pn -A -sC -sU -T4 --top-ports 200 -oN $1/$1-nmap-udp-top200

# enumerate wp  *****************************************************************************************************
# wpscan --url http://$1:80 --enumerate u | tee $1/$1-wpscan-users

# nikto -h http://$1:80 | tee $1/$1-nikto

