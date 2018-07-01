#!/bin/bash
ip=`echo $1 | cut -d "/" -f "1" | cut -d ":" -f1`
mkdir -p /root/tools/$ip 2>/dev/null
resultsFolder=/root/tools/$ip

curl -v -X OPTIONS https://$1
# curl -v -X OPTIONS http://$1
# nmap $ip -vv -Pn -p80,443 --script=http-vhosts,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-webdav-scan,http-php-version,http-shellshock,http-vuln-cve2015-1635 -oN $resultsFolder/$ip-nmap-http

# gobuster -u http://$1 -r -w /usr/share/wordlists/dirbuster/combined.txt -x jsp,htm,html,txt -t 400 -s 200,204,301,302,307 -l | tee $resultsFolder/$ip-gobuster -a
# gobuster -u https://$1 -r -w /usr/share/wordlists/dirbuster/combined.txt -x php,htm,html,txt -t 150 -s 200,204,301,302,307 -l | tee $resultsFolder/$ip-gobuster -a
# gobuster -u http://$1 -r -w /usr/share/wordlists/dirbuster/combined.txt -x cgi -t 150 -s 200,204,301,302,307 -l | tee $resultsFolder/$ip-gobuster -a
gobuster -u https://$1 -r -w /usr/share/wordlists/dirbuster/combined.txt -x zip,rar,bak,tar,sh,pl,cgi,py -t 150 -s 200,204,301,302,307 -l | tee $resultsFolder/$ip-gobuster -a
# gobuster -u https://$1 -r -w /usr/share/wordlists/dirbuster/combined.txt -x html -t 300 -s 200,204,301,302,307 -l | tee $resultsFolder/$ip-gobuster -a
# gobuster -u http://$1 -r -w /usr/share/wordlists/dirbuster/combined.txt -x asp,htm,html,txt -t 300 -s 200,204,301,302,307 -l | tee $resultsFolder/$ip-gobuster -a

nikto -h http://$1 | tee $resultsFolder/$ip-nikto -a
# wpscan --url http://$1 --enumerate u,t,p --threads 10 | tee $resultsFolder/$ip-wpscan-enum -a
