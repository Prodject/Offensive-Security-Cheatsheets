#!/bin/bash
ip=`echo $1 | cut -d "/" -f "1" | cut -d ":" -f1`
mkdir -p /root/tools/$ip 2>/dev/null
resultsFolder=/root/tools/$ip

# nmap $ip -vv -Pn -p80,443 --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-webdav-scan,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635 -oN $resultsFolder/$ip-nmap-http
nmap $ip -vv -Pn -p80 --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-webdav-scan,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635 -oN $resultsFolder/$ip-nmap-http
gobuster -u http://$1 -r -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x asp,php,htm,html,txt -t 80 -s 200,204,301,302,307,403 -l | tee $resultsFolder/$ip-gobuster -a
# gobuster -u http://$1 -r -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x asp,php,html,conf,txt -t 40 -s 200,204,301,302,307,403 -l | tee $resultsFolder/$ip-gobuster -a
# nikto -h http://$1 | tee $resultsFolder/$ip-nikto -a
# wpscan --url http://$1 --enumerate u,t,p | tee $resultsFolder/$ip-wpscan-enum -a
