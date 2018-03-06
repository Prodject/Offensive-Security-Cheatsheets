#!/bin/bash
mkdir -p /root/tools/$1 2>/dev/null
resultsFolder=/root/tools/$1

nmap $1 -vv -Pn -p80,443 --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-webdav-scan,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635 -oN $resultsFolder/$1-nmap-http
gobuster -u http://$1 -r -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt -t 150 -l | tee $resultsFolder/$1-gobuster
nikto -h http://$1 | tee $resultsFolder/$1-nikto
wpscan --url http://$1 --enumerate u,t,p | tee $resultsFolder/$1-wpscan-enum
