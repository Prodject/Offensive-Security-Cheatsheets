#!/bin/bash
ip=`echo $1 | cut -d ":" -f1`
mkdir -p /root/tools/$ip 2>/dev/null
resultsFolder=/root/tools/$ip

# nmap $ip -vv -Pn -p80,443 --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-webdav-scan,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635 -oN $resultsFolder/$1-nmap-http
gobuster -u https://$1 -r -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,htm,html -t 200 -l | tee $resultsFolder/$1-gobuster
nikto -h https://$1 | tee $resultsFolder/$1-nikto
wpscan --url http://$1 --enumerate u,t,p | tee $resultsFolder/$1-wpscan-enum
