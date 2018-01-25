#!/bin/bash
mkdir $1 2>/dev/null

nmap $1 -vv -Pn -p80,443 --script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,http-config-backup,http-default-accounts,http-methods,http-method-tamper,http-passwd,http-robots.txt,http-devframework,http-enum,http-frontpage-login,http-git,http-iis-webdav-vuln,http-php-version,http-robots.txt,http-shellshock,http-vuln-cve2015-1635 -oN $1/$1-nmap-http
nikto -h http://$1:80 | tee $1/$1-nikto
# wpscan --url http://$1:80 --enumerate u | tee $1/$1-wpscan-users