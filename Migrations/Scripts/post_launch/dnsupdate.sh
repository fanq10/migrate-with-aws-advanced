#!/bin/sh
ADDR=`hostname -I`
HOST=`hostname`
sudo touch /tmp/nsupdate.txt
sudo chmod 666 /tmp/nsupdate.txt
REVERSE=`echo $ADDR | awk -F. '{ print $4, $3, $2, $1 }' OFS='.'`
echo "server dns.onpremsim.env" > /tmp/nsupdate.txt
echo "update delete $HOST A" >> /tmp/nsupdate.txt
echo "update add $HOST 86400 A $ADDR" >> /tmp/nsupdate.txt
echo "" >> /tmp/nsupdate.txt
echo "update add $REVERSE.in-addr.arpa. 86400 PTR $HOST." >> /tmp/nsupdate.txt
echo "send" >> /tmp/nsupdate.txt

sudo nsupdate /tmp/nsupdate.txt