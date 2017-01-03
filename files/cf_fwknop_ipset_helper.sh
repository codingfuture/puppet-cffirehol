#!/bin/sh

CMD="-exist $1"
IP=$2
TO=$3
shift 3
for n in $@
do
    /usr/bin/sudo /sbin/ipset $CMD ${n}-net4 $IP \
    || /usr/bin/sudo /sbin/ipset $CMD ${n}-ip4 $IP \
    || /usr/bin/sudo /sbin/ipset $CMD ${n}-net6 $IP \
    || /usr/bin/sudo /sbin/ipset $CMD ${n}-ip6 $IP
done
