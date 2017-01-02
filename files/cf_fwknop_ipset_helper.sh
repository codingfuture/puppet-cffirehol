#!/bin/sh

if [ "$1" = "add" ]
then
    CMD=$1
    IP=$2
    shift 2
    for n in $@
    do
        /usr/bin/sudo /sbin/ipset $CMD ${n}-net4 $IP \
        || /usr/bin/sudo /sbin/ipset $CMD ${n}-ip4 $IP \
        || /usr/bin/sudo /sbin/ipset $CMD ${n}-net6 $IP \
        || /usr/bin/sudo /sbin/ipset $CMD ${n}-ip6 $IP
    done
fi
