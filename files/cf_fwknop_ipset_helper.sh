#!/bin/sh

/usr/bin/sudo /sbin/ipset $1 $2-net4 $3 \
|| /usr/bin/sudo /sbin/ipset $1 $2-net6 $3
