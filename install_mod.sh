#!/bin/sh
lsmod|grep "myutpkt"
if [ $? == 0 ]
then
    echo "utpkt is exist,now begin to remove it..."
    rmmod myutpkt
    if [ $? != 0 ]
    then
        echo "remove utpkt ok!"
    fi
fi
echo "now begin to install myutpkt.ko..."
insmod myutpkt.ko
lsmod|grep "utpkt"
if [ $? == 0 ]
then
    echo "install success"
else
    echo "install fail"
fi
