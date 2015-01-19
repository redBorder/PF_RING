#!/bin/bash

FAMILY=e1000e

#service udev start

# Remove old modules (if loaded)
rmmod e1000e
rmmod pf_ring

if [ `cat /proc/mounts | grep hugetlbfs | wc -l` -eq 0 ]; then
	echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
	mkdir /mnt/huge
	mount -t hugetlbfs nodev /mnt/huge
fi

# We assume that you have compiled PF_RING
insmod ../../../../../../kernel/pf_ring.ko

insmod ./e1000e.ko

sleep 1

killall irqbalance 

INTERFACES=$(cat /proc/net/dev|grep ':'|grep -v 'lo'|grep -v 'sit'|awk -F":" '{print $1}'|tr -d ' ')
for IF in $INTERFACES ; do
	TOCONFIG=$(ethtool -i $IF|grep $FAMILY|wc -l)
        if [ "$TOCONFIG" -eq 1 ]; then
		printf "Configuring %s\n" "$IF"
		ifconfig $IF up
		sleep 1
	fi
done
