#!/bin/bash

FAMILY=i40e

#service udev start

# Remove old modules (if loaded)
rmmod i40e
rmmod pf_ring

echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
mkdir /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

# We assume that you have compiled PF_RING
insmod ../../../../../../kernel/pf_ring.ko

# Required by i40e
modprobe ptp
modprobe vxlan

# Load the driver
insmod ./i40e.ko

# Enable debugging
find /sys/kernel/debug/i40e/ -name command -exec sh -c 'echo  "msg_enable 16" > {}' {} ';'

# Disable multiqueue
find /sys/kernel/debug/i40e/ -name command -exec sh -c 'echo  "set rss_size 1" > {}' {} ';'

sleep 1

killall irqbalance 

INTERFACES=$(cat /proc/net/dev|grep ':'|grep -v 'lo'|grep -v 'sit'|awk -F":" '{print $1}'|tr -d ' ')
for IF in $INTERFACES ; do
	TOCONFIG=$(ethtool -i $IF|grep $FAMILY|wc -l)
        if [ "$TOCONFIG" -eq 1 ]; then
		printf "Configuring %s\n" "$IF"
		ifconfig $IF up
		sleep 1
		bash ../scripts/set_irq_affinity $IF

		# Max number of RX slots
		#ethtool -G $IF rx 32768

		# Max number of TX slots
		#ethtool -G $IF tx 32768

		# Disabling VLAN stripping
		#ethtool -K $IF rxvlan off

		# Flow Control automatically disabled by the driver (no need to use the following commands)
		#ethtool -A $IF autoneg off
		#ethtool -A $IF rx off
		#ethtool -A $IF tx off
		#ethtool -s $IF speed 10000

		# Enable n-tuple hw filters
		#ethtool -K $IF ntuple on
	fi
done

