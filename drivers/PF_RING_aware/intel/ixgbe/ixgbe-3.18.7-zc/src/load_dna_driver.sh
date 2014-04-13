#!/bin/bash

FAMILY=ixgbe

#service udev start

# Remove old modules (if loaded)
rmmod ixgbe
rmmod pf_ring

echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
mkdir /mnt/huge
mount -t hugetlbfs nodev /mnt/huge

# We assume that you have compiled PF_RING
insmod ../../../../../../kernel/pf_ring.ko

# As many queues as the number of processors
#insmod ./ixgbe.ko RSS=0,0,0,0

# Disable multiqueue
insmod ./ixgbe.ko RSS=1,1,1,1 

# Configure the number of TX and RX slots
#insmod ./ixgbe.ko RSS=1,1,1,1 num_rx_slots=32768 num_tx_slots=4096

# Enable 16 queues
#insmod ./ixgbe.ko MQ=1,1,1,1 RSS=16,16,16,16

# Enable max number of hw filters
#insmod ./ixgbe.ko RSS=1,1,1,1 FdirPballoc=3,3,3,3

# Set a large MTU (jumbo frame)
#insmod ./ixgbe.ko RSS=1,1,1,1 mtu=9000

# Select the CPU of the NUMA node where per-adapter memory will be allocated
#insmod ./ixgbe.ko RSS=1,1,1,1 numa_cpu_affinity=0,0,0,0

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

		# Flow Control automatically disabled by the driver (no need to use the following commands)
		#ethtool -A $IF autoneg off
		#ethtool -A $IF rx off
		#ethtool -A $IF tx off
		#ethtool -s $IF speed 10000

		# Enable n-tuple hw filters
		#ethtool -K $IF ntuple on
	fi
done

