#!/bin/sh

IF0=eth2
IF1=eth3

#service udev start
rmmod ixgbe
rmmod pf_ring
#modprobe pf_ring
insmod $HOME/PF_RING/kernel/pf_ring.ko

# Set <id> as many times as the number of processors
#insmod ./ixgbe.ko
insmod ./ixgbe.ko MQ=0,0
sleep 1

killall irqbalance 

ifconfig $IF0 up
bash ../scripts/set_irq_affinity.sh $IF0
ethtool -A $IF0 autoneg off
ethtool -A $IF0 rx off
ethtool -A $IF0 tx off
ethtool -s $IF0 speed 10000

ifconfig $IF1 up
bash ../scripts/set_irq_affinity.sh $IF1
ethtool -A $IF1 autoneg off
ethtool -A $IF1 rx off
ethtool -A $IF1 tx off
ethtool -s $IF1 speed 10000

