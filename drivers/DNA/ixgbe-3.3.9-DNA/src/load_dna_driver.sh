#!/bin/bash

# Configure here the network interfaces to activate
IF[0]=eth2
IF[1]=eth3
IF[2]=
IF[3]=

#service udev start

# Remove old modules (if loaded)
rmmod ixgbe
rmmod pf_ring

# We assume that you have compiled PF_RING
insmod ../../../../kernel/pf_ring.ko

# Set <id> as many times as the number of processors
# Default
#insmod ./ixgbe.ko

# Disable multiqueue
insmod ./ixgbe.ko MQ=0,0,0,0

# Enable 8 queues (you need 8 or more CPU cores)
#insmod ./ixgbe.ko MQ=1,1 RSS=8,8 FdirMode=0,0

sleep 1

killall irqbalance 

for index in 0 1 2 3
do
  if [ -z ${IF[index]} ]; then
    continue
  fi
  printf "Configuring %s\n" "${IF[index]}"
  ifconfig ${IF[index]} up
  sleep 1
  bash ../scripts/set_irq_affinity.sh ${IF[index]}
#  ethtool -A ${IF[index]} autoneg off
#  ethtool -A ${IF[index]} rx off
#  ethtool -A ${IF[index]} tx off
#  ethtool -s ${IF[index]} speed 10000
done
