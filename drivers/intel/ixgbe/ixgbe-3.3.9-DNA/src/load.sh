#!/bin/sh

IF[0]=eth1
IF[1]=eth2
IF[2]=
IF[3]=

#service udev start
rmmod ixgbe
rmmod pf_ring
#modprobe pf_ring
insmod $HOME/PF_RING/kernel/pf_ring.ko

#insmod ./ixgbe.ko
insmod ./ixgbe.ko MQ=0,0,0,0
#insmod ./ixgbe.ko MQ=1,1,0,0 RSS=4,4,1,1 FdirMode=0,0,0,0
sleep 1

killall irqbalance 

for index in 0 1 2 3
do
  if [ -z ${IF[index]} ]; then
    continue
  fi
  ifconfig ${IF[index]} up
done

sleep 2

for index in 0 1 2 3
do
  if [ -z ${IF[index]} ]; then
    continue
  fi
  printf "Configuring %s\n" "${IF[index]}"
  bash ../scripts/set_irq_affinity.sh ${IF[index]}
  ethtool -A ${IF[index]} autoneg off
  ethtool -A ${IF[index]} rx off
  ethtool -A ${IF[index]} tx off
  ethtool -s ${IF[index]} speed 10000
done


