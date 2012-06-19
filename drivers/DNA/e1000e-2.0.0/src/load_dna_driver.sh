#!/bin/bash

# Remove old modules (if loaded)
rmmod e1000e
rmmod pf_ring

# We assume that you have compiled PF_RING
insmod ../../../../kernel/pf_ring.ko

# Default
insmod ./e1000e.ko

