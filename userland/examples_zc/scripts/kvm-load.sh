modprobe kvm_intel
modprobe vhost_net

modprobe tun
modprobe bridge

brctl addbr br0
brctl addif br0 eth0
ifconfig br0 up

