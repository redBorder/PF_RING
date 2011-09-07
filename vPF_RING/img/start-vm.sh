/usr/local/kvm/bin/qemu-system-x86_64 \
-boot c \
-hda ubuntu-amd64.img \
-m 512 \
-netdev type=tap,id=guest0,script=if-up.sh,vhost=on -device virtio-net-pci,netdev=guest0,mac=AB:CD:EF:AB:CD:EF  \
-vnc 0.0.0.0:0 \
-device vnplug
