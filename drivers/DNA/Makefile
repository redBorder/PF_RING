#
# IMPORTANT IMPORTANT IMPORTANT IMPORTANT IMPORTANT
#
# When you change the versions below also update
#  - ~/PF_RING/PF_RING/package/ubuntu/Makefile
#  - ~/PF_RING/package/rpm/pfring.spec

E1000=e1000-8.0.35
E1000E=e1000e-2.5.4
IGB=igb-5.0.6
IXGBE=ixgbe-3.21.2

all: igb ixgbe e1000e e1000

e1000:
#	cd $(E1000)-DNA/src; make

e1000e:
	cd $(E1000E)-DNA/src; make

igb:
	cd $(IGB)-DNA/src; make

ixgbe:
	cd $(IXGBE)-DNA/src; make

clean:
#	cd $(E1000)-DNA/src; make clean
	cd $(E1000E)-DNA/src; make clean
	cd $(IGB)-DNA/src; make clean
	cd $(IXGBE)-DNA/src; make clean

dkms-deb:
	dpkg-deb -b pfring-drivers-dna .
	sudo make -f Makefile.dkms.e1000e deb
	cp /var/lib/dkms/e1000e-dna/*/deb/*.deb .
	sudo make -f Makefile.dkms.igb deb
	cp /var/lib/dkms/igb-dna/*/deb/*.deb .
	sudo make -f Makefile.dkms.ixgbe deb
	cp /var/lib/dkms/ixgbe-dna/*/deb/*.deb .

dkms-rpm:
	sudo make -f Makefile.dkms.e1000e rpm	
	sudo make -f Makefile.dkms.igb rpm
	sudo make -f Makefile.dkms.ixgbe rpm