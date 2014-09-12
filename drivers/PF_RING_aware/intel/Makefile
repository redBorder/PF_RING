E1000=e1000/e1000-8.0.35
E1000E=e1000e/e1000e-2.5.4-zc
IGB=igb/igb-5.2.5-zc
IXGBE=ixgbe/ixgbe-3.21.2-zc

all:
#	cd $(E1000)/src; make
#	cd $(E1000E)/src; make
	cd $(IGB)/src; make
	cd $(IXGBE)/src; make

clean:
#	cd $(E1000)/src; make clean
#	cd $(E1000E)/src; make clean
	cd $(IGB)/src; make clean
	cd $(IXGBE)/src; make clean

dkms:
	./configure
	sudo make -f Makefile.dkms.ixgbe deb
	sudo make -f Makefile.dkms.igb deb
	sudo make -f Makefile.dkms.e1000e deb
