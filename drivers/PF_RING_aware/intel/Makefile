E1000=e1000/e1000-8.0.35
E1000E=e1000e/e1000e-3.0.4.1-zc
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
	/bin/rm *.deb *.rpm

dkms-deb:
	dpkg-deb -b pfring-drivers-zc-dkms .
	sudo make -f Makefile.dkms.e1000e deb
	cp /var/lib/dkms/e1000e-zc/*/deb/*.deb .
	sudo make -f Makefile.dkms.igb deb
	cp /var/lib/dkms/igb-zc/*/deb/*.deb .
	sudo make -f Makefile.dkms.ixgbe deb
	cp /var/lib/dkms/ixgbe-zc/*/deb/*.deb .

dkms-rpm:
	sudo make -f Makefile.dkms.e1000e rpm
	sudo make -f Makefile.dkms.igb rpm
	sudo make -f Makefile.dkms.ixgbe rpm
