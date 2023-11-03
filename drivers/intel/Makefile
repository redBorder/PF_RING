E1000E=e1000e/e1000e-3.8.7-zc
IGB=igb/igb-5.10.2-zc
IXGBE=ixgbe/ixgbe-5.5.3-zc
IXGBEVF=ixgbevf/ixgbevf-4.5.1-zc
I40E=i40e/i40e-2.17.4-zc
ICE=ice/ice-1.9.11-zc
IAVF=iavf/iavf-4.5.3-zc

all:
	cd $(E1000E); make
	cd $(IGB); make
	cd $(IXGBE); make
	cd $(IXGBEVF); make
	cd $(I40E); make
	cd $(ICE); make
	cd $(IAVF); make

clean:
	cd $(E1000E); make clean
	cd $(IGB); make clean
	cd $(IXGBE); make clean
	cd $(IXGBEVF); make clean
	cd $(I40E); make clean
	cd $(ICE); make clean
	cd $(IAVF); make clean
	-/bin/rm *.deb *.rpm

cleanup:
	sudo rm -rf /var/lib/dkms/*-zc  /lib/modules/`uname -r`/extra/*-zc.ko

dkms-deb-virtual:
	/bin/rm -rf tmp
	mkdir tmp
	cp -r pfring-drivers-zc-dkms tmp
	find tmp -name .git|xargs /bin/rm -rf	
	cd tmp; dpkg-deb -b pfring-drivers-zc-dkms .; mv *.deb ..

dkms-deb: cleanup dkms-deb-virtual
	sudo make -f Makefile.dkms.e1000e deb
	cp /var/lib/dkms/e1000e-zc/*/deb/*.deb .
	sudo make -f Makefile.dkms.igb deb
	cp /var/lib/dkms/igb-zc/*/deb/*.deb .
	sudo make -f Makefile.dkms.ixgbe deb
	cp /var/lib/dkms/ixgbe-zc/*/deb/*.deb .
	sudo make -f Makefile.dkms.ixgbevf deb
	cp /var/lib/dkms/ixgbevf-zc/*/deb/*.deb .
	sudo make -f Makefile.dkms.i40e deb
	cp /var/lib/dkms/i40e-zc/*/deb/*.deb .
	sudo make -f Makefile.dkms.iavf deb
	cp /var/lib/dkms/iavf-zc/*/deb/*.deb .
ifeq (y,y)
	sudo make -f Makefile.dkms.ice deb
	cp /var/lib/dkms/ice-zc/*/deb/*.deb .
endif

dkms-rpm: cleanup dkms-rpm-virtual
	sudo make -f Makefile.dkms.e1000e rpm
	sudo make -f Makefile.dkms.igb rpm
	sudo make -f Makefile.dkms.ixgbe rpm
	sudo make -f Makefile.dkms.ixgbevf rpm
	sudo make -f Makefile.dkms.i40e rpm
	sudo make -f Makefile.dkms.iavf rpm
ifeq (y,y)
	sudo make -f Makefile.dkms.ice rpm
endif

dkms-rpm-virtual:
	rpmbuild -ba pfring-zc-rpm.spec
	cp ~/rpmbuild/RPMS/noarch/pfring-drivers-zc-dkms-*.noarch.rpm .
