all: install

add: veryclean
	\/bin/rm -rf /usr/src/ice-zc-1.9.11.6281
	mkdir -p /usr/src/ice-zc-1.9.11.6281/
	cd ice/ice-1.9.11-zc/src/ ; make clean; cp -r * /usr/src/ice-zc-1.9.11.6281/
	cp ../../kernel/linux/pf_ring.h /usr/src/ice-zc-1.9.11.6281/
	sed -i -e 's/ice\.o/ice_zc.o/' -e 's/ice-/ice_zc-/' /usr/src/ice-zc-1.9.11.6281/Kbuild
	mv /usr/src/ice-zc-1.9.11.6281/Kbuild /usr/src/ice-zc-1.9.11.6281/Makefile
	sed -i '1iPF_RING_PATH=\/usr\/src\/pfring-8.6.0.6281' /usr/src/ice-zc-1.9.11.6281/Makefile
	cp dkms.conf.ice /usr/src/ice-zc-1.9.11.6281/dkms.conf 
	dkms add -m ice-zc -v 1.9.11.6281

build: add
	dkms build -m ice-zc -v 1.9.11.6281

install: build
	dkms install --force -m ice-zc -v 1.9.11.6281

deb: add add_deb install
	dkms mkdeb -m ice-zc -v 1.9.11.6281 --source-only

rpm: add add_rpm install
	dkms mkrpm -m ice-zc -v 1.9.11.6281 --source-only

add_rpm:
	cp -f zc.spec /usr/src/ice-zc-1.9.11.6281/ice-zc-dkms-mkrpm.spec

add_deb:
	cp -r zc-dkms-mkdeb /usr/src/ice-zc-1.9.11.6281/ice-zc-dkms-mkdeb
	-cd  /usr/src/ice-zc-1.9.11.6281/ice-zc-dkms-mkdeb ; find . -type d -name ".git" -exec rm -fr {} \;

remove:
	-dkms remove -m ice-zc -v 1.9.11.6281 --all
	\/bin/rm -f /lib/modules/*/weak-updates/ice*ko
	\/bin/rm -f /lib/modules/*/extra/ice*ko
	\/bin/rm -rf /var/lib/dkms/ice-zc

veryclean: remove
	\/bin/rm -fr /usr/src/ice-zc-1.9.11.6281
	
