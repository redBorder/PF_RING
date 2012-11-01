all:
	cd kernel; make
	cd userland; make
	cd drivers; make

clean:
	cd kernel; make clean
	cd userland; make clean
	cd drivers; make clean

# 
# RPM Buil Process
#
APPL=pfring
PLATFORM =`uname -p`
PACKAGE_VERSION=`cat ./kernel/linux/pf_ring.h | grep RING_VERSION | head -1 | cut -d '"' -f 2`
PACKAGE=$(APPL)-$(PACKAGE_VERSION)-0.$(PLATFORM).rpm
PACKAGE_PATH=$(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(PACKAGE)


package: all build-rpm clean-rpm

build-rpm: 
# Do NOT build package as root (http://wiki.centos.org/HowTos/SetupRpmBuildEnvironment)
#	mkdir -p $(HOME)/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
#	echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros
	@rpmbuild -bb ./package/$(APPL).spec --define "pfring_version $(PACKAGE_VERSION)"
	@echo ""
	@echo "Package contents:"
	@rpm -qpl $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(PACKAGE)
	@echo "The package is now available in $(HOME)/rpmbuild/RPMS/$(PLATFORM)/$(PACKAGE)"

changelog:
	svn -v -r {`curl -s http://sourceforge.net/projects/ntop/files/PF_RING/|grep -o "<td headers=\"files_date_h\" class=\"opt\"><abbr title=\"[^\"]*\">[^<]*</abbr></td>"|head -n 3|tail -n 1|egrep -o "[0-9]+\-[0-9]+\-[0-9]+"|head -n 1`}:"HEAD" --xml log | ./doc/svn2changelog.py > ./doc/Changelog.txt

cleanup-rpm:
	rm -f $(PACKAGE_PATH)
	rm -f $(HOME)/rpmbuild/BUILD/$(PACKAGE)
