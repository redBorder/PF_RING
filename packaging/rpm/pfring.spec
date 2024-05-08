Summary: PF_RING user-space tools
Name: pfring
Version: %{__version}
Release: %{__release}%{?dist}
License: GPL
Group: Networking/Utilities
URL: http://www.ntop.org/products/pf_ring/
Source0: %{name}-%{version}.tar.gz
Packager: David Vanhoucke <dvanhoucke@redborder.com>
# Temporary location where the RPM will be built
BuildRoot:  %{_tmppath}/%{name}-%{version}-root
BuildRequires: git, kernel, kernel-headers, kernel-devel autoconf automake libtool daq-devel
Requires: pciutils, net-tools, hiredis, ethtool 

# Disable shared libs dependency check (needed by FPGA libs)
AutoReq: no
#
# As dependencies are disabled (AutoReqProv: no) we must report them manually
%if 0%{?centos_ver} < 8
Provides: daq_pfring_zc.so, daq_pfring.so, libpfring.so
%else
Provides: libpfring.so
%endif

# Make sure .build-id is not part of the package
%define _build_id_links none

%description
PF_RING kernel module and drivers for high-speed RX/TX package processing

%prep
%setup -q -n %{name}-%{version}
ln -s $PWD $HOME/PF_RING

%build
make local
make snort

%install
PATH=/usr/bin:/bin:/usr/sbin:/sbin
if [ -d $RPM_BUILD_ROOT ]; then
	\rm -rf $RPM_BUILD_ROOT
fi

mkdir -p $RPM_BUILD_ROOT/usr/include/linux
mkdir -p $RPM_BUILD_ROOT/usr/lib
mkdir -p $RPM_BUILD_ROOT/usr/local/lib
mkdir -p $RPM_BUILD_ROOT/usr/bin
mkdir -p $RPM_BUILD_ROOT/usr/local/bin
mkdir -p $RPM_BUILD_ROOT/etc/ld.so.conf.d
mkdir -p $RPM_BUILD_ROOT/etc/pf_ring
mkdir -p $RPM_BUILD_ROOT/etc/cluster

cp kernel/linux/pf_ring.h $RPM_BUILD_ROOT/usr/include/linux/
# Userland
cp userland/lib/libpfring.a $RPM_BUILD_ROOT/usr/lib
cp userland/lib/libpfring.so.8.6.1 $RPM_BUILD_ROOT/usr/lib
cd $RPM_BUILD_ROOT/usr/lib && ln -sf libpfring.so.8.6.1 libpfring.so.8 && cd -
cd $RPM_BUILD_ROOT/usr/lib && ln -sf libpfring.so.8 libpfring.so && cd -
cp userland/lib/pfring.h $RPM_BUILD_ROOT/usr/include
cp userland/lib/pfring_zc.h $RPM_BUILD_ROOT/usr/include
cp userland/lib/pfring_ft.h $RPM_BUILD_ROOT/usr/include
cp userland/nbpf/nbpf.h $RPM_BUILD_ROOT/usr/include
cp userland/libpcap/libpcap.a $RPM_BUILD_ROOT/usr/local/lib
cp userland/libpcap/libpcap.so.1.10.1	$RPM_BUILD_ROOT/usr/local/lib
#
# NOTE
# Unless you install wireshark 2.x you cannot use the extcap plugin as CentOS
# comes with wireshark 1.x
#
mkdir -p $RPM_BUILD_ROOT/usr/lib64/wireshark/extcap
cp userland/wireshark/extcap/ntopdump $RPM_BUILD_ROOT/usr/lib64/wireshark/extcap
cp userland/tcpdump/tcpdump $RPM_BUILD_ROOT/usr/local/bin
cp userland/examples/pfcount $RPM_BUILD_ROOT/usr/bin
cp userland/examples/pfsend $RPM_BUILD_ROOT/usr/bin
cp userland/examples/pfcount_multichannel $RPM_BUILD_ROOT/usr/bin
cp userland/examples/pfsend_multichannel $RPM_BUILD_ROOT/usr/bin
cp tools/n2if $RPM_BUILD_ROOT/usr/bin
cp packaging/rpm/etc/ld.so.conf.d/pf_ring.conf $RPM_BUILD_ROOT/etc/ld.so.conf.d
cp packaging/rpm/etc/pf_ring/pf_ring.conf.example $RPM_BUILD_ROOT/etc/pf_ring
cp packaging/rpm/etc/cluster/cluster.conf.example $RPM_BUILD_ROOT/etc/cluster
%if 0%{?centos_ver} != 6
  mkdir -p $RPM_BUILD_ROOT/usr/lib/systemd/system/
  cp packaging/rpm/etc/systemd/system/pf_ring.service $RPM_BUILD_ROOT/usr/lib/systemd/system/
  cp packaging/rpm/etc/systemd/system/cluster.service $RPM_BUILD_ROOT/usr/lib/systemd/system/
  cp packaging/rpm/etc/systemd/system/cluster@.service $RPM_BUILD_ROOT/usr/lib/systemd/system/
%else
  mkdir -p $RPM_BUILD_ROOT/etc/init.d
  cp packaging/rpm/etc/init.d/pf_ring    $RPM_BUILD_ROOT/etc/init.d
  cp packaging/rpm/etc/init.d/cluster    $RPM_BUILD_ROOT/etc/init.d
%endif
cp packaging/rpm/usr/bin/pf_ringctl $RPM_BUILD_ROOT/usr/bin
cp packaging/rpm/usr/bin/pf_ringcfg $RPM_BUILD_ROOT/usr/bin
cp packaging/rpm/usr/bin/clusterctl $RPM_BUILD_ROOT/usr/bin
# DAQ
mkdir -p $RPM_BUILD_ROOT/usr/local/lib/daq
cp userland/snort/pfring-daq-module/daq_pfring.la $RPM_BUILD_ROOT/usr/local/lib/daq
cp userland/snort/pfring-daq-module/.libs/daq_pfring.so $RPM_BUILD_ROOT/usr/local/lib/daq
cp userland/snort/pfring-daq-module-zc/daq_pfring_zc.la $RPM_BUILD_ROOT/usr/local/lib/daq
cp userland/snort/pfring-daq-module-zc/.libs/daq_pfring_zc.so $RPM_BUILD_ROOT/usr/local/lib/daq
#cp sfbpf/.libs/libsfbpf.so.0 sfbpf/.libs/libsfbpf.so.0.0.1 $RPM_BUILD_ROOT/usr/local/lib
%if %nozc == 0
cp userland/examples_zc/zbalance_ipc $RPM_BUILD_ROOT/usr/bin
cp userland/examples_zc/zsend $RPM_BUILD_ROOT/usr/bin
cp userland/examples_zc/zcount $RPM_BUILD_ROOT/usr/bin
cp userland/examples_zc/zcount_ipc $RPM_BUILD_ROOT/usr/bin
cp userland/examples_ft/ftflow $RPM_BUILD_ROOT/usr/bin
%endif


# Clean out our build directory
%clean
rm -fr $RPM_BUILD_ROOT

%files
/usr/include/linux/pf_ring.h
/usr/lib/libpfring.a
/usr/lib/libpfring.so.8.6.1
/usr/lib/libpfring.so.8
/usr/lib/libpfring.so
/usr/local/lib/libpcap.a
/usr/local/lib/libpcap.so.1.10.1
/usr/include/pfring.h
/usr/include/pfring_zc.h
/usr/include/pfring_ft.h
/usr/include/nbpf.h
# DAQ
/usr/local/lib/daq/daq_pfring.la
/usr/local/lib/daq/daq_pfring.so
/usr/local/lib/daq/daq_pfring_zc.la
/usr/local/lib/daq/daq_pfring_zc.so
#/usr/local/lib/libsfbpf.so.0
#/usr/local/lib/libsfbpf.so.0.0.1
/usr/lib64/wireshark/extcap
%if %nozc == 0
/usr/bin/zbalance_ipc
/usr/bin/zsend
/usr/bin/zcount
/usr/bin/zcount_ipc
/usr/bin/ftflow
%endif
/usr/local/bin/tcpdump
/usr/bin/pfcount
/usr/bin/pfsend
/usr/bin/pfcount_multichannel
/usr/bin/pfsend_multichannel
/usr/bin/n2if
/etc/ld.so.conf.d/pf_ring.conf
/etc/pf_ring/pf_ring.conf.example
/etc/cluster/cluster.conf.example
%if 0%{?centos_ver} != 6
/usr/lib/systemd/system/pf_ring.service
/usr/lib/systemd/system/cluster.service
/usr/lib/systemd/system/cluster@.service
%else
/etc/init.d/pf_ring
/etc/init.d/cluster
%endif
/usr/bin/pf_ringctl
/usr/bin/pf_ringcfg
/usr/bin/clusterctl

# Set the default attributes of all of the files specified to have an
# owner and group of root and to inherit the permissions of the file
# itself.
%defattr(-, root, root)

# Execution order:
# install:    pre -> (copy) -> post
# upgrade:    pre -> (copy) -> post -> preun (old) -> (delete old) -> postun (old)
# un-install:                          preun       -> (delete)     -> postun

%pre
case "$1" in
  1)
    # install
  ;;
  2)
    # upgrade
  ;;
esac

%post
CMDLINE=$(tr -d '\0' < /proc/1/cmdline) 
if [ -z "${CMDLINE##*system*}" ] || [ -z "${CMDLINE##*init*}" ]; then # init/systemd (not a container)
case "$1" in
  1)
    # install
    %if 0%{?centos_ver} != 6
      /bin/systemctl daemon-reload
      %systemd_post pf_ring.service cluster.service
    %else
      /sbin/chkconfig --add pf_ring
      /sbin/chkconfig --add cluster
    %endif
  ;;
  2)
    # upgrade
    %if 0%{?centos_ver} != 6
      /bin/systemctl daemon-reload
    %endif
  ;;
esac
fi

/sbin/ldconfig > /dev/null 2>&1

%postun
CMDLINE=$(tr -d '\0' < /proc/1/cmdline) 
if [ -z "${CMDLINE##*system*}" ] || [ -z "${CMDLINE##*init*}" ]; then # init/systemd (not a container)
%if 0%{?centos_ver} != 6
  %systemd_postun_with_restart pf_ring.service cluster.service "cluster@*.service"
%else
  /etc/init.d/pf_ring restart
  /etc/init.d/cluster restart
%endif
fi

%preun
CMDLINE=$(tr -d '\0' < /proc/1/cmdline) 
if [ -z "${CMDLINE##*system*}" ] || [ -z "${CMDLINE##*init*}" ]; then # init/systemd (not a container)
case "$1" in
  0)
    # un-install
    %if 0%{?centos_ver} != 6
      %systemd_preun pf_ring.service "cluster.service" "cluster@*.service"
    %else
      /etc/init.d/cluster stop
      /etc/init.d/pf_ring stop
      /sbin/chkconfig --del cluster
      /sbin/chkconfig --del pf_ring
    %endif
  ;;
  1)
    # upgrade
  ;;
esac
fi

%changelog
* Thu Apr 4 2024 <dvanhoucke@redborder.com> - 8.6.1
- merge with version 8.6.1-stable and adapt rpm process with mock (packaging/rpm)
* Wed Dec  5 2012  <deri@centos.ntop.org> - 8.6.0
-
