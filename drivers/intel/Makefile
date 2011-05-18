E1000=e1000/e1000-8.0.30
E1000E=e1000e/e1000e-1.3.10a
IGB=igb/igb-3.0.22
IXGBE=ixgbe/ixgbe-3.1.15-FlowDirector-NoTNAPI

all:
	cd $(E1000)/src; make
	cd $(E1000E)/src; make
	cd $(IGB)/src; make
	cd $(IXGBE)/src; make

clean:
	cd $(E1000)/src; make clean
	cd $(E1000E)/src; make clean
	cd $(IGB)/src; make clean
	cd $(IXGBE)/src; make clean
