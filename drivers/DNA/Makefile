all: igb ixgbe e1000e e1000

e1000:
	cd e1000-8.0.35-DNA/src; make

e1000e:
	cd e1000e-2.0.0-DNA/src; make

igb:
	cd igb-3.4.7-DNA/src; make

ixgbe:
	cd ixgbe-3.7.17-DNA/src; make

clean:
	cd e1000e-2.0.0-DNA/src; make clean
	cd igb-3.4.7-DNA/src; make clean
	cd ixgbe-3.7.17-DNA/src; make clean
	cd e1000-8.0.35-DNA/src; make clean

