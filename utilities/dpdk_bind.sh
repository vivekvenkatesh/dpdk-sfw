#!/bin/bash

# === Configuration ===
VM_USERNAME="dpdk1"
VM_GROUP="dpdk1"
PCI_ADDRESS="0000:01:00.0"
DPDK_DRIVER="vfio-pci"
DPDK_DEVBIND="/home/${VM_USERNAME}/softwares/dpdk/dpdk-stable-24.11.3/usertools/dpdk-devbind.py" 

TAP_DEV="tap0"

# === 1. Bind Physical NIC to DPDK ===
echo "Loading module: $DPDK_DRIVER"
modprobe $DPDK_DRIVER

IF_NAME=$(basename $(ls /sys/bus/pci/devices/$PCI_ADDRESS/net/ 2>/dev/null))
if [ -n "$IF_NAME" ]; then
    echo "Found interface '$IF_NAME' for $PCI_ADDRESS. Taking it down."
    ip link set $IF_NAME down
else
    echo "No kernel interface found for $PCI_ADDRESS (already bound?)."
fi

echo "Binding $PCI_ADDRESS to $DPDK_DRIVER"
# Add --noiommu-mode back if you reverted the VM's IOMMU settings
$DPDK_DEVBIND --bind=$DPDK_DRIVER $PCI_ADDRESS

echo "--- DPDK Setup Complete ---"
