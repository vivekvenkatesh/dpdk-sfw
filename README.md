# dpdk-sfw

A simple stateful firewall implementation using DPDK, for the purpose of learning DPDK.

Project Goal: Create a stateful firewall that allows outbound connections and only permits inbound traffic that is a response to an established connection.

Build the application:

bazel build //src:sfw

To run the application:

sudo setcap cap_net_admin,cap_net_raw+ep bazel-bin/src/sfw
bazel-bin/src/sfw -l 1-2 -n 4 --vdev=net_tap0,iface=tap0

Where:
   -l argument specifies DPDK to use cores 1 and 2
   -n argument specifies DPDK to use 4 memory channels
   --vdev argument creates a virtual tap interface to initate traffic from/to the VM through DPDK