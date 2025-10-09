# dpdk-sfw

A simple stateful firewall implementation using DPDK, for the purpose of learning DPDK.

Project Goal: Create a stateful firewall that allows outbound connections and only permits inbound traffic that is a response to an established connection.

Build the application:

bazel build //src:sfw

To run the application:

bazel run //src:sfw -- -l 1-2 -n 4

Where -l argument specifies DPDK to use cores 1 and 2
and -n argument specifies DPDK to use 4 memory channels
