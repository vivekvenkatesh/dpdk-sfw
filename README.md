# dpdk-sfw

A simple stateful firewall implementation using DPDK, for the purpose of learning DPDK.

Project Goal: Create a stateful firewall that allows outbound connections and only permits inbound traffic that is a response to an established connection.

To build the application:
-------------------------

bazel build //:sfw -c dbg --strip=never

To run the application:
-----------------------

sudo setcap cap_net_admin,cap_net_raw+ep bazel-bin/sfw

bazel-bin/sfw -l 1-3 -n 4 --vdev=net_tap0,iface=tap0

Where:
   -l argument specifies DPDK to use cores 1, 2 (for NIC and tap interfaces) and 3 (for CLI)
   -n argument specifies DPDK to use 4 memory channels
   --vdev argument creates a virtual tap interface to send/receive traffic from/to the VM via DPDK

To run the tests:
-----------------

From tests/ folder, run:

  bash run_tests_bazel.sh


Example output:
----------------

Here one flow entry correspond to the outbound key and another to the inbound key that were inserted into the hash table pointing to the same CT entry. This is by design.

**ICMP traffic exchange from tap interface to outside:**

From client, run the below command:

`ping -I tap0 192.168.100.1 -c 1`

CLI Output:

```
dpdk1@dpdk1:~/git/dpdk-sfw$ bazel-bin/sfw -l 1-3 -n 4 --vdev=net_tap0,iface=tap0
EAL: Detected CPU lcores: 6
EAL: Detected NUMA nodes: 1
EAL: Detected shared linkage of DPDK
EAL: Multi-process socket /run/user/1000/dpdk/rte/mp_socket
EAL: rte_mem_virt2phy(): cannot open /proc/self/pagemap: Permission denied
EAL: Selected IOVA mode 'VA'
EAL: VFIO support initialized
EAL: Using IOMMU type 1 (Type 1)
sfw> hash dump
Flow Entry #1:
    Out Key: src_ip=192.168.100.2 dst_ip=192.168.100.1 protocol=1 icmp_type=8 icmp_code=0 icmp_id=14548 icmp_seq=1
    In Key: src_ip=192.168.100.1 dst_ip=192.168.100.2 protocol=1 icmp_type=0 icmp_code=0 icmp_id=14548 icmp_seq=1
    State: ESTABLISHED
    Last Seen: 4 seconds ago
    Timeout: 5 seconds left

Flow Entry #2:
    Out Key: src_ip=192.168.100.2 dst_ip=192.168.100.1 protocol=1 icmp_type=8 icmp_code=0 icmp_id=14548 icmp_seq=1
    In Key: src_ip=192.168.100.1 dst_ip=192.168.100.2 protocol=1 icmp_type=0 icmp_code=0 icmp_id=14548 icmp_seq=1
    State: ESTABLISHED
    Last Seen: 4 seconds ago
    Timeout: 5 seconds left
```


**TCP traffic exchange from tap interface to outside:**

From client, run the below command:

```
$ nc -p 4444 -s 192.168.100.2 192.168.100.1 4444 <-- Initial handshake
hello  <-- data exchange
^C <-- terminate connection
```


From server, run the below command:

```
$ nc -l 192.168.100.1 4444
hello
```

CLI Output:

After initial 3-way handshake:

```
dpdk1@dpdk1:~/git/dpdk-sfw$ bazel-bin/sfw -l 1-3 -n 4 --vdev=net_tap0,iface=tap0
EAL: Detected CPU lcores: 6
EAL: Detected NUMA nodes: 1
EAL: Detected shared linkage of DPDK
EAL: Multi-process socket /run/user/1000/dpdk/rte/mp_socket
EAL: rte_mem_virt2phy(): cannot open /proc/self/pagemap: Permission denied
EAL: Selected IOVA mode 'VA'
EAL: VFIO support initialized
EAL: Using IOMMU type 1 (Type 1)
sfw> hash dump

sfw> hash dump
Flow Entry #1:
    Out Key: src_ip=192.168.100.2 dst_ip=192.168.100.1 protocol=6 src_port=4444 dst_port=4444
    In Key: src_ip=192.168.100.1 dst_ip=192.168.100.2 protocol=6 src_port=4444 dst_port=4444
    State: ESTABLISHED
    Last Seen: 11 seconds ago
    Timeout: 3588 seconds left

Flow Entry #2:
    Out Key: src_ip=192.168.100.2 dst_ip=192.168.100.1 protocol=6 src_port=4444 dst_port=4444
    In Key: src_ip=192.168.100.1 dst_ip=192.168.100.2 protocol=6 src_port=4444 dst_port=4444
    State: ESTABLISHED
    Last Seen: 11 seconds ago
    Timeout: 3588 seconds left
```

After exchanging data:

We can see that the timeout is refreshed.

```
sfw> hash dump
Flow Entry #1:
    Out Key: src_ip=192.168.100.2 dst_ip=192.168.100.1 protocol=6 src_port=4444 dst_port=4444
    In Key: src_ip=192.168.100.1 dst_ip=192.168.100.2 protocol=6 src_port=4444 dst_port=4444
    State: ESTABLISHED
    Last Seen: 2 seconds ago
    Timeout: 3597 seconds left

Flow Entry #2:
    Out Key: src_ip=192.168.100.2 dst_ip=192.168.100.1 protocol=6 src_port=4444 dst_port=4444
    In Key: src_ip=192.168.100.1 dst_ip=192.168.100.2 protocol=6 src_port=4444 dst_port=4444
    State: ESTABLISHED
    Last Seen: 2 seconds ago
    Timeout: 3597 seconds left
```

After terminating the connection:

```
sfw> hash dump
Flow Entry #1:
    Out Key: src_ip=192.168.100.2 dst_ip=192.168.100.1 protocol=6 src_port=4444 dst_port=4444
    In Key: src_ip=192.168.100.1 dst_ip=192.168.100.2 protocol=6 src_port=4444 dst_port=4444
    State: CLOSING
    Last Seen: 2 seconds ago
    Timeout: 7 seconds left

Flow Entry #2:
    Out Key: src_ip=192.168.100.2 dst_ip=192.168.100.1 protocol=6 src_port=4444 dst_port=4444
    In Key: src_ip=192.168.100.1 dst_ip=192.168.100.2 protocol=6 src_port=4444 dst_port=4444
    State: CLOSING
    Last Seen: 2 seconds ago
    Timeout: 7 seconds left

sfw> hash dump
sfw>
```
