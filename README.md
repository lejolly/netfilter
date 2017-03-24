# netfilter
Based on: https://kel.bz/post/netfilter/

### setup ubuntu
```
$ sudo apt-get update
$ sudo apt-get install build-essential linux-headers-$(uname -r) make wireshark nmap git
```

### clone repo
```
$ git clone https://github.com/lejolly/netfilter.git
```

### run make
```
$ cd ./netfilter
$ make
```

### see messages from kernel module (open in another window)
```
$ watch 'sudo dmesg -c >> /tmp/dmesg.log; tail -n 40 /tmp/dmesg.log'
```

### load module
```
$ sudo insmod netfilter.ko magicstring=whee
(for multiple words use something like this: magicstring="\"hello world\"")
```

### use wireshark to inspect packets (optional, open in another window)
```
$ sudo wireshark
(listen on the loopback interface)
```

### use ping to generate packets
```
$ ping -c 1 localhost
```

### there is a random chance that your packet won't make it through
the kernel module randomly decides whether to put the magicstring into the packet. if the incoming hook does not detect the same magicstring, then it drops the packet. 

### you should see stuff like this from dmesg
```
[ 2789.829817] Initializing netfilter.
[ 2789.829922]
[ 2789.832270] === BEGIN OUTGOING ICMP PACKET WITH NO IP HEADER OPTIONS ===
[ 2789.832274] magicstring: hello world
[ 2789.832275] input magicstring length in bytes: 12
[ 2789.832277] putting magicstring into packet.
[ 2789.832278] resulting magicstring: hello world
[ 2789.832279] ===  END  OUTGOING ICMP PACKET WITH NO IP HEADER OPTIONS ===
[ 2789.832279]
[ 2789.832286] === BEGIN INCOMING ICMP PACKET WTIH IP HEADER OPTIONS ===
[ 2789.832287] magicstring: hello world
[ 2789.832288] strings match, sending packet through.
[ 2789.832288] ===  END  INCOMING ICMP PACKET WTIH IP HEADER OPTIONS ===
[ 2789.832289]
[ 2789.832292] === BEGIN OUTGOING ICMP PACKET WITH NO IP HEADER OPTIONS ===
[ 2789.832293] magicstring: hello world
[ 2789.832294] input magicstring length in bytes: 12
[ 2789.832295] putting magicstring into packet.
[ 2789.832298] resulting magicstring: hello world
[ 2789.832298] ===  END  OUTGOING ICMP PACKET WITH NO IP HEADER OPTIONS ===
[ 2789.832299]
[ 2789.832301] === BEGIN INCOMING ICMP PACKET WTIH IP HEADER OPTIONS ===
[ 2789.832302] magicstring: hello world
[ 2789.832302] strings match, sending packet through.
[ 2789.832303] ===  END  INCOMING ICMP PACKET WTIH IP HEADER OPTIONS ===
[ 2789.832304]
[ 2789.838428] Tearing down netfilter.
[ 2789.838729]
```

### unload module
```
$ sudo rmmod netfilter
```

### sample script to help run through things faster
```
#/bin/bash

rm -f ./netfilter.c
cp /media/psf/netfilter/netfilter.c ./netfilter.c
make
sudo insmod ./netfilter.ko magicstring=wheeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
ping -c 1 localhost
sudo rmmod netfilter
```

### use nmap to generate packets with IP header options (not used)
```
$ nmap --ip-options "R" localhost
```

### possibly useful links
- http://lxr.free-electrons.com/source/net/netfilter/xt_LOG.c?v=3.10
- http://seclists.org/nmap-dev/2006/q3/52
- https://www.digitalocean.com/community/tutorials/a-deep-dive-into-iptables-and-netfilter-architecture
