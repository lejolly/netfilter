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

### you should see stuff like this from dmesg
```
[ 1128.134822] Initializing netfilter.
[ 1128.138234] === BEGIN OUTGOING ICMP PACKET WITH NO IP HEADER OPTIONS ===
[ 1128.138237] magicstring: hello world
[ 1128.138238] input magicstring length in bytes: 12
[ 1128.138239] resulting magicstring: hello world
[ 1128.138240] === END OUTGOING ICMP PACKET WITH NO IP HEADER OPTIONS ===
[ 1128.138246] === BEGIN INCOMING ICMP PACKET WTIH IP HEADER OPTIONS ===
[ 1128.138247] magicstring: hello world
[ 1128.138248] === END INCOMING ICMP PACKET WTIH IP HEADER OPTIONS ===
[ 1128.138251] === BEGIN OUTGOING ICMP PACKET WITH NO IP HEADER OPTIONS ===
[ 1128.138252] magicstring: hello world
[ 1128.138253] input magicstring length in bytes: 12
[ 1128.138253] resulting magicstring: hello world
[ 1128.138254] === END OUTGOING ICMP PACKET WITH NO IP HEADER OPTIONS ===
[ 1128.138258] === BEGIN INCOMING ICMP PACKET WTIH IP HEADER OPTIONS ===
[ 1128.138258] magicstring: hello world
[ 1128.138259] === END INCOMING ICMP PACKET WTIH IP HEADER OPTIONS ===
[ 1128.146348] Tearing down netfilter.
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
