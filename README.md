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
[ 1127.261028] Initializing netfilter.
[ 1127.262982] === BEGIN PACKET ===
[ 1127.262985] Packet size: 84
[ 1127.262985] IP header size: 20
[ 1127.262987] magicstring: wheeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
[ 1127.262988] Input magic string length in bytes: 59
[ 1127.262989] String length too large, reducing to 39 bytes
[ 1127.262990] New Packet size: 124
[ 1127.262990] New IP header size: 60
[ 1127.262991] New IP header source: 127.0.0.1
[ 1127.262992] New IP header dest: 127.0.0.1
[ 1127.262993] IP header options size: 40
[ 1127.262993] IP options: (0077686565656565656565656565656565656565656565656565656565656
5656565656565656565)
[ 1127.263001] === END PACKET ===
[ 1127.263010] === BEGIN PACKET ===
[ 1127.263011] Packet size: 84
[ 1127.263011] IP header size: 20
[ 1127.263012] magicstring: wheeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
[ 1127.263013] Input magic string length in bytes: 59
[ 1127.263016] String length too large, reducing to 39 bytes
[ 1127.263017] New Packet size: 124
[ 1127.263017] New IP header size: 60
[ 1127.263018] New IP header source: 127.0.0.1
[ 1127.263018] New IP header dest: 127.0.0.1
[ 1127.263019] IP header options size: 40
[ 1127.263020] IP options: (0077686565656565656565656565656565656565656565656565656565656
5656565656565656565)
[ 1127.263027] === END PACKET ===
[ 1127.267873] Tearing down netfilter.
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
