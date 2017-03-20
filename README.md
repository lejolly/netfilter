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
$ make
```

### load module
```
$ sudo insmod netfilter.ko
```

### unload module
```
$ sudo rmmod netfilter
```

### see messages from kernel module
```
$ watch 'sudo dmesg -c >> /tmp/dmesg.log; tail -n 20 /tmp/dmesg.log'
```

### use wireshark to inspect packets
```
$ sudo wireshark
```

### use nmap to generate packets with IP header options
```
$ nmap --ip-options "R" localhost
```

### you should see stuff like this from dmesg
```
[17546.783268] Initializing netfilter.
[17546.783277] Packet has IP header
[17546.783277] Packet has IP header options
[17546.783278] IP options: (0727107F0000017F0000017F00000100000000000000000000000000000000000000000000000000)
[17547.989705] Packet has IP header
[17547.989722] Packet has no IP header options
[17551.934391] Tearing down netfilter.
```

### possibly useful links
- http://lxr.free-electrons.com/source/net/netfilter/xt_LOG.c?v=3.10
- http://seclists.org/nmap-dev/2006/q3/52
- https://www.digitalocean.com/community/tutorials/a-deep-dive-into-iptables-and-netfilter-architecture
