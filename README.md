# netfilter
Based on: https://kel.bz/post/netfilter/

### setup ubuntu
```
$ sudo apt-get update
$ sudo apt-get install build-essential linux-headers-$(uname -r) make wireshark nmap
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

### possibly useful links
- http://lxr.free-electrons.com/source/net/netfilter/xt_LOG.c?v=3.10
- http://seclists.org/nmap-dev/2006/q3/52
