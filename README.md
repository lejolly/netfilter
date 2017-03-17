# netfilter
netfilter

Based on: https://kel.bz/post/netfilter/

### setup ubuntu
```
$ sudo apt-get update
$ sudo apt-get install build-essential linux-headers-$(uname -r) make vim
```

### run make
```
$ make
```

### load module
```
$ sudo insmod hello.ko
```

### see messages from kernel module
```
$ dmesg | tail
```
