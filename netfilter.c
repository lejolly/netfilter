//Filename: netfilter.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <net/ip.h>

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

static struct nf_hook_ops nfho;
struct iphdr *iph;
struct tcphdr *tcp_header;
struct sk_buff *sock_buff;
unsigned int sport, dport;

void print_ip_header_options(struct sk_buff **skb, struct iphdr *iph);

unsigned int hook_func(unsigned int hooknum,
                       struct sk_buff **skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *)) 
{
    //NOTE: Feel free to uncomment printks! If you are using Vagrant and SSH
     //      too many printk's will flood your logs.
    // printk(KERN_INFO "=== BEGIN PACKET ===\n");

    sock_buff = skb;

    if (!sock_buff) {
        return NF_ACCEPT;
    }

    iph = (struct iphdr *)skb_network_header(sock_buff);

    if (!iph) {
        // printk(KERN_INFO "Packet has no IP header\n");
        // return NF_ACCEPT;
    } else {
        // printk(KERN_INFO "Packet has IP header\n");
        // printk(KERN_INFO "Packet size: %d\n", iph->tot_len * 4);
        // printk(KERN_INFO "IP header size: %d\n", iph->ihl * 4);
        if (iph->ihl * 4 > sizeof(struct iphdr)) {
            // printk(KERN_INFO "Packet has IP header options\n");
            // print_ip_header_options(skb, iph);
        } else {
            // printk(KERN_INFO "Packet has no IP header options\n");
            if(iph->protocol==IPPROTO_ICMP) {
                printk(KERN_INFO "=== BEGIN PACKET ===\n");
                printk(KERN_INFO "ICMP packet with no IP header options detected\n");
                printk(KERN_INFO "Packet size: %d\n", iph->tot_len * 4);
                printk(KERN_INFO "IP header size: %d\n", iph->ihl * 4);

                // add stuff here to mangle IP header
                

                // Calculation of IP header checksum
                iph->check = 0;
                ip_send_check(iph);

                printk(KERN_INFO "New IP header size: %d\n", iph->ihl * 4);
                printk(KERN_INFO "New Packet size: %d\n", iph->tot_len * 4);
                printk(KERN_INFO "=== END PACKET ===\n");
            }
        }
    }

    // if(iph->protocol==IPPROTO_TCP) {
    //     return NF_ACCEPT;

    //     tcp_header = tcp_hdr(sock_buff);
    //     sport = htons((unsigned short int) tcp_header->source);
    //     dport = htons((unsigned short int) tcp_header->dest);
    //     printk(KERN_INFO "TCP ports: source: %d, dest: %d \n", sport, dport);
    //     printk(KERN_INFO "SKBuffer: len %d, data_len %d\n", sock_buff->len, sock_buff->data_len);
    // }

    // if(iph->protocol==IPPROTO_ICMP) {
    //     printk(KERN_INFO "=== BEGIN ICMP ===\n");
    //     printk(KERN_INFO "IP header: original source: %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
    //     iph->saddr = iph->saddr ^ 0x10000000;
    //     printk(KERN_INFO "IP header: modified source: %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
    //     printk(KERN_INFO "IP header: original destin: %d.%d.%d.%d\n", NIPQUAD(iph->daddr));
    //     printk(KERN_INFO "=== END ICMP ===\n");
    // }

    //if(in) { printk(KERN_INFO "in->name:  %s\n", in->name); }
    //if(out) { printk(KERN_INFO "out->name: %s\n", out->name); }
    
    // printk(KERN_INFO "=== END PACKET ===\n");

    return NF_ACCEPT;
}

void print_ip_header_options(struct sk_buff **skb, struct iphdr *iph) {
    // based on: https://github.com/torvalds/linux/blob/6939c33a757bd006c5e0b8b5fd429fc587a4d0f4/net/netfilter/xt_LOG.c
    const unsigned char *op;
    unsigned char _opt[4 * 15 - sizeof(struct iphdr)];
    unsigned int i, optsize;
    optsize = iph->ihl * 4 - sizeof(struct iphdr);
    printk(KERN_INFO "IP header options size: %d\n", optsize);
    op = skb_header_pointer(skb, sizeof(struct iphdr), optsize, _opt);
    if (op == NULL) {
        printk(KERN_INFO "NULL IP options\n");
    } else {
        /* Max length: 127 "OPT (" 15*4*2chars ") " */
        printk(KERN_INFO "IP options: (");
        for (i = 0; i < optsize; i++) {
            printk(KERN_CONT "%02X", op[i]);
        }
        printk(KERN_CONT ")\n");
    }
}

static int __init initialize(void) {
    printk(KERN_INFO "Initializing netfilter.\n");
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    //Interesting note: A pre-routing hook may not work here if our Vagrant
    //                  box does not know how to route to the modified source.
    //                  For the record, mine did not.
    // nfho.hooknum = NF_INET_POST_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho);
    return 0;    
}

static void __exit teardown(void) {
    printk(KERN_INFO "Tearing down netfilter.\n");
    nf_unregister_hook(&nfho);
}

module_init(initialize);
module_exit(teardown);
