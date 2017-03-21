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

#define IP_HDR_OPT_LEN 40

static struct nf_hook_ops nfho;
struct tcphdr *tcp_header;
unsigned int sport, dport;

void print_ip_header_options(struct sk_buff *skb);

unsigned int hook_func(unsigned int hooknum,
                       struct sk_buff **skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *)) 
{
    //NOTE: Feel free to uncomment printks! If you are using Vagrant and SSH
     //      too many printk's will flood your logs.
    // printk(KERN_INFO "=== BEGIN PACKET ===\n");

    struct sk_buff *sock_buff;
    sock_buff = skb;

    if (!sock_buff) {
        return NF_ACCEPT;
    }

    struct iphdr *iph;
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
            // print_ip_header_options(sock_buff);
        } else {
            // printk(KERN_INFO "Packet has no IP header options\n");
            if(iph->ihl * 4 == sizeof(struct iphdr) && iph->protocol==IPPROTO_ICMP) {
                printk(KERN_INFO "=== BEGIN PACKET ===\n");
                printk(KERN_INFO "ICMP packet with no IP header options detected\n");
                printk(KERN_INFO "Packet size: %d\n", iph->tot_len);
                printk(KERN_INFO "IP header size: %d\n", iph->ihl * 4);
                printk(KERN_INFO "IP header source: %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
                printk(KERN_INFO "IP header dest: %d.%d.%d.%d\n", NIPQUAD(iph->daddr));

                // expand skb headroom (from http://stackoverflow.com/a/6417918)
                printk(KERN_INFO "skb headroom: %d\n", skb_headroom(sock_buff));                
                if (skb_headroom(sock_buff) < IP_HDR_OPT_LEN) {
                    if (0 != pskb_expand_head(sock_buff, IP_HDR_OPT_LEN - skb_headroom(sock_buff), 0, GFP_ATOMIC)) {
                        printk(KERN_ERR "Error: Unable to expand skb headroom\n");
                        kfree_skb(sock_buff);
                        return NF_STOLEN;
                    } else {
                        printk(KERN_INFO "Expanded skb headroom to: %d\n", skb_headroom(sock_buff));
                    }
                }

                // copy stuff to new IP header
                char *temp;
                temp = kzalloc(sizeof(struct iphdr) + IP_HDR_OPT_LEN, GFP_ATOMIC);
                struct iphdr *new_iphdr;
                new_iphdr = (struct iphdr*)temp;
                memcpy(new_iphdr, iph, sizeof(struct iphdr));

                // edit length values
                new_iphdr->tot_len  = new_iphdr->tot_len + IP_HDR_OPT_LEN;
                new_iphdr->ihl      = new_iphdr->ihl + (IP_HDR_OPT_LEN / 4);

                // Calculation of IP header checksum
                new_iphdr->check    = 0;
                ip_send_check(new_iphdr);

                // remove old IP header then put the new one in
                skb_pull(sock_buff, sizeof(struct iphdr));
                struct iphdr *new_iph;
                new_iph = skb_push(sock_buff, sizeof(struct iphdr) + IP_HDR_OPT_LEN);
                skb_reset_network_header(sock_buff);
                memcpy(new_iph, new_iphdr, sizeof(struct iphdr) + IP_HDR_OPT_LEN);

                struct iphdr *iph2;
                iph2 = (struct iphdr *)skb_network_header(sock_buff);
                printk(KERN_INFO "New Packet size: %d\n", iph2->tot_len);
                printk(KERN_INFO "New IP header size: %d\n", iph2->ihl * 4);
                printk(KERN_INFO "New IP header source: %d.%d.%d.%d\n", NIPQUAD(iph2->saddr));
                printk(KERN_INFO "New IP header dest: %d.%d.%d.%d\n", NIPQUAD(iph2->daddr));
                print_ip_header_options(sock_buff);
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

void print_ip_header_options(struct sk_buff *sock_buff) {
    // based on: https://github.com/torvalds/linux/blob/6939c33a757bd006c5e0b8b5fd429fc587a4d0f4/net/netfilter/xt_LOG.c
    struct iphdr *iph2;
    iph2 = (struct iphdr *)skb_network_header(sock_buff);
    const unsigned char *op;
    unsigned char _opt[4 * 15 - sizeof(struct iphdr)];
    unsigned int i, optsize;
    optsize = iph2->ihl * 4 - sizeof(struct iphdr);
    printk(KERN_INFO "IP header options size: %d\n", optsize);
    if (optsize == 0) {
        printk(KERN_INFO "Empty IP header options\n");
    } else {
        op = skb_header_pointer(sock_buff, sizeof(struct iphdr), optsize, _opt);
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
}

static int __init initialize(void) {
    printk(KERN_INFO "Initializing netfilter.\n");
    nfho.hook = hook_func;
    // nfho.hooknum = NF_INET_PRE_ROUTING;
    //Interesting note: A pre-routing hook may not work here if our Vagrant
    //                  box does not know how to route to the modified source.
    //                  For the record, mine did not.
    // nfho.hooknum = NF_INET_POST_ROUTING;

    // hook onto outgoing packets (All outgoing packets created by this local computer pass this hook in ip_build_and_send_pkt())
    nfho.hooknum = NF_INET_LOCAL_OUT;

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
