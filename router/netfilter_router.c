//Filename: netfilter_client.c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <net/ip.h>

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

#define IP_HDR_OPT_LEN 40
static char *magicstring = "default magicstring";
static char *request_string = "request";
static int cap_counter = 0;

static struct nf_hook_ops out_nfho;
static struct nf_hook_ops in_nfho;
struct tcphdr *tcp_header;
unsigned int sport, dport;

void print_ip_header_options(struct sk_buff *skb);

unsigned int out_hook_func(unsigned int hooknum,
                       struct sk_buff **skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *)) 
{
    struct sk_buff *sock_buff;
    sock_buff = skb;

    if (!sock_buff) {
        return NF_ACCEPT;
    }

    struct iphdr *iph;
    iph = (struct iphdr *)skb_network_header(sock_buff);

    if (iph && iph->ihl * 4 == (sizeof(struct iphdr) + IP_HDR_OPT_LEN) && iph->protocol==IPPROTO_ICMP) {
        printk(KERN_INFO "=== BEGIN OUTGOING ICMP PACKET WITH IP HEADER OPTIONS ===\n");

        // print original packet details
        // printk(KERN_INFO "Packet size: %d\n", ntohs(iph->tot_len));
        // printk(KERN_INFO "IP header size: %d\n", iph->ihl * 4);
        // printk(KERN_INFO "IP header source: %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
        // printk(KERN_INFO "IP header dest: %d.%d.%d.%d\n", NIPQUAD(iph->daddr));

        // expand skb headroom (from http://stackoverflow.com/a/6417918)
        // printk(KERN_INFO "Current skb headroom: %d\n", skb_headroom(sock_buff));
        if (skb_headroom(sock_buff) < IP_HDR_OPT_LEN) {
            if (0 != pskb_expand_head(sock_buff, IP_HDR_OPT_LEN - skb_headroom(sock_buff), 0, GFP_ATOMIC)) {
                printk(KERN_ERR "Error: Unable to expand skb headroom\n");
                kfree_skb(sock_buff);
                return NF_STOLEN;
            } else {
                // printk(KERN_INFO "Expanded skb headroom to: %d\n", skb_headroom(sock_buff));
            }
        }

        // copy original IP header to new IP header
        unsigned int new_hdr_len = sizeof(struct iphdr) + IP_HDR_OPT_LEN;
        char *temp;
        temp = kzalloc(new_hdr_len, GFP_ATOMIC);
        struct iphdr *new_iphdr;
        new_iphdr = (struct iphdr*)temp;
        memcpy(new_iphdr, iph, sizeof(struct iphdr));

        // copy magic string to packet
        printk(KERN_INFO "magicstring: %s\n", magicstring);
        unsigned int str_len = (strlen(magicstring) + 1) * sizeof(char);
        printk(KERN_INFO "input magicstring length in bytes: %d\n", str_len);

        if (str_len > 39) {
            str_len = 39;
            printk(KERN_INFO "string length too large, reducing to 39 bytes\n");
        }
        char *magicstring_ptr = (char *)new_iphdr + sizeof(struct iphdr) + 1;
        // printk(KERN_INFO "new_iphdr:       0x%p\n", new_iphdr);
        // printk(KERN_INFO "magicstring_ptr: 0x%p\n", magicstring_ptr);        

        if (cap_counter > 0 && cap_counter < 3) {
            printk(KERN_INFO "putting magicstring into packet.\n");
            memcpy(magicstring_ptr, magicstring, str_len);
            printk(KERN_INFO "resulting magicstring: %s\n", magicstring_ptr);
            cap_counter++;
        }

        // edit length values
        // new_iphdr->tot_len  = htons(ntohs(new_iphdr->tot_len) + IP_HDR_OPT_LEN);
        // new_iphdr->ihl      = new_iphdr->ihl + (IP_HDR_OPT_LEN / 4);

        // Calculation of IP header checksum
        new_iphdr->check    = 0;
        ip_send_check(new_iphdr);

        // remove old IP header then put the new one in
        skb_pull(sock_buff, sizeof(struct iphdr) + IP_HDR_OPT_LEN);
        struct iphdr *new_iph;
        new_iph = skb_push(sock_buff, new_hdr_len);
        skb_reset_network_header(sock_buff);
        memcpy(new_iph, new_iphdr, new_hdr_len);

        // print new packet details
        // struct iphdr *iph2;
        // iph2 = (struct iphdr *)skb_network_header(sock_buff);
        // printk(KERN_INFO "New Packet size: %d\n", ntohs(iph2->tot_len));
        // printk(KERN_INFO "New IP header size: %d\n", iph2->ihl * 4);
        // printk(KERN_INFO "New IP header source: %d.%d.%d.%d\n", NIPQUAD(iph2->saddr));
        // printk(KERN_INFO "New IP header dest: %d.%d.%d.%d\n", NIPQUAD(iph2->daddr));
        // print_ip_header_options(sock_buff);

        printk(KERN_INFO "===  END  OUTGOING ICMP PACKET WITH IP HEADER OPTIONS ===\n");
        printk(KERN_INFO "\n");
    }

    return NF_ACCEPT;
}

unsigned int in_hook_func(unsigned int hooknum,
                       struct sk_buff **skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *)) 
{
    struct sk_buff *sock_buff;
    sock_buff = skb;

    if (!sock_buff) {
        return NF_ACCEPT;
    }

    struct iphdr *iph;
    iph = (struct iphdr *)skb_network_header(sock_buff);

    if (iph && iph->ihl * 4 == (sizeof(struct iphdr) + IP_HDR_OPT_LEN) && iph->protocol==IPPROTO_ICMP) {
        printk(KERN_INFO "=== BEGIN INCOMING ICMP PACKET WTIH IP HEADER OPTIONS ===\n");

        // copy string
        char *magicstring_ptr = (char *)iph + sizeof(struct iphdr) + 1;
        char *temp;
        temp = kzalloc(IP_HDR_OPT_LEN, GFP_ATOMIC);
        memcpy(temp, magicstring_ptr, IP_HDR_OPT_LEN - 1);

        printk(KERN_INFO "options found: %s\n", temp);

        // compare strings
        if(strcmp(temp, request_string) == 0) {
            printk(KERN_INFO "SIFF handshaking request detected.\n");
            cap_counter = 1;
        } else {
            if (strcmp(temp, magicstring) != 0) {
                printk(KERN_INFO "error: strings do not match, dropping packet.\n");
                kfree_skb(sock_buff);
                printk(KERN_INFO "===  END  INCOMING ICMP PACKET WTIH IP HEADER OPTIONS ===\n");
                printk(KERN_INFO "\n");
                return NF_STOLEN;
            }
        }

        printk(KERN_INFO "===  END  INCOMING ICMP PACKET WTIH IP HEADER OPTIONS ===\n");
        printk(KERN_INFO "\n");
    }

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
    // printk(KERN_INFO "magicstring: %s\n", magicstring);

    // hook onto outgoing packets
    out_nfho.hook = out_hook_func;
    // hook onto outgoing packets (All outgoing packets created by this local computer pass this hook in ip_build_and_send_pkt())
    // out_nfho.hooknum = NF_INET_LOCAL_OUT;
    out_nfho.hooknum = NF_INET_POST_ROUTING;
    out_nfho.pf = PF_INET;
    out_nfho.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&out_nfho);

    // hook onto incoming packets
    in_nfho.hook = in_hook_func;
    in_nfho.hooknum = NF_INET_PRE_ROUTING;
    // in_nfho.hooknum = NF_INET_PRE_ROUTING;
    //Interesting note: A pre-routing hook may not work here if our Vagrant
    //                  box does not know how to route to the modified source.
    //                  For the record, mine did not.
    // in_nfho.hooknum = NF_INET_POST_ROUTING;
    in_nfho.pf = PF_INET;
    in_nfho.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&in_nfho);

    printk(KERN_INFO "\n");
    return 0;
}

static void __exit teardown(void) {
    printk(KERN_INFO "Tearing down netfilter.\n");
    nf_unregister_hook(&out_nfho);
    nf_unregister_hook(&in_nfho);
    printk(KERN_INFO "\n");
}

module_init(initialize);
module_exit(teardown);

MODULE_LICENSE("GPL");

module_param(magicstring, charp, 0000);
MODULE_PARM_DESC(magicstring, "Magic string");
