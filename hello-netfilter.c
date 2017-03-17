//Filename: hello-netfilter.c
#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

//nfho is a nf_hook_ops struct. This struct stores all the
//required information to register a Netfilter hook.
static struct nf_hook_ops nfho;

//hook_func is our Netfilter function that will be called at the pre-routing
//hook. This hook merely logs that Netfilter received a packet and tells
//Netfilter to continue processing that packet.
unsigned int hook_func(unsigned int hooknum,
                       struct sk_buff **skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *)) {

        printk(KERN_INFO "Packet!\n"); //Lets log that we recieved a packet.
        return NF_ACCEPT; //NF_ACCEPT tells the hook to continue processing the packet.

}

//initialize will setup our Netfilter hook when our kernel
//module is loaded.
static int __init initialize(void) {
        nfho.hook     = hook_func; //Points to our hook function.
        nfho.hooknum  = NF_INET_PRE_ROUTING; //Our function will run at Netfilter's pre-routing hook.
        nfho.pf       = PF_INET; //pf = protocol family. We are only interested in IPv4 traffic.
        nfho.priority = NF_IP_PRI_FIRST; //Tells Netfilter this hook should be ran "first" (there is of-course, more to this when other hooks have this priority)
        nf_register_hook(&nfho); //We now register our hook function.
        return 0;
}

static void __exit cleanup(void) {
        nf_unregister_hook(&nfho); //unregister our hook
}

module_init(initialize);
module_exit(cleanup);
