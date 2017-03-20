//Filename: hello.c
#include <linux/module.h>
#include <linux/init.h>

//setup will be the function that is called when our module is loaded.
static int __init setup(void) {
	printk(KERN_INFO "Hello, world!\n"); //printk is the kernel's version of printf. KERN_INFO is a log-level macro.
	return 0; //a return value of zero tells insmod that the module loaded successfully
}

//teardown will be the function that is called when our module is unloaded.
static void __exit teardown(void) {
	printk(KERN_INFO "Goodbye, cruel world!\n");
}

module_init(setup); //module_init defines the setup function for inserting the module
module_exit(teardown); //module_exit defines the teardown function for removing the module
