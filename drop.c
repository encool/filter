#include <linux/module.h>  
#include <linux/kernel.h>  
#include <linux/init.h>  
#include <linux/types.h>  
#include <linux/netdevice.h>  
#include <linux/skbuff.h>  
#include <linux/netfilter_ipv4.h>  
#include <linux/inet.h>  
#include <linux/in.h>  
#include <linux/ip.h>
#include <linux/delay.h> 
void msleep(unsigned int millisecs);
void get_random_bytes(void *buf, int nbytes); 
MODULE_LICENSE("GPL");  
#define NIPQUAD(addr) \  
  ((unsigned char *)&addr)[0], \  
  ((unsigned char *)&addr)[1], \  
  ((unsigned char *)&addr)[2], \  
  ((unsigned char *)&addr)[3]  
int plr=0;
unsigned short int randomnum;

int type=1;//random 1,proportion 2
unsigned long tarip;
int protocol=1;//1 udp 2 tcp
int dropmark=0;

module_param(dropmark, int, S_IRUGO|S_IWUSR);
module_param(plr, int, S_IRUGO|S_IWUSR);
module_param(type, int, S_IRUGO|S_IWUSR);
module_param(tarip, ulong, S_IRUGO|S_IWUSR);
module_param(protocol, int, S_IRUGO|S_IWUSR);
static unsigned int sample(  
unsigned int hooknum,  
struct sk_buff * skb,  
const struct net_device *in,  
const struct net_device *out,  
int (*okfn) (struct sk_buff *))  
{  
    unsigned long sip,dip; 
	get_random_bytes(&randomnum,sizeof(short int)); 
	//printk("random-->%d,type-->%d,protocol-->%d\n",randomnum,type,protocol); 
	if(skb){  
		struct sk_buff *sb = NULL;  
		sb = skb;  
		struct iphdr *iph;  
		iph  = ip_hdr(sb);  
		sip = iph->saddr;  
		dip = iph->daddr;
		if(type==1){
			if((tarip==dip)||!tarip){
				if(dropmark<100){
					dropmark=dropmark+1;
					if(dropmark<plr){	
						return NF_DROP;
					}
				}else{
					dropmark=0;
					return NF_DROP;
				}
			}else{
				return NF_ACCEPT;
			}
		}else if(type==2){
			if((tarip==dip)||!tarip){
				if(randomnum<655.35*plr){
					return NF_DROP;
				}
			}else{
				return NF_ACCEPT;
			}
			if((tarip==dip)||!tarip){
				if(randomnum<655.35*plr){
					return NF_DROP;
				}
			}
  // printk("dip==%x",dip);
//	if(((unsigned char *)&sip)[0]==127){msleep(1);}
  // printk("Packet for source address: %d.%d.%d.%d\n destination address: %d.%d.%d.%d\n ", NIPQUAD(sip), NIPQUAD(dip));  
		}  
		return NF_ACCEPT;  
	}  
}
  
 struct nf_hook_ops sample_ops = {  
   .list =  {NULL,NULL},  
   .hook = sample,  
   .pf = PF_INET,  
   .hooknum = NF_INET_LOCAL_OUT,  
   .priority = NF_IP_PRI_FILTER+2  
 };  
  
static int __init sample_init(void) {  
  nf_register_hook(&sample_ops);  
  return 0;  
}  
  
  
static void __exit sample_exit(void) {  
  nf_unregister_hook(&sample_ops);  
}  
  
 module_init(sample_init);  
 module_exit(sample_exit);   
 MODULE_AUTHOR("liqiao");  
 MODULE_DESCRIPTION("netfilter");  
