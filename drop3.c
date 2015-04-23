#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#define NIPQUAD(addr) \  
  ((unsigned char *)&addr)[0], \  
  ((unsigned char *)&addr)[1], \  
  ((unsigned char *)&addr)[2], \  
  ((unsigned char *)&addr)[3]  
 

static struct nf_hook_ops nfho;   //net filter hook option struct
struct sk_buff *sock_buff;
struct udphdr *udp_header;          //udp header struct (not used)
struct iphdr *ip_header;            //ip header struct
unsigned long dip;
unsigned long sip;
int plr=1;
unsigned short int randomnum;
int type=1;//random 1,proportion 2 //need to finish next
unsigned long tarip;
int protocol=1;//1 udp 2 tcp
int dropmark=0;
module_param(plr, int, S_IRUGO|S_IWUSR);
module_param(type, int, S_IRUGO|S_IWUSR);
module_param(tarip, ulong, S_IRUGO|S_IWUSR);

void get_random_bytes(void *buf, int nbytes); 

unsigned int hook_func(unsigned int hooknum, struct sk_buff **skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
        sock_buff = *skb;
 
        ip_header = (struct iphdr *)ip_hdr(sock_buff);    //header 
        dip = ip_header->daddr;
        sip = ip_header->saddr;
//        printk("Packet for source address: %d.%d.%d.%d\n destination address: %d.%d.%d.%d\n ", NIPQUAD(sip), NIPQUAD(dip));  
        if(!sock_buff) { return NF_ACCEPT;}
        if(tarip==dip){
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
//        if (ip_header->protocol==17) {
//                udp_header = (struct udphdr *)skb_transport_header(sock_buff);  //grab transport header
// 
//                printk(KERN_INFO "got udp packet \n");     //log we¡¯ve got udp packet to /var/log/messages
//                return NF_DROP;
//        }
               
        return NF_ACCEPT;
}
 
int init_module()
{
        nfho.hook = hook_func;
        nfho.hooknum = NF_IP_LOCAL_OUT;
        nfho.pf = PF_INET;
        nfho.priority = NF_IP_PRI_FIRST;
        nf_register_hook(&nfho);     
        return 0;
}
 
void cleanup_module()
{
        nf_unregister_hook(&nfho);     
}
 