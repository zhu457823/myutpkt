#include <linux/netfilter.h>  
#include <linux/init.h>  
#include <linux/module.h>  
#include <linux/netfilter_ipv4.h>  
#include <linux/ip.h>  
#include <linux/inet.h>  
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <linux/netfilter_bridge.h>
#include <linux/inetdevice.h>
#include <net/route.h>

#define IPPROTO_UT 219
#define VPNID_MASK  (0x03ff)
#define VPNID_BITS  (10)
#define L3UNIID_MASK    (0x03ff)

char DevPort[IFNAMSIZ]={};
int g_dbg_print_add_vlan=1;

extern struct neigh_table arp_tbl;
extern int  ut_vpncfg_init(void);
extern void ut_vpncfg_exit(void);
extern void get_ovs_tag(u32, u16 *, u16 *);
extern int ut_vpncfg_get_qinq(u16, u16, u32);
extern int ut_vpncfg_get_vpninfo(u16, u16, u16 *, u16 *, u32 *, u16 *);

struct ut_vlan {
    __be16 vlan_tci;    /* 802.1Q TCI (VLAN ID and priority). */
    __be16 vlan_tpid;   /* 802.1Q TPID. */
};
struct ut_qinq_vlan{
    unsigned char h_dest[ETH_ALEN];
    unsigned char h_source[ETH_ALEN];
    __be16 ut_spvlan_proto;
    __be16 ut_spvlan_tci;
    __be16 ut_cevlan_proto;
    __be16 ut_cevlan_tci;
    __be16 h_vlan_encapsulated_proto;
};

/*
struct utpkthdr
{
    unsigned char flag[4];
    unsigned int  vpninfo;
};
*/
unsigned char dstmac[6]={0x00,0x00,0x00,0x00,0xdd,0xdd};

void print_linear_data(struct sk_buff *skb)
{
    int linear_len = skb->len - skb->data_len;
    int i = 0;
    if (skb != NULL)
    {
        for (i = 0; i < linear_len; i++)
        {
            if (i != 0 && i % 4 == 0)
            {
                if(i%16 == 0)
                {
                    printk("\n");
                }
                else
                {
                   printk("  ");
                }
            }
            printk("%02x ", skb->data[i]);
        }
        printk("\n");
    }
}
  
/* 
 Hook function to be called. 
 there are six hooks defined in linux bridging code,this function was attached to NF_BR_PRE_ROUTING
 We modify the packets from linux bridge port.  
*/
static unsigned int add_utpkt_hdr(const struct nf_hook_ops *ops,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{

    struct iphdr *iph = ip_hdr(skb);
    struct ethhdr *eth = eth_hdr(skb);
    struct sk_buff *nskb = NULL;
    struct vlan_ethhdr vethhdr;
    struct ut_qinq_vlan utqinqhdr;
    struct iphdr niph;
    struct ethhdr neth;
    struct rtable *rt = NULL;
    struct neighbour *n = NULL;
    int ret = 0;
    __be32 paddr;
    u32 ovstag,peip,vpninfo;
    u16 l3uniid,spvlan,cevlan,tpid,vlanaction;

    if(!skb || !iph || !eth|| !strlen(DevPort))
    {
       return NF_ACCEPT;
    }

    if(0!=strcmp(skb->dev->name,"veth0"))
    {
       return NF_ACCEPT;
    }

    printk(KERN_INFO"controller to ne BEFORE MODIFY:\n");
    skb_push(skb,14);//将skb的data指针向前移动14个字节，使print_linear_data能打印出mac信息
    printk(KERN_INFO"devname=%s,len=%d,data_len=%d\n",skb->dev->name,skb->len,skb->data_len);
    printk(KERN_INFO"DMAC=%pM,SMAC=%pM,ETH_PROTO=0x%04X,vlan_proto=0x%04X,vlan_tci=0x%04X\n",
            eth->h_dest,eth->h_source,ntohs(eth->h_proto),ntohs(skb->vlan_proto),skb->vlan_tci);
    printk(KERN_INFO"SIP=%pI4,DIP=%pI4,IP_PROTOCOL=%d\n", &iph->saddr,&iph->daddr,iph->protocol);
    print_linear_data(skb);

    //ovstag = (skb->vlan_tci) & 0xfff;//从skb中获取ovstag
    ovstag = vlan_tx_tag_get_id(skb);//从skb中获取ovstag，利用if_vlan.h中提供宏定义表达式
    get_ovs_tag(ovstag,&spvlan,&cevlan);//利用spvlan和cevlan与ovstag之间关系，有ovstag的值获取spvlan和cevlan的值
    ut_vpncfg_get_vpninfo(spvlan,cevlan,&l3uniid,&tpid,&peip,&vlanaction);
    vpninfo = l3uniid;
    vpninfo = vpninfo << 10;
    printk(KERN_INFO"ovstag=%d,spvlan=%d,cevlan=%d,l3uniid=%d,tpid=0x%04x,peip=%pI4,vlanaction=%d,vpninfo=0x%08x\n",
            ovstag,spvlan,cevlan,l3uniid,tpid,&peip,vlanaction,vpninfo);
    vpninfo = cpu_to_be32(vpninfo); // change litter endian to big endian
    
    if(vlanaction == 0)
    {
        /*add vpninfo-header and ip-header and mac-header to frame*/
        nskb = dev_alloc_skb(skb->len + sizeof(struct iphdr)+sizeof(struct ethhdr)+ sizeof(u32));
        if(NULL == nskb)
        {
            printk("tmp nskb alloc failed!\n");
            return NF_ACCEPT;
        }
        
        //nskb=skb_copy(skb,GFP_ATOMIC);使用该函数后，再使用skb_push等操作容易内存写坏  
        skb_reserve(nskb,2);//保证4字节对齐
        skb_put(nskb,skb->len);//tail 指针向后移动skb的数据长度，方便复制skb的数据给nskb
        nskb->len = skb->len;
        nskb->protocol = htons(ETH_P_IP);
        memcpy((unsigned char *)nskb->data,skb->data,skb->len);//将原始报文复制给nskb->data区域        
        
        /*1.1-add utpkthdr*/
        skb_push(nskb,sizeof(u32));
        memcpy(nskb->data,&vpninfo,sizeof(u32));
        printk(KERN_INFO"1.1-add vpninfo to frame\n");
        print_linear_data(nskb);

        /*1.2-add ip-header*/
        skb_push(nskb,sizeof(struct iphdr));
        niph.version=4;
        niph.ihl=5;
        niph.tos=0;
        //printk(KERN_INFO"nskb->len=%d\n",nskb->len);
        niph.tot_len=htons(nskb->len);//tot_len既ip头20字节加上数据部分长度，sk_buff的len指的就是这个长度。
        niph.id=0;
        niph.frag_off=htons(0x4000);
        niph.ttl=64;
        niph.protocol=IPPROTO_UT;
        nskb->dev = dev_get_by_name(&init_net,DevPort);
        niph.saddr = nskb->dev->ip_ptr->ifa_list->ifa_address;//auto get controller ip address
        //niph.saddr = in_aton("2.2.2.2"); //controller ip address
        //niph.daddr = in_aton("2.2.2.1"); //ne ip address
        niph.daddr = peip; //auto get dst ne ip from ut_vpncfg_tx_node
        niph.check = 0;//must do before ip_fast_csum
        niph.check=ip_fast_csum(&niph,niph.ihl);
        memcpy((struct iphdr *)nskb->data,&niph,sizeof(struct iphdr));
        printk(KERN_INFO"1.2-add ip header to frame\n");
        print_linear_data(nskb); 
        
        /*1.3-add mac-header*/
        rt = ip_route_output(&init_net,niph.daddr,0,0,0);//查找目的ip的路由
        if(rt == NULL)
        {
            printk(KERN_INFO"rtable is NULL!\n");
        }
        else
        {
            printk(KERN_INFO"rtable is not NULL!\n");
            if(rt->rt_gateway)
            {
                printk(KERN_INFO"rt_gateway=%pI4\n",&rt->rt_gateway);
            }
        }
        paddr = rt_nexthop(rt,niph.daddr);//查找目的路由的下一跳
        printk(KERN_INFO"paddr=%pI4\n",&paddr);
        n = neigh_lookup(&arp_tbl, &paddr, nskb->dev);//查找目的路由下一跳的neighbour信息
        if(n == NULL)
        {
            printk(KERN_INFO"neighbour is NULL!\n");
        }
        else
        {
            printk(KERN_INFO"neighbour is not NULL!\n"); 
            memcpy(dstmac, n->ha, ETH_ALEN);//将neighbour中下一跳对应的mac地址拷贝给dstmac
            printk(KERN_INFO"dstmac = %pM\n",dstmac);
        }
        skb_push(nskb,sizeof(struct ethhdr));
        memcpy((unsigned char *)neth.h_dest,dstmac,ETH_ALEN);
        memcpy((unsigned char *)neth.h_source,nskb->dev->dev_addr,ETH_ALEN);//auto get controller mac address
        neth.h_proto=htons(ETH_P_IP);
        memcpy((struct ethhdr *)nskb->data,&neth,sizeof(struct ethhdr));

        /*reset mac header and ip header*/
        skb_reset_mac_header(nskb);
        skb_reset_network_header(nskb);
        printk(KERN_INFO"1.3-add mac header to frame\n");
        print_linear_data(nskb);

        ret=dev_queue_xmit(nskb);
        if(ret != 0)
        {
            printk("ret=%d\n", ret);
            return NF_ACCEPT;
        }
        printk(KERN_INFO"success add header to frame:\n");    
        print_linear_data(nskb); 
        return NF_DROP;
    }
    if(vlanaction == 4)
    {
        /*add vpninfo-header and ip-header and mac-header to frame*/
        nskb = dev_alloc_skb(skb->len + sizeof(struct iphdr)+sizeof(struct vlan_ethhdr)+ sizeof(u32));
        if(NULL == nskb)
        {
            printk("tmp nskb alloc failed!\n");
            return NF_ACCEPT;
        }

        skb_reserve(nskb,2);//保证4字节对齐
        skb_put(nskb,skb->len);//tail 指针向后移动skb的数据长度，方便复制skb的数据给nskb
        nskb->len = skb->len;
        nskb->protocol = htons(ETH_P_IP);
        memcpy((unsigned char *)nskb->data,skb->data,skb->len);//将原始报文复制给nskb->data区域 
        
        //在原始报文的mac头部加上vlan信息
        skb_reset_mac_header(nskb);
        skb_reset_network_header(nskb);  
        memcpy(vethhdr.h_dest,eth_hdr(nskb)->h_dest,ETH_ALEN);
        memcpy(vethhdr.h_source,eth_hdr(nskb)->h_source,ETH_ALEN);
        vethhdr.h_vlan_proto = htons(tpid);
        vethhdr.h_vlan_TCI = htons(spvlan);
        vethhdr.h_vlan_encapsulated_proto = htons(ETH_P_IP);

        skb_pull(nskb,sizeof(struct ethhdr));
        skb_push(nskb,sizeof(struct vlan_ethhdr));
        memcpy((struct vlan_ethhdr *)nskb->data,&vethhdr,sizeof(struct vlan_ethhdr));
        skb_reset_mac_header(nskb);
        skb_reset_network_header(nskb);         
        printk(KERN_INFO"1.1-add change raw frame mac header to mac-vlan header\n");
        print_linear_data(nskb);
        
        /*1.2-add utpkthdr*/
        skb_push(nskb,sizeof(u32));
        memcpy(nskb->data,&vpninfo,sizeof(u32));
        printk(KERN_INFO"1.2-add vpninfo to frame\n");
        print_linear_data(nskb);

        /*1.3-add ip-header*/
        skb_push(nskb,sizeof(struct iphdr));
        niph.version=4;
        niph.ihl=5;
        niph.tos=0;
        niph.tot_len=htons(nskb->len);//tot_len既ip头20字节加上数据部分长度，sk_buf的len指的就是这个长度。
        niph.id=0;
        niph.frag_off=htons(0x4000);
        niph.ttl=64;
        niph.protocol=IPPROTO_UT;
        nskb->dev = dev_get_by_name(&init_net,DevPort);
        niph.saddr = nskb->dev->ip_ptr->ifa_list->ifa_address;//auto get controller ip address
        niph.daddr = peip;   //auto get dst ne ip from ut_vpncfg_tx_node
        niph.check = 0;//must do before ip_fast_csum
        niph.check=ip_fast_csum(&niph,niph.ihl);
        memcpy((struct iphdr *)nskb->data,&niph,sizeof(struct iphdr));
        printk(KERN_INFO"1.3-add ip header to frame\n");
        print_linear_data(nskb); 
        
        /*1.4-add mac header*/
        rt = ip_route_output(&init_net,niph.daddr,0,0,0);//查找目的ip的路由
        if(rt == NULL)
        {
            printk(KERN_INFO"rtable is NULL!\n");
        }
        else
        {
            printk(KERN_INFO"rtable is not NULL!\n");
            if(rt->rt_gateway)
            {
                printk(KERN_INFO"rt_gateway=%pI4\n",&rt->rt_gateway);
            }
        }
        paddr = rt_nexthop(rt,niph.daddr);//查找目的路由的下一跳
        printk(KERN_INFO"paddr=%pI4\n",&paddr);
        n = neigh_lookup(&arp_tbl, &paddr, nskb->dev);//查找目的路由下一跳的neighbour信息
        if(n == NULL)
        {
            printk(KERN_INFO"neighbour is NULL!\n");
        }
        else
        {
            printk(KERN_INFO"neighbour is not NULL!\n"); 
            memcpy(dstmac, n->ha, ETH_ALEN);//将neighbour中下一跳对应的mac地址拷贝给dstmac
            printk(KERN_INFO"dstmac = %pM\n",dstmac);
        }
        
        skb_push(nskb,sizeof(struct ethhdr));
        memcpy((unsigned char *)neth.h_dest,dstmac,ETH_ALEN);
        memcpy((unsigned char *)neth.h_source,nskb->dev->dev_addr,ETH_ALEN);//auto get controller mac address
        neth.h_proto=htons(ETH_P_IP);
        memcpy((struct ethhdr *)nskb->data,&neth,sizeof(struct ethhdr));

        /*reset mac header and ip header*/
        skb_reset_mac_header(nskb);
        skb_reset_network_header(nskb);
        printk(KERN_INFO"1.4-add mac header to frame\n");
        print_linear_data(nskb);

        ret=dev_queue_xmit(nskb);
        if(ret != 0)
        {
            printk("ret=%d\n", ret);
            return NF_ACCEPT;
        }
        printk(KERN_INFO"success add header to frame:\n");    
        print_linear_data(nskb); 
        return NF_DROP;        
    }
    if(vlanaction == 5)
    {
        /*add vpninfo-header and ip-header and mac-header to frame*/
        nskb = dev_alloc_skb(skb->len + sizeof(struct iphdr)+sizeof(struct ut_qinq_vlan)+ sizeof(u32));
        if(NULL == nskb)
        {
            printk("tmp nskb alloc failed!\n");
            return NF_ACCEPT;
        }

        skb_reserve(nskb,2);//保证4字节对齐
        skb_put(nskb,skb->len);//tail 指针向后移动skb的数据长度，方便复制skb的数据给nskb
        nskb->len = skb->len;
        nskb->protocol = htons(ETH_P_IP);
        memcpy((unsigned char *)nskb->data,skb->data,skb->len);//将原始报文复制给nskb->data区域 
        
        //在原始报文的mac头部加上vlan信息
        skb_reset_mac_header(nskb);
        skb_reset_network_header(nskb);  
        memcpy(utqinqhdr.h_dest,eth_hdr(nskb)->h_dest,ETH_ALEN);
        memcpy(utqinqhdr.h_source,eth_hdr(nskb)->h_source,ETH_ALEN);
        utqinqhdr.ut_spvlan_proto = htons(tpid);
        utqinqhdr.ut_spvlan_tci = htons(spvlan);
        utqinqhdr.ut_cevlan_proto = htons(ETH_P_8021AD);
        utqinqhdr.ut_cevlan_tci = htons(cevlan);
        utqinqhdr.h_vlan_encapsulated_proto = htons(ETH_P_IP);

        skb_pull(nskb,sizeof(struct ethhdr));
        skb_push(nskb,sizeof(struct ut_qinq_vlan));
        memcpy((struct ut_qinq_vlan *)nskb->data,&utqinqhdr,sizeof(struct ut_qinq_vlan));
        skb_reset_mac_header(nskb);
        skb_reset_network_header(nskb);         
        printk(KERN_INFO"1.1-add change raw frame mac header to ut_qinq_vlan header\n");
        print_linear_data(nskb);
        
        /*1.2-add utpkthdr*/
        skb_push(nskb,sizeof(u32));
        memcpy(nskb->data,&vpninfo,sizeof(u32));
        printk(KERN_INFO"1.2-add vpninfo to frame\n");
        print_linear_data(nskb);

        /*1.3-add ip-header*/
        skb_push(nskb,sizeof(struct iphdr));
        niph.version=4;
        niph.ihl=5;
        niph.tos=0;
        niph.tot_len=htons(nskb->len);//tot_len既ip头20字节加上数据部分长度，sk_buf的len指的就是这个长度。
        niph.id=0;
        niph.frag_off=htons(0x4000);
        niph.ttl=64;
        niph.protocol=IPPROTO_UT;
        nskb->dev = dev_get_by_name(&init_net,DevPort);
        niph.saddr = nskb->dev->ip_ptr->ifa_list->ifa_address;//auto get controller ip address
        niph.daddr = peip;   //auto get dst ne ip from ut_vpncfg_tx_node
        niph.check = 0;//must do before ip_fast_csum
        niph.check=ip_fast_csum(&niph,niph.ihl);
        memcpy((struct iphdr *)nskb->data,&niph,sizeof(struct iphdr));
        printk(KERN_INFO"1.3-add ip header to frame\n");
        print_linear_data(nskb); 
        
        /*1.4-add mac header*/
        rt = ip_route_output(&init_net,niph.daddr,0,0,0);//查找目的ip的路由
        if(rt == NULL)
        {
            printk(KERN_INFO"rtable is NULL!\n");
        }
        else
        {
            printk(KERN_INFO"rtable is not NULL!\n");
            if(rt->rt_gateway)
            {
                printk(KERN_INFO"rt_gateway=%pI4\n",&rt->rt_gateway);
            }
        }
        paddr = rt_nexthop(rt,niph.daddr);//查找目的路由的下一跳
        printk(KERN_INFO"paddr=%pI4\n",&paddr);
        n = neigh_lookup(&arp_tbl, &paddr, nskb->dev);//查找目的路由下一跳的neighbour信息
        if(n == NULL)
        {
            printk(KERN_INFO"neighbour is NULL!\n");
        }
        else
        {
            printk(KERN_INFO"neighbour is not NULL!\n"); 
            memcpy(dstmac, n->ha, ETH_ALEN);//将neighbour中下一跳对应的mac地址拷贝给dstmac
            printk(KERN_INFO"dstmac = %pM\n",dstmac);
        }
        
        skb_push(nskb,sizeof(struct ethhdr));
        memcpy((unsigned char *)neth.h_dest,dstmac,ETH_ALEN);
        memcpy((unsigned char *)neth.h_source,nskb->dev->dev_addr,ETH_ALEN);//auto get controller mac address
        neth.h_proto=htons(ETH_P_IP);
        memcpy((struct ethhdr *)nskb->data,&neth,sizeof(struct ethhdr));
        

        /*reset mac header and ip header*/
        skb_reset_mac_header(nskb);
        skb_reset_network_header(nskb);
        printk(KERN_INFO"1.4-add mac header to frame\n");
        print_linear_data(nskb);

        ret=dev_queue_xmit(nskb);
        if(ret != 0)
        {
            printk("ret=%d\n", ret);
            return NF_ACCEPT;
        }
        printk(KERN_INFO"success add header to frame:\n");    
        print_linear_data(nskb);
        return NF_DROP;       
    }
    return NF_DROP;
}
  
/*this hooks was attached to NF_INET_PRE_ROUTING
  add vlan info to frame*/
unsigned int rm_utpkt_hdr(unsigned int hooknum,  
    struct sk_buff *skb,  
    const struct net_device *in,  
    const struct net_device *out,  
    int (*okfn)(struct sk_buff *))  
{  
    struct iphdr *iph = ip_hdr(skb);  
    struct ethhdr *eth = eth_hdr(skb);
    struct vlan_ethhdr vethhdr;
    struct sk_buff *nskb = NULL;
    struct ut_vlan *next_vlan = NULL;
    int ret = 0;
    u32 vpninfo;
    u16 vpnid,l3uniid;
    u32 peip,ovstag;

    if(!skb || !iph || !eth || !strlen(DevPort))
    {
       return NF_ACCEPT;
    }
    if(0!=strcmp(skb->dev->name,DevPort))
    {
        return NF_ACCEPT;
    }
    if(iph->protocol != IPPROTO_UT)
    {
        return NF_ACCEPT;
    }
    if(g_dbg_print_add_vlan)
    {
        printk(KERN_INFO"ne to controler BEFORE MODIFY:\n");
        printk(KERN_INFO"len=%d,data_len=%d\n",skb->len,skb->data_len);
        printk(KERN_INFO"DMAC=%pM,SMAC=%pM,ETH_PROTO=0x%04X\n",eth->h_dest,eth->h_source,ntohs(eth->h_proto));
        printk(KERN_INFO"SIP=%pI4,DIP=%pI4,IP_PROTOCOL=%d\n", &iph->saddr,&iph->daddr,iph->protocol);
        print_linear_data(skb);
    }
 
    //first,change protocol type to 0x8100 directly
    skb->protocol = htons(ETH_P_8021Q);
    /*get vpninfo from frame,in order to get ovstag value*/
    skb_pull(skb,sizeof(struct iphdr));
    memcpy(&vpninfo,skb->data,4);
    vpninfo = be32_to_cpu(vpninfo);//change big endian to littile endian
    printk(KERN_INFO"vpninfo=0x%08x\n",vpninfo);
    vpnid = vpninfo & VPNID_MASK;
    l3uniid = (vpninfo >> VPNID_BITS) & L3UNIID_MASK;
    peip = iph->saddr;
    printk(KERN_INFO"vpnid=%d,l3uniid=%d,peip=%pI4\n",vpnid,l3uniid,&peip);
    ovstag = ut_vpncfg_get_qinq(vpnid,l3uniid,peip);
    printk(KERN_INFO"ovstag = %d\n",ovstag);
    skb_pull(skb,4);//vpninfo头
    skb_reset_mac_header(skb);//修改sk_buff的data指针后，需要进行此操作。
    skb_reset_network_header(skb);
    printk(KERN_INFO"ne to controller common deal\n");
    print_linear_data(skb);
    
    if(eth_hdr(skb)->h_proto == htons(ETH_P_IP))
    {
        if(g_dbg_print_add_vlan)
        {
            printk(KERN_INFO"drop ip and vpninfo information-DMAC=%pM,SMAC=%pM,ETH_PROTO=0x%04X\n",
                    eth_hdr(skb)->h_dest,eth_hdr(skb)->h_source,ntohs(eth_hdr(skb)->h_proto));
            print_linear_data(skb);
        }

        memcpy(vethhdr.h_dest,eth_hdr(skb)->h_dest,ETH_ALEN);
        memcpy(vethhdr.h_source,eth_hdr(skb)->h_source,ETH_ALEN);
        vethhdr.h_vlan_proto = htons(ETH_P_8021Q);
        vethhdr.h_vlan_TCI = htons(ovstag);
        //vethhdr.h_vlan_TCI = htons(0x0002);
        vethhdr.h_vlan_encapsulated_proto = htons(ETH_P_IP);

        skb_pull(skb,14);//去掉二层头，方便nskb改为vlan+mac头
        /*add vlan tag to frame*/
        nskb = skb_copy(skb, GFP_ATOMIC);

        skb_push(nskb,18);//将nskb的data指针向前移动18个字节，存放vlan + mac 头
        skb_reset_mac_header(nskb);//修改sk_buff的data指针后，需要进行此操作。
        skb_reset_network_header(nskb);
        memcpy((struct vlan_ethhdr *)nskb->data,&vethhdr,18);
        
        #if 0
             nskb = skb_copy(skb, GFP_ATOMIC);
             nskb->vlan_proto = htons(ETH_P_8021Q);
             nskb->vlan_tci = htons(ovstag);
        #endif 

        //choice the interface of transmit
        nskb->dev = dev_get_by_name(&init_net,"veth0");//选择nskb的发送设备

        ret = dev_queue_xmit(nskb);//改造后的nskb结构体，通过该函数发出。
        if(ret != 0)
        {
            printk("ret=%d\n", ret);
            return NF_ACCEPT;
        }
        if(g_dbg_print_add_vlan)
        {
            printk(KERN_INFO"AFTER MODIFY:\n");
            print_linear_data(nskb);
        }
        return NF_DROP; 
    }

    else if(eth_hdr(skb)->h_proto == htons(ETH_P_8021Q) || eth_hdr(skb)->h_proto == htons(ETH_P_8021AD))
    {      
  
        //然后，再判断原始报文是否带双层vlan
        next_vlan = (struct ut_vlan *)(skb->data + sizeof(struct ethhdr)); 
        printk(KERN_INFO"next_vlan->vlan_tpid=0x%04X\n",ntohs(next_vlan->vlan_tpid));
        if(next_vlan->vlan_tpid == htons(ETH_P_8021Q) || next_vlan->vlan_tpid == htons(ETH_P_8021AD))
        {
            //原始报文带双层vlan
            skb_pull(skb,sizeof(struct vlan_ethhdr) + sizeof(struct ut_vlan));
            memcpy(vethhdr.h_dest,eth_hdr(skb)->h_dest,ETH_ALEN);
            memcpy(vethhdr.h_source,eth_hdr(skb)->h_source,ETH_ALEN);
            vethhdr.h_vlan_proto = htons(ETH_P_8021Q);
            vethhdr.h_vlan_TCI = htons(ovstag);
            vethhdr.h_vlan_encapsulated_proto = htons(ETH_P_IP);

            nskb = skb_copy(skb,GFP_ATOMIC);
            skb_push(nskb,sizeof(struct vlan_ethhdr) + sizeof(struct ut_vlan));
            memcpy((struct vlan_ethhdr *)nskb->data,&vethhdr,sizeof(struct vlan_ethhdr));

            //choice the interface of transmit
            nskb->dev = dev_get_by_name(&init_net,"veth0");//选择nskb的发送设备

            ret = dev_queue_xmit(nskb);//改造后的nskb结构体，通过该函数发出。
            if(ret != 0)
            {
                printk("ret=%d\n", ret);
                return NF_ACCEPT;
            }
            if(g_dbg_print_add_vlan)
            {
                printk(KERN_INFO"raw frame with QinQ vlan AFTER MODIFY:\n");
                print_linear_data(nskb);
            }
            return NF_DROP;
        }
        else
        {
            //原始报文带单层vlan 
            skb_pull(skb,sizeof(struct vlan_ethhdr));//去掉原始报文的单层vlan
            memcpy(vethhdr.h_dest,eth_hdr(skb)->h_dest,ETH_ALEN);
            memcpy(vethhdr.h_source,eth_hdr(skb)->h_source,ETH_ALEN);
            vethhdr.h_vlan_proto = htons(ETH_P_8021Q);
            vethhdr.h_vlan_TCI = htons(ovstag);
            vethhdr.h_vlan_encapsulated_proto = htons(ETH_P_IP);
                
            nskb = skb_copy(skb,GFP_ATOMIC);
            skb_push(nskb,sizeof(struct vlan_ethhdr));
            memcpy((struct vlan_ethhdr *)nskb->data,&vethhdr,sizeof(struct vlan_ethhdr));
                
            //choice the interface of transmit
            nskb->dev = dev_get_by_name(&init_net,"veth0");//选择nskb的发送设备

            ret = dev_queue_xmit(nskb);//改造后的nskb结构体，通过该函数发出。
            if(ret != 0)
            {
                printk("ret=%d\n", ret);
                return NF_ACCEPT;
            }
            if(g_dbg_print_add_vlan)
            {
                printk(KERN_INFO"raw frame with vlan tag AFTER MODIFY:\n");
                skb_push(nskb,sizeof(struct ethhdr));
                print_linear_data(nskb);
            }
                return NF_ACCEPT;
        }
        return NF_ACCEPT;
    }
    return NF_DROP;
}  
  
/* A netfilter instance to use */  
static struct nf_hook_ops nfho_rm_utpkt_hdr = {  
    .hook = rm_utpkt_hdr,  
    .pf = PF_INET,  
    .hooknum = NF_INET_PRE_ROUTING,  
    .priority = NF_IP_PRI_FIRST,  
    .owner = THIS_MODULE,  
};  
static struct nf_hook_ops nfho_add_utpkt_hdr = {
    .hook = add_utpkt_hdr, 
    .pf = NFPROTO_BRIDGE,
    .hooknum = NF_BR_PRE_ROUTING,
    .priority = NF_BR_PRI_FIRST,
    .owner = THIS_MODULE,
};
 
static int __init utpkt_init(void)  
{
    memcpy(DevPort,"eth2",4);  
    ut_vpncfg_init(); 
    printk(KERN_INFO"init utpkt.ko\n");    
    if (nf_register_hook(&nfho_rm_utpkt_hdr)) {  
        printk(KERN_ERR"nf_register_hook() failed\n");  
        return -1;  
    }
    if (nf_register_hook(&nfho_add_utpkt_hdr)) {
        printk(KERN_ERR"nf_register_hook() failed\n");
        return -1;
    }
    return 0;  
}  
  
static void __exit utpkt_exit(void)  
{
    ut_vpncfg_exit();  
    nf_unregister_hook(&nfho_rm_utpkt_hdr);
    nf_unregister_hook(&nfho_add_utpkt_hdr);
}  
  
module_init(utpkt_init);  
module_exit(utpkt_exit);  
MODULE_AUTHOR("ut_wyw");  
MODULE_LICENSE("GPL"); 


