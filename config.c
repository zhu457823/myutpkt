#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>

#define VPNCFG_DEBUG
#ifdef VPNCFG_DEBUG
#ifdef __KERNEL__
/* This one if debugging is on, and kernel space */
#define PDEBUG(fmt, args...) printk("" fmt, ## args)
#else
/* This one for user space */
#define PDEBUG(fmt, args...) fprintf(stderr, fmt, ## args)
#endif
#else
#define PDEBUG(fmt, args...) /* not debugging: nothing */
#endif


#define NETLINK_USER 31
#define MAX_MSGSIZE (1000)

struct sock *nl_sk = NULL;
static struct file *vpncfg_file = NULL; 

static struct hlist_head *vpncfg_rx_table = NULL;
static struct hlist_head *vpncfg_tx_table = NULL;
#define VPNCFG_HASH_BUCKETS 1000

#define ADD_ERROR_MSG "add vpncfg error"
#define DEL_ERROR_MSG "del vpncfg error"
#define CHECK_ERROR_MSG "check vpncfg error, cfg exist"
#define CFG_INFO_ERROR_MSG "wrong configure msg"
#define CFG_INFO_OK_MSG	"configure is ok"
#define OPERATION_LENGTH (6)
#define DECIMALISM_VLAUE (10)
#define RECV_MSG_KEY_LENGTH (20)
#define RECV_MSG_VALUE_LENGTH (32+1)
#define SEND_BACK_MSG_LENGTH (50)
#define OVS_QINQTAG_CRITIAL_VALUE (4096)
#define OUTPUT_LENGTH (200)
#define VPNCFG_LOG_DIR "/var/log/igb.log"
#define VPNCFG_LOG_ATTR O_RDWR|O_CREAT|O_APPEND

static DEFINE_MUTEX(ut_vpncfg_mutex);

struct ut_vpncfg_rx_node
{
	struct rcu_head rcu;
	char ifname[30];
    u32 nsid;
	u16 vpnid;
	u16 l3uniid;
	u32 peip;
    u32 ovstag;
	struct hlist_node hash_node;
};

struct ut_vpncfg_tx_node
{
	struct rcu_head rcu;
	char ifname[30];
    u32 nsid;
	u16  spvlanid; //ovs svlan
	u16 l3uniid;
	u16 cevlanid; //ovs cvlan
	u16 vlanaction;
	u16 tpid;
    u32 peip;
	struct hlist_node hash_node;
};

struct vpncfg_node{
	u16 flag;
	char ifname[30];
	u32 nsid;
	u32 peid;
	u16 l3uniid;
	u16 vpnid;
	u16 outtag; 
	u16 innertag; 
	u16 vlanaction;
	u16 tpid;
    u32 peip;
	u32 ovstag;
};
/*
struct ut_l3uni_vlantag
{
	u16 vlanaction;
	u16 outtag;
	u16 innertag;
	u16 tpid;
};
*/
void ut_vpncfg_lock(void)
{
	mutex_lock(&ut_vpncfg_mutex);
}

void ut_vpncfg_unlock(void)
{
	mutex_unlock(&ut_vpncfg_mutex);
}

char* ut_vpncfg_get_msg_vlaue(char *recvdata, char *keydata, char *valdata)
{
	int i = 0;
	while (*recvdata != '=' && *recvdata != '\0'){
		keydata[i] = *recvdata;
		recvdata++;
		i++;
		if (i > 100)break;
	}
	keydata[i] = '\0';
	if(*recvdata == '=')
		recvdata++;
	i = 0;
	while (*recvdata != '\\' && *recvdata != '\0'){
		valdata[i] = *recvdata;
		i++;
		recvdata++;
		if (i > 100)break;
	}
	valdata[i] = '\0';
	if(*recvdata == '\\')
		recvdata++;
	return recvdata;
}

void get_ovs_tag(u32 ovstag, u16 *ovssvlan, u16 *ovscvlan)
{
	//ovstag value larger than 4096 then svlan & cvlan, otherwise only svlan
	if(ovstag > OVS_QINQTAG_CRITIAL_VALUE)
	{
		*ovssvlan = ovstag >> 12;
		*ovscvlan = ovstag & 0xfff;
	}
	else
	{
		*ovssvlan = ovstag;
		*ovscvlan = 0;
	}
}

static void ut_vpncfg_get_time_str(struct rtc_time *tm)
{
    struct timex  txc;

    /* 获取当前的UTC时间 */
    do_gettimeofday(&(txc.time));

    /* 把UTC时间调整为本地时间 */
    txc.time.tv_sec -= sys_tz.tz_minuteswest * 60;

    /* 算出时间中的年月日等数值到tm中 */
    rtc_time_to_tm(txc.time.tv_sec,tm);
}

//the log info is store in /tmp/vpncfg.txt; we should not delete it without create it again
//otherwise no log we can get
static void ut_vpncfg_print_log(char *string)
{
	struct rtc_time tm;
	char output[OUTPUT_LENGTH] = {0};
	mm_segment_t old_fs;
	loff_t *pos;
	ssize_t ret;
	if(vpncfg_file == NULL)
	{
		vpncfg_file = filp_open(VPNCFG_LOG_DIR, VPNCFG_LOG_ATTR, 0777); 
		if (unlikely(!vpncfg_file))
		{
			printk("vpncfg_file open failed..........\n");
			return;
		}
	}
	pos = &(vpncfg_file->f_pos);
	
	ut_vpncfg_get_time_str(&tm);

	sprintf(output, "%04d-%02d-%02d %02d:%02d:%02d------%s\n"
        ,tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour
        ,tm.tm_min, tm.tm_sec, string);

	old_fs = get_fs();
	set_fs(KERNEL_DS); //扩展内核空间到用户空间
	ret = vfs_write(vpncfg_file, output, strlen(output), pos);
	set_fs(old_fs);
	return;
}


static struct hlist_head *hash_rx_bucket(u16 vpnid, u16 l3uniid, u16 pwinlabel)
{
	unsigned int hash = jhash_3words((u32)vpnid, (u32)l3uniid, pwinlabel, 0);
	PDEBUG("hash_rx_bucket hash = %d\n", hash & (VPNCFG_HASH_BUCKETS - 1));
	return &vpncfg_rx_table[hash & (VPNCFG_HASH_BUCKETS - 1)];
}


static void ut_free_rx_node(struct rcu_head *rcu)
{
	struct ut_vpncfg_rx_node *rx_node = container_of(rcu, struct ut_vpncfg_rx_node, rcu);
	PDEBUG("ut_free_rx_node***************\n");
	kfree(rx_node);
}

static void ut_delete_all_rx_node(void)
{
	struct ut_vpncfg_rx_node *rx_node= NULL;
	struct hlist_head *bucket;
	int i = 0;

	for(i = 0; i < VPNCFG_HASH_BUCKETS; i++)
	{
		bucket = &vpncfg_rx_table[i];
		rcu_read_lock();
		hlist_for_each_entry_rcu(rx_node, bucket, hash_node)
		{
			hlist_del_rcu(&rx_node->hash_node);
			call_rcu(&rx_node->rcu, ut_free_rx_node);
		}
		rcu_read_unlock();
	}
}

static struct ut_vpncfg_rx_node * ut_vpncfg_create_rx_node(struct vpncfg_node* vpnnode)
{
	struct ut_vpncfg_rx_node *rx_node = NULL;
	size_t alloc_size = 0;

	alloc_size = sizeof(struct ut_vpncfg_rx_node);
	rx_node = kzalloc(alloc_size, GFP_KERNEL);
	if (!rx_node)
		return ERR_PTR(-ENOMEM);
	rx_node->l3uniid = vpnnode->l3uniid;
	rx_node->peip = vpnnode->peip;
	rx_node->vpnid = vpnnode->vpnid;
	if(vpnnode->ovstag > OVS_QINQTAG_CRITIAL_VALUE)
	{
		rx_node->ovstag = vpnnode->ovstag >> 12;
	}
	else
	{
		rx_node->ovstag = vpnnode->ovstag;
	}
	strcpy(rx_node->ifname,vpnnode->ifname);
	return rx_node;
}


static struct ut_vpncfg_rx_node * ut_vpncfg_add_rx_node(struct vpncfg_node* vpnnode)
{
	long err = 0;
	struct ut_vpncfg_rx_node *rx_node = NULL;
	u16 vpnid = vpnnode->vpnid;
	u16 l3uniid = vpnnode->l3uniid;
	u32 peip = vpnnode->peip;
	struct hlist_head *bucket;
	if(unlikely(!vpnnode))
	{
		err = EINVAL;
		goto out;
	}

	rx_node = ut_vpncfg_create_rx_node(vpnnode);
	if (IS_ERR(rx_node)) 
	{
		err = PTR_ERR(rx_node);
		goto out;
	}
	
	PDEBUG("ut_vpncfg_del_rx_node vpnid = %d, l3uniid = %d, peip = %pI4\n", vpnid, l3uniid, &peip);
	bucket = hash_rx_bucket(vpnid, l3uniid, peip);
	hlist_add_head_rcu(&rx_node->hash_node, bucket);
	return rx_node;
out:
	return ERR_PTR(err);
}

static int ut_vpncfg_del_rx_node(struct vpncfg_node* vpnnode)
{
	struct ut_vpncfg_rx_node *rx_node= NULL;
	u16 vpnid = vpnnode->vpnid;
	u16 l3uniid = vpnnode->l3uniid;
	u32 peip = vpnnode->peip;

	struct hlist_head *bucket;
	if(unlikely(!vpnnode))
		return EINVAL;
	
	bucket = hash_rx_bucket(vpnid, l3uniid, peip);
	rcu_read_lock();
	hlist_for_each_entry_rcu(rx_node, bucket, hash_node)
	{
		if(rx_node->l3uniid == l3uniid && rx_node->vpnid == vpnid && 
			rx_node->peip == peip)
		{
			PDEBUG("ut_vpncfg_del_rx_node vpnid = %d, l3uniid = %d, peip = %pI4\n", vpnid, l3uniid, &peip);
			hlist_del_rcu(&rx_node->hash_node);
			call_rcu(&rx_node->rcu, ut_free_rx_node);
			rcu_read_unlock();
			return 0;
		}
	}
	rcu_read_unlock();
	return EFAULT;	
}

static int ut_vpncfg_check_rx_exist(struct vpncfg_node* vpnnode)
{
	struct ut_vpncfg_rx_node *rx_node= NULL;
	u16 vpnid = vpnnode->vpnid;
	u16 l3uniid = vpnnode->l3uniid;
	u32 peip = vpnnode->peip;
	char output[OUTPUT_LENGTH] = {0};

	struct hlist_head *bucket;
	if(unlikely(!vpnnode))
		return EINVAL;
	
	bucket = hash_rx_bucket(vpnid, l3uniid, peip);
	rcu_read_lock();
	hlist_for_each_entry_rcu(rx_node, bucket, hash_node)
	{
		if(rx_node->l3uniid == l3uniid && rx_node->vpnid == vpnid && 
			rx_node->peip == peip)
		{
			sprintf(output, "ut_vpncfg_check_rx_exist vpnid = %d, l3uniid = %d, peip = %pI4", vpnid, l3uniid, &peip);
			PDEBUG("ut_vpncfg_check_rx_exist vpnid = %d, l3uniid = %d, peip = %pI4\n", vpnid, l3uniid, &peip);
			rcu_read_unlock();
			return 1;
		}
	}
	rcu_read_unlock();
	return 0;	
}

static struct hlist_head *hash_tx_bucket(u16 spvlan, u16 cevlan)
{
	unsigned int hash = jhash_2words((u32)spvlan, (u32)cevlan, 0);
	PDEBUG("hash_tx_bucket hash = %d\n", hash & (VPNCFG_HASH_BUCKETS - 1));
	return &vpncfg_tx_table[hash & (VPNCFG_HASH_BUCKETS - 1)];
}


static void ut_free_tx_node(struct rcu_head *rcu)
{
	struct ut_vpncfg_tx_node *tx_node = container_of(rcu, struct ut_vpncfg_tx_node, rcu);
	PDEBUG("ut_free_tx_node****************\n");
	kfree(tx_node);
}

static void ut_delete_all_tx_node(void)
{
	struct ut_vpncfg_tx_node *tx_node= NULL;
	struct hlist_head *bucket;
	int i = 0;

	for(i = 0; i < VPNCFG_HASH_BUCKETS; i++)
	{
		bucket = &vpncfg_tx_table[i];
		rcu_read_lock();
		hlist_for_each_entry_rcu(tx_node, bucket, hash_node)
		{
			hlist_del_rcu(&tx_node->hash_node);
			call_rcu(&tx_node->rcu, ut_free_tx_node);
		}
		rcu_read_unlock();
	}
}

static struct ut_vpncfg_tx_node * ut_vpncfg_create_tx_node(struct vpncfg_node* vpnnode, u16 ovsspvlan, u16 ovscevlan)
{
	struct ut_vpncfg_tx_node *tx_node = NULL;
	size_t alloc_size = 0;

	alloc_size = sizeof(struct ut_vpncfg_tx_node);
	tx_node = kzalloc(alloc_size, GFP_KERNEL);
	if (!tx_node)
		return ERR_PTR(-ENOMEM);
	tx_node->vlanaction = vpnnode->vlanaction;
	tx_node->l3uniid = vpnnode->l3uniid;
	tx_node->tpid = vpnnode->tpid;
	tx_node->cevlanid = ovscevlan;
	tx_node->spvlanid = ovsspvlan;
    tx_node->peip = vpnnode->peip;
	strcpy(tx_node->ifname,vpnnode->ifname);
	return tx_node;
}


static struct ut_vpncfg_tx_node * ut_vpncfg_add_tx_node(struct vpncfg_node* vpnnode)
{
	long err = 0;

	struct ut_vpncfg_tx_node *tx_node= NULL;
	u16 ovsspvlan = 0;
	u16 ovscevlan = 0;
	struct hlist_head *bucket;
	get_ovs_tag(vpnnode->ovstag, &ovsspvlan, &ovscevlan);

	if(unlikely(!vpnnode))
	{
		err = EINVAL;
		goto out;
	}

	tx_node = ut_vpncfg_create_tx_node(vpnnode, ovsspvlan, ovscevlan);
	if (IS_ERR(tx_node)) 
	{
		err = PTR_ERR(tx_node);
		goto out;
	}
	PDEBUG("ut_vpncfg_add_tx_node spvlan = %d, cevlan = %d\n", ovsspvlan, ovscevlan);
	
	bucket = hash_tx_bucket(ovsspvlan, ovscevlan);
	hlist_add_head_rcu(&tx_node->hash_node, bucket);
	return tx_node;
out:
	return ERR_PTR(err);
}

static int ut_vpncfg_del_tx_node(struct vpncfg_node* vpnnode)
{
	struct ut_vpncfg_tx_node *tx_node= NULL;
	u16 ovsspvlan = 0;
	u16 ovscevlan = 0;
	struct hlist_head *bucket;
	get_ovs_tag(vpnnode->ovstag, &ovsspvlan, &ovscevlan);
	
	if(unlikely(!vpnnode))
		return EINVAL;
	
	bucket = hash_tx_bucket(ovsspvlan, ovscevlan);
	rcu_read_lock();
	hlist_for_each_entry_rcu(tx_node, bucket, hash_node)
	{
		if(tx_node->spvlanid == ovsspvlan && tx_node->cevlanid == ovscevlan)
		{
			PDEBUG("ut_vpncfg_del_tx_node spvlan = %d, cevlan = %d\n", ovsspvlan, ovscevlan);
			hlist_del_rcu(&tx_node->hash_node);
			call_rcu(&tx_node->rcu, ut_free_tx_node);
			rcu_read_unlock();
			return 0;
		}
	}
	rcu_read_unlock();
	return EFAULT;	
}

static int ut_vpncfg_check_tx_exist(struct vpncfg_node* vpnnode)
{
	struct ut_vpncfg_tx_node *tx_node= NULL;
	u16 ovsspvlan = 0;
	u16 ovscevlan = 0;
	char output[OUTPUT_LENGTH] = {0};
	struct hlist_head *bucket;
	get_ovs_tag(vpnnode->ovstag, &ovsspvlan, &ovscevlan);

	if(unlikely(!vpnnode))
		return EINVAL;
	
	bucket = hash_tx_bucket(ovsspvlan, ovscevlan);
	rcu_read_lock();
	hlist_for_each_entry_rcu(tx_node, bucket, hash_node)
	{
		if(tx_node->spvlanid == ovsspvlan && tx_node->cevlanid == ovscevlan)
		{
			sprintf(output, "ut_vpncfg_check_tx_exist spvlan = %d, cevlan = %d", ovsspvlan, ovscevlan);
			PDEBUG("ut_vpncfg_check_tx_exist spvlan = %d, cevlan = %d\n", ovsspvlan, ovscevlan);
			ut_vpncfg_print_log(output);
			rcu_read_unlock();
			return 1;
		}
	}
	rcu_read_unlock();
	return 0;	
}


static void ut_vpncfg_recv_msg(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	//struct sk_buff *skb_out;
	char msg[SEND_BACK_MSG_LENGTH];
	memset(msg, 0, SEND_BACK_MSG_LENGTH);

	struct vpncfg_node vpnnode;
	memset(&vpnnode, 0, sizeof(struct vpncfg_node));

	struct ut_vpncfg_rx_node * rx_node = NULL;
	struct ut_vpncfg_tx_node * tx_node = NULL;

	PDEBUG(KERN_ALERT "Enetring:%s\n", __FUNCTION__);
	ut_vpncfg_lock();
	nlh = (struct nlmsghdr*)skb->data;
	memcpy(&vpnnode, nlmsg_data(nlh), sizeof(struct vpncfg_node));
	char buffer[1000] = {0};
	memset(buffer, 0, 1000);
	sprintf(buffer,"receive config: flag=%d,vpnid=%d,outtag=%d,innertag=%d,l3uniid=%d,ovstag=%d,vlanaction=%d,tpid=%d,peip=%pI4,nsid=%d,ifname=%s",
		vpnnode.flag,vpnnode.vpnid,vpnnode.outtag,vpnnode.innertag,vpnnode.l3uniid,vpnnode.ovstag,vpnnode.vlanaction,vpnnode.tpid,&vpnnode.peip,vpnnode.nsid,vpnnode.ifname);	
	ut_vpncfg_print_log(buffer);

	if(vpnnode.flag== 0) //add
	{
		if (ut_vpncfg_check_tx_exist(&vpnnode) == 1 || ut_vpncfg_check_rx_exist(&vpnnode) == 1)
		{
			sprintf(msg, "%s","add check errro!");
			goto error;
		}
		if (IS_ERR(rx_node = ut_vpncfg_add_rx_node(&vpnnode)))
		{
			sprintf(msg, "%s","add rx node errro!");
			goto error;
		}
		
		
		if (IS_ERR(tx_node = ut_vpncfg_add_tx_node(&vpnnode)))
		{
			sprintf(msg, "%s","add tx node errro!");
			goto error;
		}
	}
	else if (vpnnode.flag == 1) //del
	{
		if((ut_vpncfg_del_rx_node(&vpnnode)))
		{
			sprintf(msg, "%s","del rx node errro!");
			goto error;
		}
		if((ut_vpncfg_del_tx_node(&vpnnode)))
		{
			sprintf(msg, "%s","del tx node errro!");
			goto error;
		}
	}
	else
	{
		sprintf(msg, "%s",CFG_INFO_ERROR_MSG);
		goto error;
	}
	sprintf(msg, "%s",CFG_INFO_OK_MSG);
	goto send_back;
error:
    //todo :log
	
send_back:
	ut_vpncfg_unlock();
    ut_vpncfg_print_log(msg);
}

void send_packet_for_arp(int nsid,char *ifname,int iptype,char *dip,char *sip)
{
	struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int len = NLMSG_SPACE(MAX_MSGSIZE);
	char message[MAX_MSGSIZE] = {0};
	int slen = 0;

    if(!nl_sk){
        return;
    }

    // 为新的 sk_buffer申请空间
    skb = alloc_skb(len, GFP_KERNEL);
    if(!skb){
        printk(KERN_ERR "my_net_link: alloc_skb Error./n");
        return;
    }
	sprintf(message, "nsid=%d,ifname=%s,iptype=%d,dip=%s,sip=%s\n", nsid,ifname,iptype,dip,sip);
	slen = strlen(message)+1;

    //用nlmsg_put()来设置netlink消息头部
    nlh = nlmsg_put(skb, 0, 0, 0, MAX_MSGSIZE, 0);

    // 设置Netlink的控制块里的相关信息
    NETLINK_CB(skb).portid = 0; // 消息发送者的id标识，如果是内核发的则置0
    NETLINK_CB(skb).dst_group = 5; //多播组号为5

    message[slen] = '\0';
	memcpy(NLMSG_DATA(nlh), message, slen+1);

    //通过netlink_unicast()将消息发送用户空间由dstPID所指定了进程号的进程
    //netlink_unicast(nl_sk,skb,dstPID,0);
    netlink_broadcast(nl_sk, skb, 0,5, GFP_KERNEL); 
    printk("send OK!\n");
    return;
}


 int ut_vpncfg_init(void){
	struct netlink_kernel_cfg cfg = {
		.input = ut_vpncfg_recv_msg,
	};
	int err = 0;
	PDEBUG("enter my module!\n");
        printk(KERN_INFO"init configure!\n");
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
	//nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, 0, hello_nl_recv_msg, NULL, THIS_MODULE);
	if (unlikely(!nl_sk)){
		err = -EFAULT;
		goto out;
	}
	vpncfg_rx_table = kzalloc(VPNCFG_HASH_BUCKETS * sizeof(struct hlist_head),
			    GFP_KERNEL);
	if (unlikely(!vpncfg_rx_table))
	{
		err = -ENOMEM;
		goto free;
	}
	vpncfg_tx_table = kzalloc(VPNCFG_HASH_BUCKETS * sizeof(struct hlist_head),
			    GFP_KERNEL);
	if (unlikely(!vpncfg_tx_table))
	{
		err = -ENOMEM;
		goto free;
	}
	vpncfg_file = filp_open(VPNCFG_LOG_DIR, VPNCFG_LOG_ATTR, 0777); 
	if (unlikely(!vpncfg_file))
	{
		err = -ENOMEM;
		goto free;
	}

	return 0;
free:
	if(vpncfg_rx_table)
		kfree(vpncfg_rx_table);
	if(vpncfg_tx_table)
		kfree(vpncfg_tx_table);
	if(vpncfg_file)
		kfree(vpncfg_file);
	netlink_kernel_release(nl_sk);
out:
	return err;
}

 void ut_vpncfg_exit(void){
	PDEBUG("leave my module!\n");
	ut_delete_all_rx_node();
	ut_delete_all_tx_node();
	rcu_barrier();
	netlink_kernel_release(nl_sk);
	kfree(vpncfg_rx_table);
	kfree(vpncfg_tx_table);
	kfree(vpncfg_file);
}


int ut_vpncfg_get_qinq(u16 vpnid, u16 l3uniid, u32 peip)
{
	struct hlist_head *bucket;
	struct ut_vpncfg_rx_node *rx_node = NULL;
	u16 ovstag;

	bucket = hash_rx_bucket(vpnid, l3uniid, peip);
	rcu_read_lock();
	hlist_for_each_entry_rcu(rx_node, bucket, hash_node)
	{
		if(rx_node->l3uniid == l3uniid && rx_node->vpnid == vpnid && 
			rx_node->peip == peip)
		{
			ovstag = rx_node->ovstag;
			rcu_read_unlock();
			return ovstag;
		}
	}
	rcu_read_unlock();
	//if not find the node, set spvlan & cevlan 0
	return 0;
}

int ut_vpncfg_get_vpninfo(u16 spvlan, u16 cevlan, u16 * l3uniid, u16 * tpid, u32 * peip, u16 * vlanaction)
{
	struct hlist_head *bucket;
	struct ut_vpncfg_tx_node *tx_node = NULL;

	bucket = hash_tx_bucket(spvlan, cevlan);
	rcu_read_lock();
	hlist_for_each_entry_rcu(tx_node, bucket, hash_node)
	{
		if(tx_node->spvlanid== spvlan && tx_node->cevlanid== cevlan)
		{
			*l3uniid = tx_node->l3uniid;
			/*3univlan->vlanaction = tx_node->vlanaction;
			l3univlan->outtag = tx_node->outtag;
			l3univlan->innertag = tx_node->innertag;
			l3univlan->tpid = tx_node->tpid;*/
            *tpid = tx_node->tpid;
            *peip = tx_node->peip;
            *vlanaction = tx_node->vlanaction;
			rcu_read_unlock();
			return 1;
		}
	}
	rcu_read_unlock();
	return 0;
}

