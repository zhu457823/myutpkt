# myutpkt
 myutpkt模块的入方向处理函数rm_utpkt_hdr（）函数会针对这3种形式的报文分别做如下处理：
 1、原始报文不带vlan信息：首先由网元发给Controller的报文可以得到vpnid、l3uniid、peip信息，调用ut_vpncfg_get_qinq（vpnid,l3uniid,peip）函数，得到ovstag的值，然后，剥掉网元给原始报文封装的mac头+IP头+Vpninfo信息，在原始报文的mac头添加vlan信息，vlan tpid = 0x8100，vlan tci = ovstag。最后将改造的报文通过veth0发送给vrf。
 2、原始报文带vlan信息：首先由网元发给Controller的报文可以得到vpnid、l3uniid、peip信息，调用ut_vpncfg_get_qinq（vpnid,l3uniid,peip）函数，得到ovstag的值，然后，剥掉网元给原始报文封装的mac头+IP头+Vpninfo信息，改造原始报文的mac-vlan头信息，vlan tpid = 0x8100，vlan tci = ovstag。最后将改造的报文通过veth0发送给vrf。
 3、原始报文带QinQ信息：首先由网元发给Controller的报文可以得到vpnid、l3uniid、peip信息，调用ut_vpncfg_get_qinq（vpnid,l3uniid,peip）函数，得到ovstag的值，然后，剥掉网元给原始报文封装的mac头+IP头+Vpninfo信息，改造原始报文的ut_qinq_hdr头信息，vlan tpid = 0x8100，vlan tci = ovstag。最后将改造的报文通过veth0发送给vrf。

  myutpkt模块的出方向处理函数add_utpkt_hdr（）会调用ut_vpncfg_get_vpninfo（spvlan,cevlan）函数获取tpid和vlanaction的值，针对vlanaction的值做3种处理：
  1、vlanaction = 0 的情况：剥掉原始报文Mac+0x8100+ovstag头的vlan信息，打上vpninfo、IP头和Mac头信息，最后通过eth2发送给网元。
  2、vlanaction = 4 的情况：将原始报文头Mac+0x8100+ovstag改造成Mac+tpid+spvlan头，打上vpninfo、IP头和Mac头信息，最后通过eth2发送给网元。
  3、vlanaction = 5 的情况：将原始报文头Mac+0x8100+ovstag改造成Mac+0x8100+spvlan+0x88a8+cevlan头，打上vpninfo、IP头和Mac头信息，最后通过eth2发送给网元。
