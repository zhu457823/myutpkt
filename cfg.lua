require "lib4lua"
--vpncfg_node:flag,ifname[30],nsid,peid,l3uniid,vpnid,outtag,innertag,vlanaction,tpid,peip,ovstag
--cfginfo.flag = lua_tonumber(L,1);
--    cfginfo.vpnid = lua_tonumber(L,2)-1; //vpnid网管配置是[1-1024],网元是[0-1023],传给igb时需要减1
--        cfginfo.outtag = lua_tonumber(L,3);
--            cfginfo.innertag = lua_tonumber(L,4);
--              cfginfo.l3uniid = ((int)lua_tonumber(L,5))&0x3ff;//l3uniid需要取低10个bit,范围为[0-1023]
--                                    cfginfo.ovstag = lua_tonumber(L,6);
--                                        cfginfo.vlanaction = lua_tonumber(L,7);
--                                            cfginfo.tpid = lua_tonumber(L,8);
--                                                cfginfo.nsid = lua_tonumber(L,9);
--                                                    cfginfo.peip = lua_tonumber(L,10);
--                                                        sprintf(cfginfo.ifname,"%s",lua_tostring(L,11));
lib4lua.pwinfo2driver(0,1,2,0,3,2,0,0x0800,2,0x01020202,587202563)



--AddPwDriverInfo(vpnid,spvlan,cevlan,action,pwinlabel,lspinlabel,pwoutlabel,lspoutlabel,l3uniid,tag,tpid)
--[[
function AddPwDriverInfo(vpnid,spvlan,cevlan,action,pwinlabel,lspinlabel,pwoutlabel,lspoutlabel,l3uniid,tag,tpid)
    syslog("LUA_LOG_INFO","AddPwDriverInfo",vpnid,spvlan,cevlan,action,pwinlabel,lspinlabel,pwoutlabel,lspoutlabel,l3uniid,tag,tpid)
    if vpnid ==nil or spvlan ==nil or cevlan ==nil or action ==nil or pwinlabel ==nil or lspinlabel ==nil or pwoutlabel ==nil or lspoutlabel ==nil or l3uniid ==nil or tag ==nil or tpid ==nil then
        return "AddPwDriverInfo Error: some parm is nil" 
    end
    syslog("LUA_LOG_INFO", lib4lua.pwinfo2driver(0,vpnid,spvlan,cevlan,pwinlabel,lspinlabel,pwoutlabel,lspoutlabel,l3uniid,tag,action,tpid))
end


memcpy(&vpnnode, nlmsg_data(nlh), sizeof(struct vpncfg_node));
	char buffer[1000] = {0};
	memset(buffer, 0, 1000);
	sprintf(buffer,"receive config: flag=%d,vpnid=%d,outtag=%d,innertag=%d,pwinlabel=%d,lspinlabel=%d,pwoutlabel=%d,lspoutlabel=%d,l3uniid=%d,ovstag=%d,vlanaction=%d,tpid=%d,nsid=%d,ifname=%s",
		vpnnode.flag,vpnnode.vpnid,vpnnode.outtag,vpnnode.innertag,vpnnode.pwinlabel,vpnnode.lspinlabel,vpnnode.pwoutlabel,vpnnode.lspoutlabel,vpnnode.l3uniid,vpnnode.ovstag,vpnnode.vlanaction,
        vpnnode.tpid,vpnnode.nsid,vpnnode.ifname);	
        
	memcpy(&vpnnode, nlmsg_data(nlh), sizeof(struct vpncfg_node));
	char buffer[1000] = {0};
	memset(buffer, 0, 1000);
	sprintf(buffer,"receive config: flag=%d,vpnid=%d,outtag=%d,innertag=%d,l3uniid=%d,ovstag=%d,vlanaction=%d,tpid=%d,peip=%pI4,nsid=%d,ifname=%s",
		vpnnode.flag,vpnnode.vpnid,vpnnode.outtag,vpnnode.innertag,vpnnode.l3uniid,vpnnode.ovstag,vpnnode.vlanaction,vpnnode.tpid,&vpnnode.peip,vpnnode.nsid,vpnnode.ifname);	
--]]        
