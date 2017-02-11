# somelist2dnsmasq
convert gfwlist and a ad block list to dnsmasq's config file



1. `python list2dnsmasq.py`

2. ```
   /
   ├── myblocklist.txt      // block list, domains
   ├── mygfwlist.txt        // user's gfwlist, same rule as gfwlist
   ├── ignore.txt           // IP or domain will be removed from all list below
   │
   ├── forward_ip_list      // config file for openwrt-shadowsocks Forward List
   ├── gfwlist.conf         // dnsmasq config file, domains will be redirected you proxy
   ├── whitelist.conf       // dnsmasq config file, domains will be directed to their server
   └── blocklist.conf       // dnsmasq config file, DNS request will be redirected to 127.0.0.1:2 by default
   ```

   `gfwlist.conf`'s priority is higher than `whitelist.conf`'s

3. see also: https://github.com/shadowsocks/luci-app-shadowsocks/wiki/GfwList-Support

4. Thanks to: 

   1. https://github.com/cokebar/gfwlist2dnsmasq
   2. http://www.miui.com/thread-1877166-1-1.html