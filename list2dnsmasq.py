#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author: themebe@me.com
# referer: https://github.com/cokebar/gfwlist2dnsmasq

import urllib.request
import base64
import re
import datetime

# gfwlist
gfwlist_dnsip = '127.0.0.1'
gfwlist_dnsport = '5353'
gfwlist_ipset = 'ss_spec_dst_fw'
# whitelist
whitelist_dnsip = '114.114.114.114'
whitelist_dnsport = '53'
whitelist_ipset = 'ss_spec_dst_bp'
# blocklist
blocklist_dnsip = gfwlist_dnsip
blocklist_dnsport = '2'

gfwlist_url = 'https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt'
mygfwlist_url = './mygfwlist.txt'
blocklist_url = 'https://raw.githubusercontent.com/h2y/Shadowrocket-ADBlock-Rules/master/sr_adb.conf'
myblocklist_url = './myblocklist.txt'
# after all, will remove IP or domain from all list which exists in ignore.txt
ignorelist_url = './ignore.txt'


# domains in gfwlist blacklist will be write into gfwlist_output,
# ip in gfwlist blacklist will be write into gfwip_output for openwrt-shadowsocks

# for openwrt-shadowsocks
gfwip_output = 'forward_ip_list'
# for dnsmasq-full
gfwlist_output = 'gfwlist.conf'
whitelist_output = 'whitelist.conf'
blocklist_output = 'blocklist.conf'


"""
file format:

gfwip_output
123.123.123.123
123.123.123.134

gfwlist_output
server=/domain.com/$gfwlist_dnsip#$gfwlist_dnsport
ipset=/domain.com/$gfwlist_ipset

whitelist_output
server=/domain.com/$whitelist_dnsip#$whitelist_dnsport
ipset=/domain.com/$whitelist_ipset

blocklist_output
server=/domain.com/$blocklist_dnsip#$blocklist_dnsport
"""

gfwip = set()
gfwlist = set()
whitelist = set()
blocklist = set()


def text_to_list(text):
    if type(text) is bytes:
        text = text.decode('utf-8')
    if '\r' in text:
        text = text.replace('\r', '\n').replace('\n\n', '\n')
    return text.split('\n')


def get_url(url):
    print('  reading from: {}'.format(url))
    content = ''
    if url[:4] == 'http':
        response = urllib.request.urlopen(url, timeout=30)
        content = response.read()
    else:
        try:
            with open(url, 'r') as f:
                content = f.read()
        except:
            pass
    return content


def update_google():
    global gfwlist
    _root = '''ac|ad|ae|al|am|as|at|az|ba|be|bf|bg|bi|bj|bs|bt|by|ca|cat|cd|cf|cg|
ch|ci|cl|cm|co.ao|co.bw|co.ck|co.cr|co.id|co.il|co.in|co.jp|co.ke|co.kr|co.ls|
co.ma|com|com.af|com.ag|com.ai|com.ar|com.au|com.bd|com.bh|com.bn|com.bo|com.br|
com.bz|com.co|com.cu|com.cy|com.do|com.ec|com.eg|com.et|com.fj|com.gh|com.gi|com.gt|
com.hk|com.jm|com.kh|com.kw|com.lb|com.ly|com.mm|com.mt|com.mx|com.my|com.na|com.nf|
com.ng|com.ni|com.np|com.om|com.pa|com.pe|com.pg|com.ph|com.pk|com.pr|com.py|com.qa|
com.sa|com.sb|com.sg|com.sl|com.sv|com.tj|com.tr|com.tw|com.ua|com.uy|com.vc|com.vn|
co.mz|co.nz|co.th|co.tz|co.ug|co.uk|co.uz|co.ve|co.vi|co.za|co.zm|co.zw|cv|cz|de|dj|
dk|dm|dz|ee|es|fi|fm|fr|ga|ge|gg|gl|gm|gp|gr|gy|hk|hn|hr|ht|hu|ie|im|iq|is|it|je|jo|
kg|ki|kz|la|li|lk|lt|lu|lv|md|me|mg|mk|ml|mn|ms|mu|mv|mw|mx|ne|nl|no|nr|nu|org|pl|pn|
ps|pt|ro|rs|ru|rw|sc|se|sh|si|sk|sm|sn|so|sr|st|td|tg|tk|tl|tm|tn|to|tt|us|vg|vn|
vu|ws'''
    for e in _root.replace('\n', '').split('|'):
        gfwlist.add('google.{}'.format(e))


def update_gfwlist():
    global gfwip, gfwlist, whitelist, gfwlist_url, mygfwlist_url
    re_ipv4 = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d+)*)')
    re_domain = re.compile(r'([\w\-\_]+\.[\w\-\_\.]+)')

    def get_ip(text):
        r = re_ipv4.search(text)
        if r:
            return r.group(1)
        else:
            return ''

    def get_match(text):
        r = re_domain.search(text)
        if r:
            return r.group(1)
        else:
            return ''

    def function_name(lines):
        for line in lines:
            if len(line)==0 or line[0] in '!/[':
                pass
            else:
                if line[:2] == '@@':
                    # direct -> white list
                    m = get_match(line)
                    if m:
                        i = get_ip(line)
                        if len(i) == 0:
                            whitelist.add(m)
                            if m in gfwlist:
                                gfwlist.remove(m)
                        else:
                            # drop this ip
                            pass
                else:
                    # proxy -> black list
                    m = get_match(line)
                    if m:
                        i = get_ip(line)
                        if len(i) == 0:
                            gfwlist.add(m)
                        else:
                            gfwip.add(i)

    text = base64.b64decode(get_url(gfwlist_url))
    function_name(text_to_list(text))
    text = get_url(mygfwlist_url)
    function_name(text_to_list(text))

    # remove elements from gfwlist which exist in whitelist
    # mygfwlist > gfwlist
    for e in whitelist:
        if e in gfwlist:
            gfwlist.remove(e)


def update_blocklist():
    global blocklist, blocklist_url, gfwlist, whitelist, mygfwlist_url
    lines = text_to_list(get_url(blocklist_url))
    for line in lines:
        if len(line) == 0 or line[0] in '#![bsd':
            pass
        else:
            keys = line.split(',')
            if len(keys) > 2:
                if keys[2].upper() == 'REJECT':
                    if keys[0].upper() in ['DOMAIN-SUFFIX', 'DOMAIN']:
                        blocklist.add(keys[1])
                    elif keys[0].upper() == 'DOMAIN-KEYWORD':
                        blocklist.add('{}.cn'.format(keys[1]))
                        blocklist.add('{}.com'.format(keys[1]))
                        blocklist.add('{}.com.cn'.format(keys[1]))

    lines = text_to_list(get_url(myblocklist_url))
    for line in lines:
        if len(line) == 0 or line[0] in '#![':
            pass
        else:
            blocklist.add(line)


def update_ignore():
    global ignorelist_url, gfwlist, whitelist, blocklist
    lines = text_to_list(get_url(ignorelist_url))
    for line in lines:
        if len(line) == 0 or line[0] in '#![':
            pass
        else:
            if line in gfwlist:
                gfwlist.remove(line)
            if line in whitelist:
                whitelist.remove(line)
            if line in blocklist:
                blocklist.remove(line)


print('gfwlist and adblock to dnsmasq config file')
print(' updating google.* ...')
update_google()
print(' updating gfwlist ...')
update_gfwlist()
print(' updating adblock list ...')
update_blocklist()
print(' removing ignored IPs or domains ...')
update_ignore()

def save_gfwip(e):
    return '{}\n'.format(e)

def save_gfwlist(e):
    return 'server=/{0}/{1}#{2}\nipset=/{0}/{3}\n'.format(
        e, gfwlist_dnsip, gfwlist_dnsport, gfwlist_ipset)

def save_whitelist(e):
    return 'server=/{0}/{1}#{2}\nipset=/{0}/{3}\n'.format(
        e, whitelist_dnsip, whitelist_dnsport, whitelist_ipset)

def save_blocklist(e):
    return 'server=/{0}/{1}#{2}\n'.format(
        e, blocklist_dnsip, blocklist_dnsport)


#save to file
for url, lst, fname, convert in ((None, gfwip, gfwip_output, save_gfwip), 
                   (gfwlist_url, gfwlist, gfwlist_output, save_gfwlist),
                   (mygfwlist_url, whitelist, whitelist_output, save_whitelist),
                   (blocklist_url, blocklist, blocklist_output, save_blocklist)):
    print(' writing {} ...'.format(fname))
    with open(fname, 'w', newline='\n') as f:
        if url:
            f.write('# update from: {}\n# filename: {}\n# update at: {}\n\n'.format(
                url,
                fname,
                datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S")
                ))
        for e in lst:
            if len(e):
                f.write(convert(e))

print('DONE!')
