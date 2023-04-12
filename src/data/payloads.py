import binascii
"""
黑名单payload字典记录，用于提供黑名单payload相关的端口信息、协议信息、payload数据以及sid等信息
"""


def bytes_to_hex(buf):
    """
    输入bytes,输出Hex
    """

    if isinstance(buf, bytes):
        buf = bytes.hex(buf)

    return buf


def hex_to_bytes(buf):
    """
    输入Hex,输出bytes
    """
    if isinstance(buf, str):
        buf = binascii.unhexlify(buf)
    return buf


EXAMPLE_HEADER = {
    'http': {
        'request': b'',
        'response': b'GET / HTTP/1.1\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)\r\nHost: www.example.com\r\nConnection: Keep-Alive\r\nAccept-Encoding: gzip\r\nAccept-Language: en-us,en;q=0.5\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 200\r\n\r\n'
    }
}

# payload字典列表
playload_list = [
    {
        "name": "CODESYS 网关服务器无效的内存访问尝试",
        "pro": "TCP",
        "sort": "黑名单",
        "sport": 14200,
        "dport": 1210,
        "data": [
            {
                'payload': b"\xdd\xdd" + b"\x41" * 18 + b"\x00\x00" + b"\xdd\xdd" + b"\x41" * 16 + b"\x0E\x00\x00\x00",
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
        "sid": 100000
    },
    {
        "name": "CODESYS 网关服务器目录遍历尝试",
        "pro": "TCP",
        "data": [
            {
                'payload': b"\xdd\xdd" + b"\x41" * 20 + b"\x2e\x2e\x41\x2e\x2e",
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
        "sort": "黑名单",
        "sport": 14200,
        "dport": 1210,
        "sid": 100001
    },
    {
        "name": "CODESYS 网关服务器栈缓冲区溢出尝试",
        "pro": "TCP",
        "data": [
            {
                'payload': b"\xdd\xdd" + b"\x41" * 16 + b"\x06\x00\x00\x00" + b"\x41" * 232,
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
        "sort": "黑名单",
        "sport": 14200,
        "dport": 1210,
        "sid": 100002
    },
    {
        "name": "CODESYS 网关服务器堆缓冲区溢出尝试",
        "pro": "TCP",
        "data": [
            {
                'payload': b"\xdd\xdd" + b"\x41" * 16 + b"\x06\x00\x00\x00" + b"\x41" * 260 + b"\xff\xff\xff\x8f",
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
        "sort": "黑名单",
        "sport": 14200,
        "dport": 1210,
        "sid": 100003
    },
    {
        "name": "IGSS SCADA dc.exe 服务器目录遍历和任意的文件执行",
        "pro": "TCP",
        "data": [
            {
                'payload': b"\x41" * 12 + b"\x0a" + b"\x2E\x2E\x5C\x2E\x2E\x5C\x2E\x2E\x5C\x2E\x2E\x5C\x2E\x2E\x5C",
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
        "sort": "黑名单",
        "sport": 14200,
        "dport": 12397,
        "sid": 100005
    },
    {
        "name": "IGSS SCADA 任意的文件读和覆盖尝试",
        "pro": "TCP",
        "data": [
            {
                'payload': b"\x41" * 2 + b"\x01\x00" + b"\x41" * 2 + b"\x0d\x00\x00\x00" + b"\x41" * 8 + b"\x03\x00\x00\x00" + b"\x2e\x2e",
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
        "sort": "黑名单",
        "sport": 14200,
        "dport": 12401,
        "sid": 100006
    },
    {
        "name": "DAQFactory NETB 协议栈溢出尝试",
        "pro": "UDP",
        "data": [
            {
                'payload': b"NETB" + b"\x41" * 230 + b"\x00" * 6 + b"\x41" * 131,
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
        "sort": "黑名单",
        "sport": 14200,
        "dport": 20034,
        "sid": 100007
    },
    {
        "name": "DATAC Control RealWin SCADA System 缓冲区溢出",
        "pro": "TCP",
        "data": [
            {
                'payload': b"\x10\x23\x54\x67" + b"\xbd\x02\x00\x00" + b"\x41" * 2 + b"\x0a\x00\x05\x00" + b"\x41" * 715,
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
        "sort": "黑名单",
        "sport": 14200,
        "dport": 910,
        "sid": 100008
    },
    {
        "name": "Kingview HMI 堆溢出尝试",
        "pro": "TCP",
        "data": [
            {
                'payload':  b"\x90" * 8 + b"\x41" * 1440,
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
        "sort": "黑名单",
        "sport": 14200,
        "dport": 777,
        "sid": 100009
    },
    {
        "name": "罗克韦尔自动化ControlLogix EtherNET/IPreset 命令行拒绝服务",
        "pro": "TCP",
        "data": [
            {
                'payload':  b"\x6f\x00\x00\x00\x00\x00\x00\x04\x02\x00\x00\x00\x00\x00\xb2\x00\x08\x00\x05\x03\x20\x01\x24\x01\x30\x03",
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
        "sort": "黑名单",
        "sport": 14200,
        "dport": 44818,
        "sid": 100136
    },
    {
        "name": "罗克韦尔自动化ControlLogix EtherNET/IPmodules boot code dump攻击尝试",
        "pro": "TCP",
        "data": [
            {
                'payload': b"\x6f\x00\x00\x00\x00\x00\x00\x04\x02\x00\x00\x00\x00\x00\xb2\x00\x08\x00\x97\x02\x20\xc0\x24\x00\x00\x00",
                'direction': 0
            }
        ],
        "sort": "黑名单",
        "sport": 14200,
        "dport": 44818,
        "sid": 100135
    },
    {
        "name": "西门子SIMATIC WinCC flexible runtime 栈缓冲区溢出尝试",
        "pro": "TCP",
        "data": [
            {
                'payload': b"\x00\x01\x03" + b"\x00" * 23 + b"\xff\xff\xff\xff" + b"\x00" * 1024,
                'direction': 0
            }
        ],
        "sort": "黑名单",
        "sport": 14200,
        "dport": 2308,
        "sid": 100028
    },
    {   
        "name": "检测到ADWARE_PUP活动:W32.Daqa.C下载",
        "sid": 2001447,
        "sort": "黑名单",
        "pro": "TCP",
        "dport": 80,
        "sport": 14200,
        "dip": "49.234.13.200",
        "sip": "192.168.0.88",
        "data": [
            {
                'payload': b'GET / HTTP/1.1\r',
                'direction': 0
            },
            {
                'payload': b'\x67\x6f\x69\x64\x72\x2e\x63\x61\x62' + b'\x48\x6f\x73\x74x\3a\x20\x77\x77\x77\x2e\x77\x65\x62\x6e\x65\x74\x69\x6e\x66\x6f\x2e\x6e\x65\x74',
                'direction': 1    # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "检测到拒绝服务攻击:Catalyst内存泄露攻击",
        "sid": 2000011,
        "sort": "dos_blacklist",
        "pro": "TCP",
        "dport": 23,
        "sport": 14200,
        "sip": "49.234.13.200",
        "dip": "192.168.0.88",
        "data": [
            {
                'payload': b'\x41\x41\x41\x0a',
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "攻击响应:Cisco TclShell TFTP读取请求",
        "sid": 2009244,
        "sort": "attack_response_blacklist",
        "pro": "UDP",
        "dport": 69,
        "sport": 14200,
        "dip": "49.234.13.200",
        "sip": "192.168.0.88",
        "data": [
            {
                'payload': b'\x00\x01\x74\x63\x6C\x73\x68\x2E\x74\x63\x6C',
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "检测到聊天工具:ICQ",
        "sid": 2001804,
        "sort": "chat_blacklist",
        "pro": "TCP",
        "dport": 5190,
        "sport": 14200,
        "rule": "alert tcp $HOME_NET any -> $EXTERNAL_NET 5190 (msg:\"检测到聊天工具:ICQ\"; flow: from_client,established; content:\"|2A01|\"; depth: 2; content:\"|00010001|\"; offset: 8; depth: 4; reference:url,doc.emergingthreats.net/2001804; classtype:policy-violation; sid:2001804; rev:5; metadata:created_at 2010_07_30, updated_at 2010_07_30;)",
        "dip": "49.234.13.200",
        "sip": "192.168.0.88",
        "data": [
            {
                'payload': b'\x2A\x01' + b'\x00' * 6 + b'\x00\x01\x00\x01',
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "在url中检测到了命令执行(/bin/sh)",
        "sid": 2011465,
        "sort": "code_execution_blacklist",
        "pro": "TCP",
        "rule": "alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:\"在url中检测到了命令执行(/bin/sh)\"; flow:established,to_server; http.uri; content:\"/bin/sh\"; nocase; classtype:web-application-attack; sid:2011465; rev:8; metadata:created_at 2010_10_13, updated_at 2020_04_21;)",
        "dport": 80,
        "sport": 14200,
        "sip": "49.234.13.200",
        "dip": "192.168.0.88",
        "data": [
            {
                'payload': b'GET /vulnerable.php?cmd=/bin/sh HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nConnection: close\r\nReferer: http://www.example.com/index.html\r\n',
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "发现目录扫描行为(1)",
        "sid": 1,
        "sort": "directory_scan_blacklist",
        "rule": "alert http any any -> $HOME_NET any (msg:\"发现目录扫描行为(1)\"; flow:established,to_server; http.uri; content:\"/index\"; nocase; url_decode; flowbits:set, dir_search; flowint:dir_search_count, + , 1; sid:1;)",
        "pro": "TCP",
        "dport": 80,
        "sport": 14200,
        "sip": "49.234.13.200",
        "dip": "192.168.0.88",
        "data": [
            {
                'payload': b'GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nConnection: close\r\nReferer: http://www.example.com/index.html\r\n',
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "检测到dns查询了可疑域名(bridges.torproject.org)",
        "sid": 2017925,
        "sort": "dns_domain_blacklist",
        "rule": "alert dns $HOME_NET any -> any any (msg:\"检测到dns查询了可疑域名(bridges.torproject.org)\"; dns.query; content:\"bridges.torproject.org\"; depth:22; nocase; reference:url,www.torproject.org/docs/bridges.html.en; reference:md5,2e3f7f9b3b4c29aceccab693aeccfa5a; classtype:external-ip-check; sid:2017925; rev:6; metadata:created_at 2014_01_04, former_category POLICY, tag IP_address_lookup_website, updated_at 2020_09_01;)",
        "pro": "UDP",
        "dport": 53,
        "sport": 14200,
        "dip": "49.234.13.200",
        "sip": "192.168.0.88",
        "data": [
            {
                'payload': b'\x10\x32\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x16' + b'bridges.torproject.org' + b'\x00' + b'\x00\x10\x00\x01',
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "检测到访问了可疑域名(*.darktech.org)",
        "sid": 2014489,
        "sort": "domain_blacklist",
        "rule": "alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"检测到访问了可疑域名(*.darktech.org)\"; flow:established,to_server; http.host; content:\".darktech.org\"; endswith; classtype:bad-unknown; sid:2014489; rev:4; metadata:created_at 2012_04_05, updated_at 2020_04_21;)",
        "pro": "TCP",
        "dport": 80,
        "sport": 14100,
        "dip": "49.234.13.200",
        "sip": "192.168.0.88",
        "data": [
            {
                'payload': b'GET /user HTTP/1.1\r\nHost: www.example.darktech.org\r\n\r\n',
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "检测到拒绝服务攻击:疑似SolarWinds TFTP Server dos尝试",
        "sid": 2011673,
        "sort": "dos_blacklist",
        "rule": "alert udp $EXTERNAL_NET any -> $HOME_NET 69 (msg:\"检测到拒绝服务攻击:疑似SolarWinds TFTP Server dos尝试\"; content:\"|00 01 01|\"; depth:3; content:\"NETASCII\"; reference:url,www.exploit-db.com/exploits/12683/; reference:url,doc.emergingthreats.net/2011673; classtype:attempted-dos; sid:2011673; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)",
        "pro": "UDP",
        "dport": 69,
        "sport": 14100,
        "sip": "49.234.13.200",
        "dip": "192.168.0.88",
        "data": [
            {
                'payload': b'\x00\x01\x01' + b'NETASCII',
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "检测到dns请求了DynDNS域名(*.bounceme.net)",
        "sid": 2028678,
        "sort": "dyn_domain_blacklist",
        "rule": "alert dns $HOME_NET any -> any any (msg:\"检测到dns请求了DynDNS域名(*.bounceme.net)\"; dns.query; content:\".bounceme.net\"; nocase; endswith; reference:url,www.noip.com/support/faq/free-dynamic-dns-domains; classtype:bad-unknown; sid:2028678; rev:1; metadata:affected_product Any, attack_target Client_Endpoint, created_at 2019_10_14, deployment Perimeter, former_category POLICY, performance_impact Low, signature_severity Informational, updated_at 2019_10_14;)",
        "pro": "UDP",
        "dport": 53,
        "sport": 14200,
        "dip": "49.234.13.200",
        "sip": "192.168.0.88",
        "data": [
            {
                'payload': b'\x10\x32\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x14' + b'example.bounceme.net' + b'\x00' + b'\x00\x10\x00\x01',
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "检测到Visagesoft eXPert PDF查看器ActiveX Control任意文件覆盖",
        "sid": 2008791,
        "sort": "et_actives_blacklist",
        "rule": "alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:\"检测到Visagesoft eXPert PDF查看器ActiveX Control任意文件覆盖\"; flow:to_client,established; content:\"CLSID\"; nocase; content:\"BDF3E9D2-5F7A-4F4A-A914-7498C862EA6A\"; nocase; distance:0; content:\"savePageAsBitmap\"; nocase; reference:bugtraq,31984; reference:url,milw0rm.com/exploits/6875; reference:url,doc.emergingthreats.net/2008791; classtype:web-application-attack; sid:2008791; rev:3; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2010_07_30, deployment Perimeter, signature_severity Major, tag ActiveX, updated_at 2016_07_01;)",
        "pro": "TCP",
        "sport": 14200,
        "dport": 80,
        "dip": "49.234.13.200",
        "sip": "192.168.0.88",
        "data": [
            {
                'payload': EXAMPLE_HEADER["http"]["response"] + b'CLSID=BDF3E9D2-5F7A-4F4A-A914-7498C862EA6A&savePageAsBitmap=C:\test.txt',
                'direction': 1   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "检测到exploit_kit活动:Java/PDF初始化登录",
        "sid": 2013025,
        "sort": "exploit_kit_blacklist",
        "rule": "alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"检测到exploit_kit活动:Java/PDF初始化登录\"; flow:established,to_server; content:\"/Home/games/2fdp.php?f=\"; http_uri; classtype:exploit-kit; sid:2013025; rev:2; metadata:created_at 2011_06_13, former_category EXPLOIT_KIT, updated_at 2011_06_13;)",
        "pro": "TCP",
        "sport": 14200,
        "dport": 80,
        "dip": "49.234.13.200",
        "sip": "192.168.0.88",
        "data": [
            {
                'payload': b'GET /Home/games/2fdp.php?f=1 HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nConnection: Keep-Alive\r\n\r\n',
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "漏洞利用活动:xp_servicecontrol访问",
        "sid": 2009999,
        "sort": "exploit_blacklist",
        "rule": "alert tcp $EXTERNAL_NET any -> $SQL_SERVERS 1433 (msg:\"漏洞利用活动:xp_servicecontrol访问\"; flow:to_server,established; content:\"x|00|p|00|_|00|s|00|e|00|r|00|v|00|i|00|c|00|e|00|c|00|o|00|n|00|t|00|r|00|o|00|l|00|\"; nocase; reference:url,doc.emergingthreats.net/2009999; classtype:attempted-user; sid:2009999; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)",
        "pro": "TCP",
        "sport": 14200,
        "dport": 1433,
        "sip": "49.234.13.200",
        "dip": "192.168.0.88",
        "data": [
            {
                'payload': b'\x78\x00\x70\x00\x5f\x00\x73\x00\x65\x00\x72\x00\x76\x00\x69\x00\x63\x00\x65\x00\x63\x00\x6f\x00\x6e\x00\x74\x00\x72\x00\x6f\x00\x6c\x00\x00\x00',
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "检测到远程文件包含漏洞",
        "sid": 2010463,
        "sort": "file_inclusion_blacklist",
        "rule": "alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"检测到远程文件包含漏洞\"; flow:established,from_server; content:\"FeeLCoMzFeeLCoMz\"; reference:url,doc.emergingthreats.net/2010463; reference:url,opinion.josepino.com/php/howto_website_hack1; classtype:successful-user; sid:2010463; rev:7; metadata:created_at 2010_07_30, updated_at 2010_07_30;)",
        "pro": "TCP",
        "sport": 14200,
        "dport": 80,
        "sip": "49.234.13.200",
        "dip": "192.168.0.88",
        "data": [
            {
                'payload': b'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 15\r\n\r\nFeeLCoMzFeeLCoMz',
                'direction': 1   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "检测到游戏活动:Battle.net",
        "sid": 2002101,
        "sort": "games_blacklist",
        "rule": "alert tcp $HOME_NET any -> $EXTERNAL_NET 6112 (msg:\"检测到游戏活动:Battle.net\"; flow:established,to_server; content:\"|FF 50|\"; depth:2; content:\"RATS\"; offset:12; depth:12; reference:url,doc.emergingthreats.net/bin/view/Main/2002101; classtype:policy-violation; sid:2002101; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)",
        "pro": "TCP",
        "sport": 14200,
        "dport": 6112,
        "dip": "49.234.13.200",
        "sip": "192.168.0.88",
        "data": [
            {
                'payload': b'\xFF\x50' + b'\x00' * 12 + b'RATS',
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "检测到未知命令",
        "sid": 2610278,
        "sort": "exploit2_blacklist",
        "rule": "alert http any any -> any any (msg:\"检测到未知命令\"; flow:to_server,established; content:\"POST\"; http_method; content:\"/command.php\"; http_uri; content:\"cmd=\"; http_client_body; depth:4; threshold:type limit, track by_src, seconds 60, count 1; classtype:bad-unknown; sid:2610278; rev:1;)",
        "pro": "TCP",
        "sport": 14200,
        "dport": 80,
        "dip": "49.234.13.200",
        "sip": "192.168.0.88",
        "data": [
            {
                'payload': b'POST /command.php HTTP/1.1\r\nHost: www.example.com\r\nContent-Length: 7\r\n\r\ncmd=ls',
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "检测到低信誉ip访问",
        "sid": 2525000,
        "sort": "ip_blacklist",
        "rule": "alert ip [1.189.88.67,1.203.161.58,1.203.93.254,1.235.102.223,1.63.226.82,1.9.128.13,101.226.241.74,101.251.99.49,101.254.208.9,101.27.41.197,101.4.0.2,101.75.165.75,101.89.67.29,102.164.222.93,103.108.87.133,103.123.215.73,103.135.160.130,103.145.12.111,103.145.12.121,103.145.12.122,103.145.12.123,103.145.12.125,103.145.12.134,103.145.13.23,103.15.140.126,103.196.240.244,103.196.31.194,103.205.7.98,103.216.186.74,103.27.7.147,103.38.252.26,103.4.31.112,103.45.177.175,103.53.211.244,103.61.100.196,103.63.2.211,103.63.2.215,103.63.215.83,103.65.236.169,103.78.180.181,103.86.134.194,103.86.158.210,103.94.6.194,104.131.46.166,104.140.188.22,104.140.188.42,104.140.188.58,104.168.168.20,104.168.198.32,104.206.128.14] any -> $HOME_NET any (msg:\"检测到低信誉ip访问\"; reference:url,blacklist.3coresec.net/lists/et-open.txt; threshold: type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:2525000; rev:459; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag 3CORESec, signature_severity Major, created_at 2020_07_20, updated_at 2022_04_21;)",
        "pro": "TCP",
        "sport": 14200,
        "dport": 3333,
        "dip": "192.168.0.233",
        "sip": "1.203.161.58",
        "data": [
            {
                'payload': b'adhahh',
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "检测到可疑ja3 hash值:Metaploit http扫描",  # 没能成功验证，但是没找到问题在哪
        "sid": 2028301,
        "sort": "js3_hash_blacklist",
        "rule": "alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:\"检测到可疑ja3 hash值:Metaploit http扫描\"; ja3_hash; content:\"8a9d5d0f12f7d43ee3af1c51d2998d99\"; reference:url,github.com/trisulnsm/trisul-scripts/blob/master/lua/frontend_scripts/reassembly/ja3/prints/ja3fingerprint.json; classtype:unknown; sid:2028301; rev:2; metadata:created_at 2019_09_10, former_category JA3, updated_at 2019_10_29;)",
        "pro": "TCP",
        "sport": 14200,
        "dport": 443,
        "dip": "49.234.13.200",
        "sip": "192.168.0.233",
        "data": [
            {
                'payload': b'\x16\x03\x01\x00\xdc\x01\x00\x00\xd8\x03\x03\x16\xf1\x7c\x89\x62\x73\xd1\xd0\x98\x31\x4a\x02\xe8\x7d\xd4\xcb\x2a\x00\x9f\x00\x00\x01\x00\x00\x00\x00\x00\x17\x00\x15\x00\x00\x12\x73\x6f\x6d\x65\x2d\x73\x6e\x69\x2d\x65\x78\x74\x65\x6e\x73\x69\x6f\x6e\x00\x0a\x00\x06\x00\x04\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00',
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "恶意软件活动:r0 CnC Architecture",  
        "sid": 2022106,
        "rule": "alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"恶意软件活动:r0 CnC Architecture\"; flow:to_server,established; http.method; content:\"GET\"; http.uri; content:\"/i686?ver=\"; depth:10; fast_pattern; http.header; content:\"Expect|3a 20|100-continue\"; http.user_agent; content:\"Mozilla/5.0 (Windows NT 6.3|3b 20|rv|3a|36.0) Gecko/20100101 Firefox/36.0\"; http.header_names; content:!\"Referer|0d 0a|\"; reference:url,blog.cari.net/carisirt-defaulting-on-passwords-part-1-r0_bot/; classtype:command-and-control; sid:2022106; rev:4; metadata:created_at 2015_11_17, former_category MALWARE, updated_at 2020_06_09;)",
        "sort": "malware_blacklist",
        "pro": "TCP",
        "sport": 14200,
        "dport": 80,
        "dip": "49.234.13.200",
        "sip": "192.168.0.233",
        "data": [
            {
                'payload': b'GET /i686?ver= HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0\r\nAccept: */*\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nExpect: 100-continue\r\n\r\n',
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "ET MOBILE_MALWARE SymbOS/Yxes CnC Checkin Request 2",  
        "sid": 2012846,
        "rule": "alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"ET MOBILE_MALWARE SymbOS/Yxes CnC Checkin Request 2\"; flow:established,to_server; content:\"/number/?PhoneType=\"; nocase; http_uri; reference:url,blog.fortinet.com/symbosyxes-or-downloading-customized-malware/; classtype:command-and-control; sid:2012846; rev:2; metadata:attack_target Mobile_Client, created_at 2011_05_25, former_category MOBILE_MALWARE, updated_at 2011_05_25, mitre_tactic_id TA0037, mitre_tactic_name Command_And_Control, mitre_technique_id T1041, mitre_technique_name Exfiltration_Over_C2_Channel;)",
        "sort": "mobile_malware_blacklist",
        "pro": "TCP",
        "sport": 14200,
        "dport": 80,
        "dip": "49.234.13.200",
        "sip": "192.168.0.233",
        "data": [
            {
                'payload': b'POST /number/?PhoneType=android HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.131 Mobile Safari/537.36\r\nAccept: */*\r\nReferer: http://www.example.com/index.html\r\nContent-Length: 0\r\n\r\n',
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "检测到dns查询了onion代理域名(way2tor)",  
        "sid": 2019982,
        "rule": "alert dns $HOME_NET any -> any any (msg:\"检测到dns查询了onion代理域名(way2tor)\"; dns_query; content:\".way2tor\"; fast_pattern; nocase; endswith; reference:url,en.wikipedia.org/wiki/Tor_(anonymity_network); classtype:bad-unknown; sid:2019982; rev:7; metadata:affected_product Any, attack_target Client_Endpoint, created_at 2014_12_20, deployment Perimeter, signature_severity Informational, tag DNS_Onion_Query, updated_at 2019_09_28;)",
        "sort": "tor_blacklist",
        "pro": "UDP",
        "sport": 14200,
        "dport": 53,
        "dip": "49.234.13.200",
        "sip": "192.168.0.233",
        "data": [
            {
                'payload': b'\x10\x32\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0f' + b'example.way2tor' + b'\x00' + b'\x00\x10\x00\x01',
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "检测到TO_CHAR缓冲区溢出尝试",  
        "sid": 2102699,
        "rule": "alert tcp $EXTERNAL_NET any -> $SQL_SERVERS $ORACLE_PORTS (msg:\"检测到TO_CHAR缓冲区溢出尝试\"; flow:to_server,established; content:\"TO_CHAR\"; nocase; pcre:\"/TO_CHAR\\s*\\(\\s*SYSTIMESTAMP\\s*,\\s*(\\x27[^\\x27]{256}|\\x22[^\\x22]{256})/smi\"; classtype:attempted-user; sid:2102699; rev:2; metadata:created_at 2010_09_23, updated_at 2010_09_23;)",
        "sort": "overflow_blacklist",
        "pro": "TCP",
        "sport": 14200,
        "dport": 1521,
        "sip": "49.234.13.200",
        "dip": "192.168.0.233",
        "data": [
            {
                'payload': b"SELECT TO_CHAR(SYSTIMESTAMP, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' FROM DUAL;",
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "检测到FTP Root登录尝试，疑似暴力破解",  
        "sid": 2010642,
        "rule": "alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:\"检测到FTP Root登录尝试，疑似暴力破解\"; flow:established,to_server; content:\"USER \"; nocase; depth:5; content:\"root\"; within:15; nocase; threshold: type threshold, track by_src, count 5, seconds 60; reference:url,doc.emergingthreats.net/2010642; classtype:attempted-recon; sid:2010642; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)",
        "sort": "passwd_attack_blacklist",
        "pro": "TCP",
        "sport": 14200,
        "dport": 21,
        "sip": "49.234.13.200",
        "dip": "192.168.0.233",
        "data": [
            {
                'payload': b"USER root",
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            },
            {
                'payload': b"USER root",
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            },
            {
                'payload': b"USER root",
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            },
            {
                'payload': b"USER root",
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            },
            {
                'payload': b"USER root",
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "检测到Paypal钓鱼受害者正在发送数据",  
        "sid": 2012630,
        "rule": "alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"检测到Paypal钓鱼受害者正在发送数据\"; flow:established,to_server; content:\"POST\"; http_method; content:\"usr=\"; content:\"&pwd=\"; content:\"&name-on=\"; content:\"&cu-on=\"; content:\"&how2-on=\"; fast_pattern; classtype:social-engineering; sid:2012630; rev:3; metadata:attack_target Client_Endpoint, created_at 2011_04_05, deployment Perimeter, signature_severity Major, tag Phishing, updated_at 2016_07_01;)",
        "sort": "phishing_blacklist",
        "pro": "TCP",
        "sport": 14200,
        "dport": 80,
        "dip": "49.234.13.200",
        "sip": "192.168.0.233",
        "data": [
            {
                'payload': b"POST /login.php HTTP/1.1\r\nHost: www.paypal.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 57\r\n\r\nusr=username&pwd=password&name-on=Peter&cu-on=1234&how2-on=mail\r\n",
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "检测到Modbus扫描",
        "sid": 2009286,
        "rule": "alert tcp any any -> any 502 (msg:\"检测到Modbus扫描\"; flow:established,to_server; content:\"|00 00 00 00 00 02|\"; depth:6; threshold: type both, track by_src, count 100, seconds 10; reference:url,code.google.com/p/modscan/; reference:url,www.rtaautomation.com/modbustcp/; reference:url,doc.emergingthreats.net/2009286; classtype:bad-unknown; sid:2009286; rev:4; metadata:created_at 2010_07_30, updated_at 2020_11_12;)",
        "sort": "port_scan_blacklist",
        "pro": "TCP",
        "sport": 14200,
        "dport": 502,
        "dip": "49.234.13.200",
        "sip": "192.168.0.233",
        "data": [
            {
                'payload': b"\x00" * 5 + b"\x02",
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            } for _ in range(1000)
        ],
    },
    {   
        "name": "检测到Nessus Netbios扫描",  # 扫描需要重复触发所以没有测试成功
        "sid": 2015754,
        "rule": "alert udp $EXTERNAL_NET any -> $HOME_NET [137,138,139,445] (msg:\"检测到Nessus Netbios扫描\"; content:\"n|00|e|00|s|00|s|00|u|00|s\"; fast_pattern; reference:url,www.tenable.com/products/nessus/nessus-product-overview; classtype:attempted-recon; sid:2015754; rev:3; metadata:created_at 2012_10_01, updated_at 2019_10_08;)",
        "sort": "port_scan_blacklist",
        "pro": "UDP",
        "sport": 14200,
        "dport": 139,
        "sip": "49.234.13.200",
        "dip": "192.168.0.233",
        "data": [
            {
                'payload': hex_to_bytes("6e006500730073007500730000"),
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ],
    },
    {   
        "name": "检测到正向shell解码的Shellcode",  # 扫描需要重复触发所以没有测试成功
        "sid": 2009246,
        "rule": "alert tcp any any -> any any (msg:\"检测到正向shell解码的Shellcode\"; flow:established; content:\"|53 53 53 53 53 43 53 43 53 FF D0 66 68|\"; content:\"|66 53 89 E1 95 68 A4 1A|\"; distance:0; reference:url,doc.emergingthreats.net/2009246; classtype:shellcode-detect; sid:2009246; rev:3; metadata:created_at 2010_07_30, updated_at 2010_07_30;)",
        "sort": "shellcode_blacklist",
        "pro": "TCP",
        "sport": 14200,
        "dport": 233,
        "dip": "49.234.13.200",
        "sip": "192.168.0.233",
        "data": [
            {
                'payload': b"\x53\x53\x53\x53\x53\x43\x53\x43\x53\xFF\xD0\x66\x68\x66\x53\x89\xE1\x95\x68\xA4\x1A",
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ]
    },
    {   
        "name": "检测到ADWARE_PUP活动:间谍软件UA头(H)",
        "sid": 2003749,
        "rule": "alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"检测到ADWARE_PUP活动:间谍软件UA头(H)\"; flow:to_server,established; content:\"User-Agent|3a| H|0d 0a|\"; reference:url,doc.emergingthreats.net/2003749; classtype:pup-activity; sid:2003749; rev:8; metadata:attack_target Client_Endpoint, created_at 2010_07_30, deployment Perimeter, former_category USER_AGENTS, signature_severity Minor, tag Spyware_User_Agent, updated_at 2016_07_01;)",
        "sort": "间谍软件UA_blacklist",
        "pro": "TCP",
        "sport": 14200,
        "dport": 233,
        "dip": "49.234.13.200",
        "sip": "192.168.0.233",
        "data": [
            {
                'payload': b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: H\r\n\r\n",
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ]
    },
    {   
        "name": "检测到在URI中使用MYSQL注释进行SQL注入",
        "sid": 2011040,
        "rule": "alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:\"检测到在URI中使用MYSQL注释进行SQL注入\"; flow:established,to_server; content:\"/*\"; http_uri; content:\"*/\"; http_uri; pcre:\"/\\x2F\\x2A.+\\x2A\\x2F/U\"; reference:url,dev.mysql.com/doc/refman/5.0/en/comments.html; reference:url,en.wikipedia.org/wiki/SQL_injection; reference:url,doc.emergingthreats.net/2011040; classtype:web-application-attack; sid:2011040; rev:4; metadata:affected_product Web_Server_Applications, attack_target Web_Server, created_at 2010_07_30, deployment Datacenter, signature_severity Major, tag SQL_Injection, updated_at 2019_08_22;)",
        "sort": "sqli_blacklist",
        "pro": "TCP",
        "sport": 14200,
        "dport": 80,
        "sip": "49.234.13.200",
        "dip": "192.168.0.233",
        "data": [
            {
                'payload': b"GET /index.php?id=1/**/UNION/**/SELECT/**/1,2,3/**/FROM/**/users-- HTTP/1.1\r\nHost: www.example.com\r\nConnection: keep-alive\r\n\r\n",
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ]
    },
    {   
        "name": "ssl黑名单证书指纹列表：检测到恶意的ssl证书(Dridex恶意软件)",  # ssl的验证比较麻烦，最后调试，这个还没测 TODO: 测试
        "sid": 902200330,
        "rule": "alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:\"ssl黑名单证书指纹列表：检测到恶意的ssl证书(Dridex恶意软件)\"; tls.fingerprint:\"a0:c4:d5:41:d7:55:53:fe:96:51:2f:22:99:98:96:b0:ed:fc:73:5b\"; reference:url, sslbl.abuse.ch/ssl-certificates/sha1/a0c4d541d75553fe96512f22999896b0edfc735b/; sid:902200330; rev:1;)",
        "sort": "ssl_blacklist",
        "pro": "TCP",
        "sport": 14200,
        "dport": 443,
        "dip": "49.234.13.200",
        "sip": "192.168.0.233",
        "data": [
            {
                'payload': hex_to_bytes("1603010200010001fc03030b98956a6c46537fb9702f99489eef8da5525396f6076bf7ecf19b098870b86f20895afbcb04ff75584d66cad233845b15cc6b3586fb3f5bf79b60ba775a5344b70024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d00208e0451483f760ccd0c6c7b34c60a730f79bae0ed7a7bb95eb946961b996ea50a001500f6000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            },
            {
                'payload': hex_to_bytes("160303003b0200003703033aee0c114791f9c6d079acefb20a755eddac67b8a69121989440e9a24d54e9d200cca800000fff01000100000b000201000023000016030303ef0b0003eb0003e80003e5308203e1308202c9a0030201020214568439d01495814968af6a63d33c09ba6aa2819d300d06092a864886f70d01010b0500307f310b300906035504061302636e3112301006035504080c094775616e67646f6e67310f300d06035504070c06466f7368616e3110300e060355040a0c07796f756e676572310c300a060355040b0c036f7073310c300a06035504030c036f7073311d301b06092a864886f70d010901160e7a7a73756b69403136332e636f6d3020170d3233303331323135333130385a180f32313233303231363135333130385a307f310b300906035504061302636e3112301006035504080c094775616e67646f6e67310f300d06035504070c06466f7368616e3110300e060355040a0c07796f756e676572310c300a060355040b0c036f7073310c300a06035504030c036f7073311d301b06092a864886f70d010901160e7a7a73756b69403136332e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100b3f00a43034f467a7df46cba01f29c806b2d8217efb680c2c942b7334d53549c0ea1b9d525db0ad8438e769dcbd159a70043814f08e48ce0c8a1c53b6455b0ea88df32460a5141b24674cf6d9486f1e519e4913ede3e20f35ad0a1b85de46459de2fb9f9ff3d074ddd2d6175006bc8d8dd2f18fb9073aafc4b956ca7abe63ddc9386552d67f31d82fa1ecafcc6f9e91a2ecc5ca28c9d5352cc664048c8124c414c45dff0c089bf3fc1566c1095b26d40bf2a03174764d242b7d05af9ee1ffd3ecc67582726e13ea9c1aed0678902abd8ae82ec41e10b19ee5690761e1cdab97cbd91293c7fbb12b7a71926be499a5d50df3959ebc6470b0fe7f3f4dc40c492f70203010001a3533051301d0603551d0e04160414a0c4d541d75553fe96512f22999896b0edfc735b301f0603551d23041830168014a0c4d541d75553fe96512f22999896b0edfc735b300f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003820101009ebf3f215601ccfc43c733c280d8b20a04685352249fcbce0d7d2152d713096c1f50996da689ee0dc36c45bad67c7d88fa7225fdfa81c3e309a7aa8493ebec5aab52d593809104555a0837be0cc8609033b1eb5b9741588d89baf5753796f23d69c80b82dacef9d26918ca5526e3ab4730a12c14aa26e9b9dd9ef293ae3ce575e8844ef88d43bb576658da1d4d22e664f3cebfab87805cb3cc5535dcb129174ee7e1d1fa51a2f6faf5c234815642728119da085836179ca648b9aa57235423eea103e32db000c67d13f9a8e9d596526500c7704c9193bc12363660949810816de9be0351ce24104a6d850ae97de144713e1a1b2d151fe145166a53ece5655fb9160303012c0c00012803001d20d0890c58b468f132ebb40e88ef4421b637b05664772046019b55e4ed98e2333e04010100b39040886b3efe141902a9d66b9eb0cad1993c1267cb8e5db6ea2958246227e2ef9245876b8807fd6f35503823d125b4b9ca4d10be16fd097c5f66638660e6e2d69af2df967dcd743489f99dd21f9bd5b0183fc3a43f898017717a7b36b6b1f6a428175b7ed3e4cbe6a7c72b1943c692fd1ee4b84c1a3abd54662c8364a402446bd26e8075ac492ecf692c43071795503f59ef134c81945a915bd917eebd8d2070808fa5136e7ceebb403820504d4b7b59a35fa31e489dc74d096673f070058f1d02724ff53920ab488f49a3cb539623f15287f38e3325868ca58fc54e04eb67a8f3cc8f0e7b69a570d711e59dac913a8122ac17864f523298638f00e148028416030300040e000000"),
                'direction': 1   # 0 代表从c到s, 1 代表从s到c
            },
            {
                'payload': hex_to_bytes("160303002510000021205d7351de62edf4467a0b138d334cd6a1953285a01dba96a9f5100d5e51cd197a140303000101160303002048877c58b962bab80368bb795ad77e926a9e3ff1cf0389232c1f45f5f856102c"),
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            },
            {
                'payload': hex_to_bytes("16030300aa040000a600001c2000a00d506933db1b7bf50093914c76e0458a448687a1e34b54d87ea38e41662267285e9dac00d04ebd7b9d106d73d5fd7fac0e40cbb85aa923a6389b5c7cba359556068e9994b1f1087e27042a0a85bef67f22372b901715a17521cc933a7e1842f4a1294cf4f0194b0e1e38f05e7b0bdb54d9b45bab91218b408cf2fb0862cb0c70399a49f485b9cdfd58558b31da931cb6eb6befa853feaad7348a40ad48aa15271403030001011603030020b40659396aa33f8b703ab69516991c4c67e3b430ca9c07e80684909b2d17dd31"),
                'direction': 1   # 0 代表从c到s, 1 代表从s到c
            },
            {
                'payload': hex_to_bytes("170303013fde3b200f06cc9da015d4b84a7b028a6360c299cee61e74d6405bcb523afe5dada4621a11ccad1d4dccf212e3ec523742c05aedbae8e05467efb86b5ef1bb967039816bfc395bc18a25d365178b3c7036fabbd6dddfb1a476a7e490a4a9921be18caecc66717dd65416162bcf5104d05567a3050781db7746f59adc61ba1cb7389ef7c58540c9ab3e468ec7a1b53862d5028e1d493a9fb59b9b11331624909ce5ab987c352468e22677e888693e98a21aa1af26f37f58e6ba94c7b0805091f0a20c8470ba10493506faf60aca28411338117de657b6039fdab586c8841869d09b302411cc3a77e02a879c337ea84acabc6e6caaa81b9bc047de344c5a21b404b4d72a7d6d2d42e4be8ebb45d486570e193f5dec5f47b2db40017917dda0eee6f748107a5da72dffababa51423249b8fc6118a162a61697e2fcbafc1852affa2"),
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            },
            {
                'payload': hex_to_bytes("17030300a52c98560879274663f2b07632174a053636918a8764579c2612e5ed0275c57c8966fc2c71a9570ca48952cdc8ca72e50617a3fb1eb6fca10c2348e67a79d7f19c7400b0081c17de5e9436dd1875c9744450dcc886fad5d29ab9d09cbe1c0cd6bc7b3acbe276cce8735d821bb6d2fc7673fbb601182310ef3ab7943c57dab9424ff326ee463ed919519c096280c79cda78fbc64683dca26dbc1548dbca4801c8e7269d0e63af"),
                'direction': 1   # 0 代表从c到s, 1 代表从s到c
            }
        ]
    },
    {   
        "name": "检测到已知的Tor出口节点流量，ip组1",   # 未部署在审计 TODO: 测试
        "sid": 2520000,
        "rule": "alert tcp [102.130.113.37,102.130.113.9,103.155.84.104,103.214.7.251,103.228.53.155,103.234.220.205,103.236.201.88,103.251.167.10,103.251.167.20,103.253.41.98] any -> $HOME_NET any (msg:\"检测到已知的Tor出口节点流量，ip组1\"; reference:url,doc.emergingthreats.net/bin/view/Main/TorRules; threshold: type limit, track by_src, seconds 60, count 1; classtype:misc-attack; flowbits:set,ET.TorIP; sid:2520000; rev:4772; metadata:affected_product Any, attack_target Any, deployment Perimeter, tag TOR, signature_severity Audit, created_at 2008_12_01, updated_at 2022_04_21;)",
        "sort": "tor_blacklist",
        "pro": "TCP",
        "sport": 14200,
        "dport": 233,
        "sip": "102.130.113.9",
        "dip": "192.168.0.233",
        "data": [
            {
                'payload': b"hello, world",
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ]
    },
    {   
        "name": "检测到Octoshape UDP会话",   # 未部署在审计
        "sid": 2009986,
        "rule": "alert udp $HOME_NET 8247 -> $EXTERNAL_NET 8247 (msg:\"检测到Octoshape UDP会话\"; threshold: type both, count 2, seconds 60, track by_src; reference:url,msmvps.com/blogs/bradley/archive/2009/01/20/peer-to-peer-on-cnn.aspx; reference:url,doc.emergingthreats.net/2009986; classtype:trojan-activity; sid:2009986; rev:2; metadata:created_at 2010_07_30, updated_at 2010_07_30;)",
        "sort": "trojan_activity_blacklist",
        "pro": "UDP",
        "sport": 8247,
        "dport": 8247,
        "dip": "49.234.13.200",
        "sip": "192.168.0.233",
        "data": [
            {
                'payload': b"hello, world",
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            } for _ in range(3)
        ]
    },
    {   
        "name": "检测到可疑的User-Agent(入站规则)",   # 未部署在审计
        "sid": 2008228,
        "rule": "alert http $EXTERNAL_NET any -> $HOME_NET any (msg:\"检测到可疑的User-Agent(入站规则)\"; flow:to_server,established; threshold: type limit, count 3, seconds 300, track by_src; http.header; content:\"User-Agent|3a 20|bot/\"; nocase; reference:url,doc.emergingthreats.net/bin/view/Main/2008228; classtype:trojan-activity; sid:2008228; rev:11; metadata:affected_product Any, attack_target Client_Endpoint, created_at 2010_07_30, deployment Perimeter, former_category HUNTING, signature_severity Major, tag User_Agent, updated_at 2020_04_22;)",
        "sort": "UA_blacklist",
        "pro": "TCP",
        "sport": 14200,
        "dport": 80,
        "sip": "49.234.13.200",
        "dip": "192.168.0.233",
        "data": [
            {
                'payload': b"GET /page.html HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: bot/1.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64)\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: zh-CN\r\nReferer: http://www.google.com/\r\nUpgrade-Insecure-Requests: 1\r\nCookie: __cfd_out=1\r\nConnection: keep-alive\r\n\r\n",
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            } for _ in range(3)
        ]
    },
    {   
        "name": "检测到蠕虫活动:shell bot perl代码下载",   # 未部署在审计
        "sid": 2002683,
        "rule": "alert http $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any (msg:\"检测到蠕虫活动:shell bot perl代码下载\"; flow:to_client,established; content:\"ShellBOT\"; nocase; reference:url,doc.emergingthreats.net/2002683; classtype:trojan-activity; sid:2002683; rev:6; metadata:created_at 2010_07_30, updated_at 2010_07_30;)",
        "sort": "worm_activity_blacklist",
        "pro": "TCP",
        "sport": 14200,
        "dport": 80,
        "dip": "49.234.13.200",
        "sip": "192.168.0.233",
        "data": [
            {
                'payload': b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: 8\r\n\r\ShellBOT",
                'direction': 1   # 0 代表从c到s, 1 代表从s到c
            }
        ]
    },
    {   
        "name": "检测到在url中存在跨站脚本攻击尝试",   # 未部署在审计
        "sid": 2009714,
        "rule": "alert http $EXTERNAL_NET any -> $HTTP_SERVERS any (msg:\"检测到在url中存在跨站脚本攻击尝试\"; flow:to_server,established; http.uri; content:\"</script>\"; nocase; reference:url,ha.ckers.org/xss.html; reference:url,doc.emergingthreats.net/2009714; classtype:web-application-attack; sid:2009714; rev:8; metadata:affected_product Web_Server_Applications, attack_target Web_Server, created_at 2010_07_30, deployment Datacenter, former_category WEB_SERVER, signature_severity Major, tag XSS, tag Cross_Site_Scripting, updated_at 2020_08_20;)",
        "sort": "xss_blacklist",
        "pro": "TCP",
        "sport": 14200,
        "dport": 80,
        "sip": "49.234.13.200",
        "dip": "192.168.0.233",
        "data": [
            {
                'payload': b"GET /rds-help/advanced/deferredView.jsp?view=%3Cscript%3Ealert%28%22XSS%22%29%3B%3C%2Fscript%3E HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\n\r\n",
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ]
    },
    {   
        "name": "漏洞利用活动:在http uri中存在ysoserial Payload(Clojure1)",
        "sid": 2033468,
        "rule": "alert http any any -> [$HOME_NET,$HTTP_SERVERS] any (msg:\"漏洞利用活动:在http uri中存在ysoserial Payload(Clojure1)\"; flow:established,to_server; http.uri; content:\"/+vADGAwAABQBzAHIAAAARAGoAYQB2AGEALgB1AHQAaQBsAC4ASABhAHMAaABNAGEAcAAFAAcADCU0JRwlFgBgAGQlAwAAA\"; fast_pattern; classtype:attempted-admin; sid:2033468; rev:1; metadata:attack_target Server, created_at 2021_07_28, deployment Perimeter, deployment Internal, former_category EXPLOIT, malware_family ysoserial, signature_severity Major, tag Exploit, updated_at 2021_07_28;)",
        "sort": "ysoserial_payload_blacklist",
        "pro": "TCP",
        "sport": 14200,
        "dport": 80,
        "sip": "49.234.13.200",
        "dip": "192.168.0.233",
        "data": [
            {
                'payload': b"GET /example/+vADGAwAABQBzAHIAAAARAGoAYQB2AGEALgB1AHQAaQBsAC4ASABhAHMAaABNAGEAcAAFAAcADCU0JRwlFgBgAGQlAwAAA HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\n\r\n",
                'direction': 0   # 0 代表从c到s, 1 代表从s到c
            }
        ]
    },
    # 正常通信流量
    # {   
    #     "name": "modbus15",
    #     "sid": 15,
    #     "rule": "alert http any any -> [$HOME_NET,$HTTP_SERVERS] any (msg:\"漏洞利用活动:在http uri中存在ysoserial Payload(Clojure1)\"; flow:established,to_server; http.uri; content:\"/+vADGAwAABQBzAHIAAAARAGoAYQB2AGEALgB1AHQAaQBsAC4ASABhAHMAaABNAGEAcAAFAAcADCU0JRwlFgBgAGQlAwAAA\"; fast_pattern; classtype:attempted-admin; sid:2033468; rev:1; metadata:attack_target Server, created_at 2021_07_28, deployment Perimeter, deployment Internal, former_category EXPLOIT, malware_family ysoserial, signature_severity Major, tag Exploit, updated_at 2021_07_28;)",
    #     "sort": "ysoserial_payload_blacklist",
    #     "pro": "TCP",
    #     "sport": 14200,
    #     "dport": 502,
    #     "sip": "192.168.0.21",
    #     "dip": "192.168.0.233",
    #     "data": [
    #         {
    #             'payload': hex_to_bytes("000100000008010f000000030100"),
    #             'direction': 0   # 0 代表从c到s, 1 代表从s到c
    #         },
    #         {
    #             'payload': hex_to_bytes("000100000006010f00000003"),
    #             'direction': 1   # 0 代表从c到s, 1 代表从s到c
    #         }
    #     ]
    # }
]
