# LCVPN - VPN in 3 hours

This repo is just an answer on a question "how much time it'll take to write my own simple VPN in golang"  
It was less than I can ever image - little bit more than 3 hours.  
Update: next 30 minut was spent on dynamic config reloading on HUP signal  
Update: next 2 hours to use only one UDP socket, support broadcast and multicast, support config reload and encryption key change without going offline  
Update: and about 30 minutes more to implement multithread + so_socket

So, LCVPN is
  - Very light and easy (one similar config on all hosts)
  - Uses AES-128, AES-192 or AES-256 encryption (note that AES-256 is **much slower** than AES-128 on most conputers)
  - Communicates via UDP directly to selected host (no central server)
  - Works only on Linux (uses TUN device)
  - Multithread send and receive - scaleable for big traffc
  - Due to use so_reuseport better result in case of bigger number of hosts
  - Please don't use it in production without testing, it's beta stage

### Install and run

You need golang (at least 1.5) installed and configured:

```sh
$ go install github.com/kanocz/lcvpn
$ sudo $GOPATH/bin/lcvpn -local 192.168.3.3/24 -config lcvpn.conf
```

where **192.168.3.3/23** is internal vpn ip which will be setted on tun interface

### Config example

```
[main]
port = 23456
aeskey = 4A34E352D7C32FC42F1CEB0CAA54D40E9D1EEDAF14EBCBCECA429E1B2EF72D21
#altkey = 1111111117C32FC42F1CEB0CAA54D40E9D1EEDAF14EBCBCECA429E1B2EF72D21
broadcast = 192.168.3.255
recvThreads = 4
sendThreads = 4

[remote "prague"]
ExtIP = 46.234.105.229
LocIP = 192.168.3.15

[remote "berlin"]
ExtIP = 103.224.182.245
LocIP = 192.168.3.8

[remote "kiev"]
ExtIP = 95.168.211.37
LocIP = 192.168.3.3
```

where port is UDP port for communication  
aeskey is hex form of 16, 24 or 32 bytes key (for AES-128, AES-192 or AES-256)  
number of remotes is virtualy unlimited, each takes about 256 bytes in memory

### Config reload

Config is reloaded on HUP signal. In case of invalid config just log message will appeared, previous one is used.  
P.S.: listening udp socket is not reopened for now, so on port change restart is needed

### Online key change

**altkey** configuration option allows specify alternative AES key that will be used in case if decription with primary
one failed. This allow to use next algoritm to change keys without link going offline:
  - In normal state only **aeskey** is set (setting altkey is more cpu-consuming)
  - Set altkey to new key on all hosts and send HUP signal
  - Exchange altkey and aeskey on all hosts and send HUP signal
  - Remove altkey (with old key) from configs on all hosts and send HUP signal again
  - We are running with new key :)

### Plans

Don't know what more to implement... please let me know if you need something
