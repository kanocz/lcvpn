# LCVPN - Light decentralized VPN in golang

Originally this repo was just an answer on a question "how much time it'll take to write my own simple VPN in golang" (answer is about 3 hours for first prototype), but now it used in production in different environments.

So, LCVPN is
  - Very light and easy (one similar config on all hosts)
  - Use same config for all hosts (autedetect local params) - useful with puppet etc
  - Uses AES-128, AES-192 or AES-256 encryption (note that AES-256 is **much slower** than AES-128 on most computers) + optional HMAC-SHA256 or (super secure! 😅 ) NONE encryption (just copy without modification)
  - Communicates via UDP directly to selected host (no central server)
  - Works only on Linux (uses TUN device)
  - Support of basic routing - can be used to connect several networks
  - Multithread send and receive - scaleable for big traffc
  - Due to use so_reuseport better result in case of bigger number of hosts
  - It's still in beta stage, use it on your own risk (and please use only versions marked as "release")

![alt tag](https://raw.githubusercontent.com/kanocz/lcvpn/master/topology.png)

### Install and run

You need golang (at least 1.5) installed and configured:

```sh
$ go get -u github.com/kanocz/lcvpn
```

if you have config in /etc/lcvpn.conf

```sh
$ sudo $GOPATH/bin/lcvpn
```

if you want to specify different location of config (or if you need to run several instances)

```sh
$ sudo $GOPATH/bin/lcvpn -config lcvpn.conf
```
if you host is hidden behind firewall (with udp port forward) lcvpn is unable to detect
which "remote" is localhost. In this case use next syntax:

```sh
$ sudo $GOPATH/bin/lcvpn -local berlin -config lcvpn.conf
```


### Config example

```
[main]
port = 23456
encryption = aescbchmac
mainkey = 4A34E352D7C32FC42F1CEB0CAA54D40E9D1EEDAF14EBCBCECA429E1B2EF72D219D1EEDAF14EBCBCECA429E1B2EF72D21
altkey = 1111111117C32FC42F1CEB0CAA54D40E9D1EEDAF14EBCBCECA429E1B2EF72D219D1EEDAF14EBCBCECA429E1B2EF72D21
broadcast = 192.168.3.255
netcidr = 24
recvThreads = 4
sendThreads = 4

[remote "prague"]
ExtIP = 46.234.105.229
LocIP = 192.168.3.15
route = 192.168.10.0/24
route = 192.168.15.0/24
route = 192.168.20.0/24

[remote "berlin"]
ExtIP = 103.224.182.245
LocIP = 192.168.3.8
route = 192.168.11.0/24

[remote "kiev"]
ExtIP = 95.168.211.37
LocIP = 192.168.3.3
```

where port is UDP port for communication  
encryption is *aescbchmac* for AES-CBC+HMAC-SHA256, *legacy-aescbc-unsafe* for unauthenticated legacy AES-CBC or *none* for no encryption.

For *legacy-aescbc-unsafe*, mainkey/altkey is the hex form of a 16, 24 or 32-byte key (for AES-128, AES-192 or AES-256).
for *aescbchmac* mainkey/altkey is 32 bytes longer
for *none* mainkey/altkey mainkey/altkey is just ignored
LocIP, broadcast, route networks, and external UDP endpoints must resolve to IPv4
number of remotes is virtualy unlimited, each takes about 256 bytes in memory  

### Config reload

Config is reloaded on HUP signal. In case of invalid config just log message will appeared, previous one is used.  
P.S.: listening udp socket is not reopened for now, so on port change restart is needed

### Wire protocol compatibility and replay protection

Version 0.3 uses a new packet format and is not wire-compatible with older versions. Upgrade all peers together.
Old peers reject the new frame before writing it to the TUN interface.

Every packet contains the intended peer's VPN address, a random per-peer session ID, and a monotonically increasing sequence number.
Receivers keep a 1024-packet sliding window for each session, allowing UDP reordering while rejecting duplicates
and packets older than the window. Replay state is shared by all receive threads and survives configuration reloads,
but is kept in memory and is reset when the daemon restarts.

The *aescbchmac* mode calculates HMAC-SHA256 over the IV and ciphertext and verifies it before decryption.
The session ID and sequence number are inside the authenticated ciphertext. The *legacy-aescbc-unsafe* and *none* modes do not
provide cryptographic authentication; their replay checks cannot protect against an active attacker who can modify packets.
The former *aescbc* configuration name is intentionally rejected. Use *legacy-aescbc-unsafe* only when wire compatibility
with an existing unauthenticated AES-CBC deployment is required.

### Online key change

**altkey** configuration option allows specify alternative encryption key that will be used in case if decription with primary
one failed. This allow to use next algoritm to change keys without link going offline:
  - In normal state only **mainkey** is set (setting altkey is more cpu-consuming)
  - Set altkey to new key on all hosts and send HUP signal
  - Exchange altkey and aeskey on all hosts and send HUP signal
  - Remove altkey (with old key) from configs on all hosts and send HUP signal again
  - We are running with new key :)

### Roadmap

* 100% unit test coverage
* please let me know if you need anything more
