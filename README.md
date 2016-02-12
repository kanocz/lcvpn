# LCVPN - VPN in 3 hours

This repo is just an answer on a question "how much time it'll take to write my own simple VPN in golang"  
It was less than I can ever image - little bit more than 3 hours.

So, LCVPN is
  - Very light and easy (one similar config on all hosts)
  - Uses AES-128, AES-192 or AES-256 encryption
  - Communicates via UDP directly to selected host (no central server)
  - Works only on Linux (uses TUN device)
  - Uses only 2 threads (one for send and one for receive), but can be easly extended to use some worker pool
  - Is a **toy** project, don't use it in production without testing
  - One more time, it's a **toy** project, so no clean code can be expected :)

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
number of remotes is virtualy unlimited, but maximal numbers of opened files have to be adjusted if you plan to use more than 1020 (each use one socket + listening socket and so on)

### Plans

Maybe I'll implement some optimizations like using worker threads, reusing part of last message instead of crypto/rand and so on :)
