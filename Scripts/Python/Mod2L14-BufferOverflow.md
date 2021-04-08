# Module 2, Lesson 14 – Buffer Overflow Exploit

## 1. Identify the attack surface of the server

```bash
nmap 192.168.229.13 ( found port 313373/tcp open Elite)
nc 192.168.229.13 31337 ("Welcome to the character customizatino server! Type HELP for options")
HELP brings up a list of inputs
```

## 2. Fuzz the server for weaknesses in buffers

[Simple Fuzzer Script](CTE-2103/Scripts/CTE-2103-Week6.md#actual-fuzzer-script)

## 3. Develop a proof of concept exploit.
## 4. Further develop your exploit to a full shell.
## NOTE: You can choose to do a BIND or REVERSE shell or try both.