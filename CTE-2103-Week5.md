# CTE - Week 5

## Classroom Links

* [Teams](https://teams.microsoft.com/l/team/19%3a7a166f374eb44c89bb972a20cf5a3d6e%40thread.tacv2/conversations?groupId=b0216bab-7ebb-498b-af22-3d7c8db2d92f&tenantId=37247798-f42c-42fd-8a37-d49c7128d36b)  
* [CLME](https://learn.dcita.edu/)
* [CTE_TTPs_Lab_Manual_CTA_1901](.\Files\CTE_TTPs_Lab_Manual_CTA_1901.pdf)

## Module 2 — Lesson 6: File Transfer

### Transferring Files

Common Name | Acronym | Typical Ports
--- | --- | ---
Secure Copy Protocol/Secure Shell |  SCP/SSH | TCP 22
File Transfer Protocol | FTP | TCP 20, 21
Trivial File Transfer Protocol | TFTP | TCP 69
Hypertext Transfer Protocol / HyperText Transfer Protocol Secure | HTTP/HTTPS | HTTP: TCP 80 / HTTPS: TCP 443
Server Message Block / Common INternet File System | SMB/CIFS | SMB: TCP 445
Network File System | NFS | TCP / UDP 2049, 111

### Transering File
* Secure Copy
  * `scp [ [user@] src host: ] src file [ [user@] dst host: ] dst file`
  * SCP Pullig
    * `user@src_host:src_file dst_file`
  * SCP Pushing
    * `scp src_file user@dst_host:dst_file`
* Windows SMB
  * `net use <drive letter > :< sharename> / user: [domain] \ < username>`
* Netcat
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
* Basic Netcat Usage
  * Open a listening port on your Windows 7 VM
    * Don't forget to check your syntax  
    ![NetCat Listener](./Files/CTE-Week4/Images/NetCat-Listener.jpg)
    * Connect to Windows 7 VM from CentOS
    ![NetCat Listener](./Files/CTE-Week4/Images/NetCat-Listener2.jpg)
  * Using Netcat to Get a Remote Shell
    * Use the -e option to execute a program after connection
    ![NetCat Listener](./Files/CTE-Week4/Images/NetCat-Listener3.jpg)
    * Ensure the nc version you are using has the —e option.
* Transferring Files With Netcat
  * Receiver sets up listener; sender calls forward
    * Destination: `nc -1 <dst port > <filename>`
    * Source: `nc 10.0.2.2 <dst_port < <filename>`
  ![NetCat File Transfer](./Files/CTE-Week4/Images/NetCat-File-Transfer.jpg)
  * Reverse transfer
    * Sender sets up listener; receiver calls back
    * Source: `nc -1 <src port > < <filename>`
    * Destination: `nc <src_ip> <src_port> <filename>`
    ![NetCat File Transfer](./Files/CTE-Week4/Images/NetCat-File-Transfer2.png)

### Socat
