import socket
import os

with socket.socket() as s:
    s.connect(('192.168.229.105', 21))
    print(s.recv(4096))
#7 220 ProFTPB 1.3.5 Server (Great Job!) [172.17.0.2]

with socket.socket() as s:
    s.connect(('192.168.229.105', 21))
    print(s.recv(4096).decode(ascii).lstrip('220 '))

# Settings for my own listner
def myGrabber():
    with socket.socket() as s:
        s.connect(('192.168.229.105', 21))
        banner = s.recv(17).decode('ascii').lstrip('220 ')
        print(banner)
    with open('/home/exercises/ftp_software_list.txt') as handle:
    #text = 'ProFTPB 1.3.5'
    #linenum = 0
        for line in handle:
            if banner in line:
                print('I found the text')
                print('The full line reads as:')
                print(line)    
        
### Still need work
