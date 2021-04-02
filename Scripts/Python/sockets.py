import socket
with socket.socket() as s:
    s.connect(('192.168.229.105', 21))
    print(s.recv(4096))
#7 220 ProFTPB 1.3.5 Server (Great Job!) [172.17.0.2]

with socket.socket() as s:
    s.connect(('192.168.229.105', 21))
    print(s.recv(4096).decode(ascii).lstrip('220 '))