import socket
with socket.socket() as s:
     s.bind(('',9999))
     s.listen()
     conection, ipaddr = s.accept()

     with connection:

         print("Connection from", ipaddr)
         while True:
         connection.sendall(b"220 ProFTPB 1.3.5 Server (Great Job!) [172.17.0.2]\n")