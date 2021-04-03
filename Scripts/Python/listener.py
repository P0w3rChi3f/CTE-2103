import socket

def myListener():
    with socket.socket() as s:
        s.bind(('',9999))
        s.listen()
        conn, ipaddr = s.accept()
        with conn:
            print('Connected by', ipaddr)
            while True:
                conn.sendall(b"220 ProFTPB 1.3.5 Server (Great Job!) [172.17.0.2]\n")
                conn.recv(1024)    
        
        
        
        #