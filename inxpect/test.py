import socket
import sys
import json

HOST, PORT = "localhost", 8080


m = {"type": 4, "value": 0, "buffer":""} # a real dict.


data = json.dumps(m)

# Create a socket (SOCK_STREAM means a TCP socket)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    # Connect to server and send data
    sock.connect((HOST, PORT))
    sock.sendall(bytes(data,encoding="utf-8"))


    # Receive data from the server and shut down
    received = sock.recv(1024)
    received = json.loads(received)
    
    
    
    print("Sent:     {}".format(data))
    print("Received: {}".format(received))

    sock.close()

except Exception as e:
    print(e)
    print("Unexpected error:", sys.exc_info()[0])
