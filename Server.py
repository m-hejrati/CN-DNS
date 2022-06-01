import binascii
import socket

address = "127.0.0.1"
port = 1234

# Create a datagram socket
UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# Bind to address and ip
UDPServerSocket.bind((address, port))
print("Server listening ...\n")

# Listen for incoming datagrams
while True:
    bytesAddressPair = UDPServerSocket.recvfrom(4096)

    message = bytesAddressPair[0]
    address = bytesAddressPair[1]

    clientMsg = "Message from Client: {}".format(binascii.hexlify(message))
    clientIP = "Client IP Address:{} ".format(address)

    print(clientMsg)
    print(clientIP)

    # Send received message again to client
    UDPServerSocket.sendto(message, address)

    # send test string to client
    # UDPServerSocket.sendto(str.encode("Test String"), address)
    # 5465737420537472696e67