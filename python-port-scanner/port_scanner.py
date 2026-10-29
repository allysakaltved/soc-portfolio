#importing socket allows program to send and receive data over a network, 
# it is essential for port scanning
import socket

# asks user for input for target IP and start and end port range
target = input("What IP do you want to scan? ")
while True:
    try:
        start_port = int(input("Enter starting port: "))
        end_port = int(input("Enter ending port: "))
        if start_port >= 1 and end_port <= 65535 and end_port >= start_port:
            break
        else:
            print("Invalid port range! Please try again.")
    except ValueError:
        print("Invalid input! Please enter a number.")

print("Scanning ", target, "...")

open_ports = 0

# create for loop for ports, create socket and timeout, print status, and close socket
for port in range(start_port, end_port + 1):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex((target, port))
    if result==0:
        print("Port ", port, "is OPEN")
        open_ports += 1
    s.close()
print("Scan complete!")
print("Total open ports: ", open_ports)
