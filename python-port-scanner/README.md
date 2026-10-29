# Python TCP Port Scanner

## Overview
A basic TCP port scanner I developed using Python to practice network programming, socket connections, and cybersecurity fundamentals.

The script allows users to specify a target IP address and port range, then attempts TCP connections to identify open ports.

## Features
- Accepts a target IP address
- Allows users to specify a custom port range
- Uses Python's socket module to test TCP connections
- Displays open ports
- Counts the total number of open ports found
- Validates port ranges and handles invalid numeric input
- Uses connection timeouts to prevent excessive waiting

## Technologies Used
- Python 3
- Socket module
- TCP/IP networking

## How to Run
Run the script using:

`python3 port_scanner.py`

Enter the target IP address, starting port, and ending port when prompted.

Only scan systems you own or have permission to test.

## Future Improvements
- IP address validation
- Improved error handling
- Faster scanning
- Service identification
- Exporting scan results to a file

