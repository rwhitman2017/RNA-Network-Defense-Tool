# https://www.shellvoide.com/python/intercept-and-sniff-live-traffic-data-in-a-network-in-python/
# Maybe some good info in here.
import random
import argparse
import socket
from requests import get
from contextlib import closing
from scapy.all import *
import smtplib

def email(port_being_scanned):  # Email function
    fromaddr = 'rnanetworkdefense@outlook.com'  
    toaddrs  = 'meyeco2438@emailhost99.com'  
    msg = 'Spam email Test'  

    username = 'rnanetworkdefense@outlook.com'  
    password = "7h3r3'5 n0 p01n7 1n t4k1ng 7h15 p455w0rd fr0m m3... bu7 0k!"

    server = smtplib.SMTP('smtp-mail.outlook.com', 587)  
    server.ehlo()
    server.starttls()
    server.login(username, password)  
    server.sendmail(fromaddr, toaddrs, msg)  
    server.quit()
    server = smtplib.SMTP_SSL('smtp-mail.outlook.com', 587)
    server.login('rnanetworkdefense@outlook.com', "7h3r3'5 n0 p01n7 1n t4k1ng 7h15 p455w0rd fr0m m3... bu7 0k!")
    server.sendmail(
        "rnanetworkdefense@outlook.com", 
        "destination@google.com", 
        "You are being port scanned on port: ")
    server.quit()
    return 0

def scan_filter(pkt): # Detects if a port scan is in progress
    """Ip packet will be one of three types: TCP, UDP, or ICMP.
    Todo."""
    localIPAddr = socket.gethostbyname(socket.gethostname())  # Gets local ip address #127.0.0.1
    tcpPorts = [port for port in range(1, 65536)]  # Initialize list with every tcp port
    udpPorts = [port for port in range(1, 65536)]  # Initialize list with every udp port
    
    if IP in pkt:  # If packet contains the IP header
        # If the source IP address of the packet is from the local machine, do not flag it.
        if pkt[IP].src == localIPAddr:
            return False
    
    # If a TCP packet's destination port is in the list (1-65535), flag it
    if TCP in pkt and pkt[TCP].dport in tcpPorts:
        return True
    # If a UDP packet's destination port is in the list, flag it
    elif UDP in pkt and pkt[UDP].dport in udpPorts:
        return True
    # If an ICMP packet is being sent, flag it
    elif ICMP in pkt:
        return True
    # Nothing is happening, return false
    else:
        return False

def lock_down_ports():
    # TBD
    return 0
    
def check_socket(host, port):
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:  # Initialize socket
        # If port is open (socket connection return is 0
        if sock.connect_ex((host, port)) == 0:  # Open socket from particular host to specified port
            print("Port " + str(port) + " is open")  # Print port number
            
def list_open_ports():
    ip = get("https://api.ipify.org").text  # Get "my" public IP
    for port in range(1, 65536):  # Go through all ports
        check_socket(ip, port)  # Check to see if port is open
    return
    
def print_packet_info(pkt):
    return pkt.summary()  # Display packet summary information
    
PARSER = argparse.ArgumentParser()  # Read in command line arguments

PARSER.add_argument(
    "--blockscan",
    "-b",
    help="Pass to block port scanning on your host network",
    action="store_true"
)
PARSER.add_argument(
    "--email",
    "-e",
    help="Pass to enable email notifications",
    action="store_true"
)

PARSER.add_argument(
    "--listOpenPorts",
    "-l",
    help="Pass to list open ports from external IP",
    action="store_true"
)

ARGS = PARSER.parse_args()

# Send email notification (TBD)
"""
if ARGS.email:
"""

if ARGS.listOpenPorts:
    list_open_ports()

if ARGS.blockscan:  # If blockscan is requested, do that. Else...dont.
    #  Calls scan_filter function if packet returns true. If true, print packet info.
    sniff(lfilter=scan_filter, count=0, prn=print_packet_info)
    
    """TODO:
    Need to figure out if we are being port scanned..
    Basic steps we need to do - 
    First, see if packet is originating from our box, to do that
    make sure its an ip packet... if it is and ip is source, return false
    if it returns true it means that it needs to be filtered. We can act
    on any number of tcp packets that are destined for any of the ports we define
    in some predefined or userdefined list......"""
