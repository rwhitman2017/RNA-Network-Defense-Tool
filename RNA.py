# https://www.shellvoide.com/python/intercept-and-sniff-live-traffic-data-in-a-network-in-python/
# Maybe some good info in here.
# https://pypi.org/project/django-block-ip/
import random
import argparse
from socket import *
from requests import get
from contextlib import closing
from scapy.all import *
import smtplib
from email.mime.text import MIMEText
from struct import unpack

def email(port_being_scanned, src_addr):  # Email function
    fromaddr = "rnanetworkdefense@outlook.com"
    password = "7h3r3'5 n0 p01n7 1n t4k1ng 7h15 p455w0rd fr0m m3... bu7 0k!"
    toaddrs  = "anthony@adatechri.com"
    if port_being_scanned != 0:
        text_msg = "New scan detected on port %s" + str(port_being_scanned)
    else:
        text_msg = "SYN flood detected from IP: " + str(src_addr)
    
    msg = MIMEText(text_msg)
    msg['Subject'] = "RNA Network Defense Tool Notification"
    msg['From'] = "RNA"
    msg['To'] = toaddrs
    
    s = smtplib.SMTP('smtp-mail.outlook.com', 587)
    s.starttls()
    s.login(fromaddr, password)
    s.sendmail(fromaddr, toaddrs, msg.as_string())
    s.quit()
    
    return 0
    
def is_private_address(ip):
    f = unpack('!I',inet_pton(AF_INET,ip))[0]
    private = (
        # 127.0.0.0
        [2130706432, 4278190080],
        # 192.168.0.0
        [3232235520, 4294901760],
        # 172.16.0.0
        [2886729728, 4293918720],
        # 10.0.0.0
        [167772160,  4278190080],
    )
    for net in private:
        if (f & net[1]) == net[0]:
            return True
    
    return False

def has_syn_flag(pkt):
    if pkt[TCP].flags & 0x02:
        return True
    else:
        return False

# Make a hashtable (dictionary) with all the IPs the filter
# has seen and keep track of how many times each IP appears
#GOOD PRESENTING POINT FOR DR.OC
knownTCP_IPs = {}
knownUDP_IPs = {}
knownICMP_IPs = {}

def scan_filter(pkt): # Detects if a port scan is in progress
    # Ip packet will be one of three types: TCP, UDP, or ICMP.
    
    # From this point forward, we have a packet we should look out for...
    # If certain attributes of a packet are present, we should be
    # able to detect malicious activity
    
    global knownTCP_IPs, knownUDP_IPs, knownICMP_IPs
    localIPAddr = socket.gethostbyname(socket.gethostname())  # Gets local ip address 127.0.0.1
    
    if pkt.haslayer(IP) and pkt[IP].src == localIPAddr:  # If packet contains the IP header
        # If the source IP address of the packet is from the local machine, do not flag it.
        return False
    # Most likely, you won't be getting suspicious traffic from within your local network
    if pkt.haslayer(IP) and is_private_address(pkt[IP].src):
        return False
    
    # Declare source address once so we don't have to do it
    # for every type of packet
    source_ip_address = ""
    if pkt.haslayer(IP):
        source_ip_address = pkt[IP].src
    
    if pkt.haslayer(IP) and pkt.haslayer(TCP) and has_syn_flag(pkt):
        if source_ip_address in knownTCP_IPs:
            knownTCP_IPs[source_ip_address] += 1
        else:
            knownTCP_IPs.update( {source_ip_address : 1} )
        
        '''# TODO: Pass in S argument 1-10 w different level of sensitivity
        if (knownTCP_IPs[source_ip_address] > x):'''
        
        return True
    # If a UDP packet's destination port is in the list, flag it
    elif pkt.haslayer(IP) and pkt.haslayer(UDP):
        if source_ip_address in knownUDP_IPs:
            knownUDP_IPs[source_ip_address] += 1
        else:
            knownUDP_IPs.update( {source_ip_address : 1} )
        return True
    # If an ICMP packet is being sent, flag it
    elif pkt.haslayer(ICMP) in pkt:
        if source_ip_address in knownICMP_IPs:
            knownICMP_IPs[source_ip_address] += 1
        else:
            knownICMP_IPs.update( {source_ip_address : 1} )
        return True
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
    # Display packet summary information
    # return pkt.summary()
    return None
    
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
