# https://www.shellvoide.com/python/intercept-and-sniff-live-traffic-data-in-a-network-in-python/
# Maybe some good info in here.

import random
import argparse
from socket import *
from requests import get
from contextlib import closing
from scapy.all import *
import smtplib
from email.mime.text import MIMEText
from struct import unpack
import threading

popular_dns_servers = [
    "208.67.222.222",
    "208.67.220.220",
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "8.26.56.26",
    "8.20.247.20"
]

def email(output):  # Email function
    fromaddr = "rnanetworkdefense@outlook.com"
    password = "7h3r3'5 n0 p01n7 1n t4k1ng 7h15 p455w0rd fr0m m3... bu7 0k!"
    toaddrs  = "anthony@adatechri.com"
    
    msg = MIMEText(output)
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

def syn(pkt):  # syn flag
    if pkt[TCP].flags.S:
        return True
    else:
        return False
        
def null(pkt):  # no flags
    if not pkt[TCP].flags:
        return True
    else:
        return False
        
def fin(pkt):  # fin
    if pkt[TCP].flags.F:
        return True
    else:
        return False
        
def xmas_tree(pkt):  # Fin push and urg
    if pkt[TCP].flags.F and pkt[TCP].flags.P and pkt[TCP].flags.U:
        return True
    else:
        return False

def ack(pkt):  # ack
    if pkt[TCP].flags.A:
        return True
    else:
        return False

# Make a hashtable (dictionary) with all the IPs the filter
# has seen and keep track of how many times each IP appears
#GOOD PRESENTING POINT FOR DR.OC
knownTCP_IPs = {}
knownUDP_IPs = {}
knownICMP_IPs = {}
email_enabled = False
public_ip = ""
all_enabled = False

def scan_filter(pkt): # Detects if a port scan is in progress
    # Ip packet will be one of three types: TCP, UDP, or ICMP.
    
    # From this point forward, we have a packet we should look out for...
    # If certain attributes of a packet are present, we should be
    # able to detect malicious activity
    
    global knownTCP_IPs, knownUDP_IPs, knownICMP_IPs, email_enabled, public_ip, all_enabled
    localIPAddr = socket.gethostbyname(socket.gethostname())  # Gets local ip address 127.0.0.1
    
    # Declare source address once so we don't have to do it
    # for every type of packet
    source_ip_address = ""
    if pkt.haslayer(IP):
        source_ip_address = pkt[IP].src
    
    if public_ip == "":
        public_ip = get("https://api.ipify.org").text
    
    if pkt.haslayer(IP) and (source_ip_address == localIPAddr or source_ip_address == public_ip):  # If packet contains the IP header
        # If the source IP address of the packet is from the local machine, do not flag it.
        return False
    # Most likely, you won't be getting suspicious traffic from within your local network
    if pkt.haslayer(IP) and is_private_address(source_ip_address):
        return False
    
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        if (pkt[TCP].sport != 443 and pkt[TCP].sport != 80):
            if syn(pkt) or null(pkt) or fin(pkt) or xmas_tree(pkt) or ack(pkt):
                if source_ip_address not in knownTCP_IPs:
                    knownTCP_IPs.update( {source_ip_address : []} )
                
                scanned_ports = knownTCP_IPs[source_ip_address]
                
                if pkt[TCP].dport not in scanned_ports:
                    scanned_ports.append(pkt[TCP].dport)
                
                knownTCP_IPs.update( {source_ip_address : scanned_ports} )
                
                if all_enabled:
                    out_text = "Possible TCP attack from source IP address: " + source_ip_address + " on ports " + str(scanned_ports) + "\n"
                    print(out_text)
                    if email_enabled:
                        email(out_text)
                    knownTCP_IPs.clear()
                elif len(scanned_ports) >= 20:
                    out_text = "Possible TCP attack from source IP address: " + source_ip_address + " on ports " + str(scanned_ports) + "\n"
                    print(out_text)
                    if email_enabled:
                        email(out_text)
                    knownTCP_IPs.clear()
        
        return True
    # If a UDP packet's destination port is in the list, flag it
    elif pkt.haslayer(IP) and pkt.haslayer(UDP):
        if source_ip_address in popular_dns_servers:
            return False
        
        if source_ip_address not in knownUDP_IPs:
            knownTCP_IPs.update( {source_ip_address : []} )
            
        scanned_ports = knownTCP_IPs[source_ip_address]
        
        if pkt[UDP].dport not in scanned_ports:
            scanned_ports.append(pkt[UDP].dport)
            
        knownUDP_IPs.update( {source_ip_address : scanned_ports} )
        
        if all_enabled:
            out_text = "Possible UDP attack from source IP address: " + source_ip_address + " on ports " + str(scanned_ports) + "\n"
            print(out_text)
            knownUDP_IPs.clear()
        elif len(scanned_ports) >= 20:
            out_text = "Possible UDP attack from source IP address: " + source_ip_address + " on ports " + str(scanned_ports) + "\n"
            print(out_text)
            knownUDP_IPs.clear()
        
        return True
    # If an ICMP packet is being sent, flag it
    if pkt.haslayer(ICMP):
        if source_ip_address in knownICMP_IPs:
            knownICMP_IPs[source_ip_address] += 1
        else:
            knownICMP_IPs.update( {source_ip_address : 1} )
        
        if knownICMP_IPs[source_ip_address] == 50:
            print("+50 ICMP requests originating from the IP address: " + source_ip_address)
            knownICMP_IPs.clear()
        
        return True
    else:
        return False
    
def check_socket(host, port):
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:  # Initialize socket
        # If port is open (socket connection return is 0
        if sock.connect_ex((host, port)) == 0:  # Open socket from particular host to specified port
            print("Port " + str(port) + " is open")  # Print port number
    return None
            
def list_open_ports():
    ip = get("https://api.ipify.org").text  # Get "my" public IP
    for port in range(1, 65536):  # Go through all ports
        check_socket(ip, port)  # Check to see if port is open
    return None
    

if __name__ == "__main__":
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
    
    PARSER.add_argument(
        "--all",
        "-a",
        help="Pass to display all traffic that might be malicious",
        action="store_true"
    )

    ARGS = PARSER.parse_args()
    
    if ARGS.email:
        email_enabled = True
    
    if ARGS.listOpenPorts:
        list_open_ports()
        
    if ARGS.all:
        all_enabled = True

    if ARGS.blockscan:  # If blockscan is requested, do that. Else...dont.
        #  Calls scan_filter function if packet returns true. If true, print packet info.
        sniff(lfilter=scan_filter, count=0)
        
        """TODO:
        Need to figure out if we are being port scanned..
        Basic steps we need to do -
        First, see if packet is originating from our box, to do that
        make sure its an ip packet... if it is and ip is source, return false
        if it returns true it means that it needs to be filtered. We can act
        on any number of tcp packets that are destined for any of the ports we define
        in some predefined or userdefined list......"""
