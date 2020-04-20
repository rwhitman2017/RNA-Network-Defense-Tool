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

def email(output):
    # Setup email authentication data
    fromaddr = "rnanetworkdefense@outlook.com"
    password = "7h3r3'5 n0 p01n7 1n t4k1ng 7h15 p455w0rd fr0m m3... bu7 0k!"
    toaddrs  = "anthony@adatechri.com"
    
    # Set the subject, from, and to fields of the email
    msg = MIMEText(output)
    msg['Subject'] = "RNA Network Defense Tool Notification"
    msg['From'] = "RNA"
    msg['To'] = toaddrs
    
    # Open a connection to the SMTP server and login with the credentials to send the email
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

# Packet has flags: SYN
def syn(pkt):
    if pkt[TCP].flags.S:
        return True
    else:
        return False
        
# Packet has no flags
def null(pkt):
    if not pkt[TCP].flags:
        return True
    else:
        return False

# Packet has flags: FIN
def fin(pkt):
    if pkt[TCP].flags.F:
        return True
    else:
        return False

# Packet has flags: FIN, PUSH, and URG
def xmas_tree(pkt):
    if pkt[TCP].flags.F and pkt[TCP].flags.P and pkt[TCP].flags.U:
        return True
    else:
        return False

# Packet has flags: ACK
def ack(pkt):
    if pkt[TCP].flags.A:
        return True
    else:
        return False

# Make a hashtable (dictionary) with all the IPs the filter
# has seen and keep track of what ports have been scanned by it,
# or how many ICMP requests it has made
knownTCP_IPs = {}
knownUDP_IPs = {}
knownICMP_IPs = {}

all_enabled = False
email_enabled = False

# Make the public IP string global so we don't have to retrieve
# it every time a packet is detected
public_ip = ""

def scan_filter(pkt):
    # From this point forward, we have a packet we should look out for...
    # If certain attributes of a packet are present, we should be
    # able to detect malicious activity with mild certainty
    
    # If the packet doesn't have an IP header, don't even bother...
    if not pkt.haslayer(IP):
        return False
    
    global knownTCP_IPs, knownUDP_IPs, knownICMP_IPs, email_enabled, public_ip, all_enabled
    # "localhost", 127.0.0.1; can sometimes be private address
    localIPAddr = socket.gethostbyname(socket.gethostname())
    
    # Declare source address here once so we don't have to do it
    # for every type of packet
    source_ip_address = pkt[IP].src
    
    if public_ip == "":
        public_ip = get("https://api.ipify.org").text
    
    # If the IP address of the packet is from the local machine, there's no need to go further
    if source_ip_address == localIPAddr or source_ip_address == public_ip:
        return False
    # Most likely, you won't be getting suspicious traffic from within your local network
    if is_private_address(source_ip_address):
        return False
    
    # IP packet will be one of three types: TCP, UDP, or ICMP.
    # a.) TCP
    if pkt.haslayer(TCP):
        # If the source port is either 80 or 443, it's probably not malicious
        if (pkt[TCP].sport != 443 and pkt[TCP].sport != 80):
            # Detect if the packet has typical flags that indicate an nmap scan
            if syn(pkt) or null(pkt) or fin(pkt) or xmas_tree(pkt) or ack(pkt):
                # If the IP address hasn't been seen before, initialize a key/value pair
                # with the key as the IP address and the value as an empty list
                if source_ip_address not in knownTCP_IPs:
                    knownTCP_IPs.update( {source_ip_address : []} )
                
                # Get the "value" (list of ports the IP address has tried to scan)
                scanned_ports = knownTCP_IPs[source_ip_address]
                
                # If the port hasn't been seen before, append it to the list
                if pkt[TCP].dport not in scanned_ports:
                    scanned_ports.append(pkt[TCP].dport)
                
                # Update the key/value pair with the new list of ports that the IP address has tried to scan
                knownTCP_IPs.update( {source_ip_address : scanned_ports} )
                
                # If -a is passed, show every TCP packet that has dangerous-looking flags
                if all_enabled:
                    out_text = "Possible TCP attack from source IP address: " + source_ip_address + " on ports " + str(scanned_ports) + "\n"
                    print(out_text)
                    knownTCP_IPs.clear()
                # If -a is not passed, show a list with 20 elements of all the ports that have been scanned
                elif len(scanned_ports) >= 20:
                    out_text = "Possible TCP attack from source IP address: " + source_ip_address + " on ports " + str(scanned_ports) + "\n"
                    print(out_text)
                    knownTCP_IPs.clear()
        
        return True
    # b.) UDP
    elif pkt.haslayer(UDP):
        # Because UDP is used constantly with DNS servers, there will be many false positives,
        # so if the packet's IP address matches that of a popular DNS server, ignore the packet
        if source_ip_address in popular_dns_servers:
            return False
        
        # Remainder of logic is the same as TCP
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
    # c.) ICMP
    elif pkt.haslayer(ICMP):
        # For this dictionary, we are only keeping track of the IP address and
        # how many times its seen
        ''' -------------------------------------------------------------- '''
        # If the IP address is in the dictionary, add one to its value
        if source_ip_address in knownICMP_IPs:
            knownICMP_IPs[source_ip_address] += 1
        # Otherwise, initialize a new key/value pair with the IP address as the
        # key, and 1 as its value (ie. its been seen one time as an ICMP packet)
        else:
            knownICMP_IPs.update( {source_ip_address : 1} )
        
        # If one IP address has sent 50 ICMP packets, we should probably
        # display it to the user
        if knownICMP_IPs[source_ip_address] == 50:
            out_text = "+50 ICMP requests originating from the IP address: " + source_ip_address
            print(out_text)
            if email_enabled:
                email(out_text)
            knownICMP_IPs.clear()
        
        return True
    else:
        return False
    
def check_socket(host, port):
    # Initialize socket
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        # If port is open, socket connect function returns 0
        if sock.connect_ex((host, port)) == 0:
            print("Port " + str(port) + " is open")
    return None
            
def list_open_ports():
    # Get public IP address
    ip = get("https://api.ipify.org").text
    # Go through all ports and check if it's open
    for port in range(1, 65536):
        check_socket(ip, port)
    return None
    

if __name__ == "__main__":
    # Command line arguments
    PARSER = argparse.ArgumentParser()

    PARSER.add_argument(
        "--view",
        "-v",
        help="View filtered traffic that is probably malicious",
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
    
    if ARGS.view:
        # Calls scan_filter function if packet returns true. If true, determine if the packet(s)
        # are malicious and then output the information to the screen
        sniff(lfilter=scan_filter, count=0)
