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
import os

dns_server_exceptions = [
    "208.67.222.222",  # OpenDNS
    "208.67.220.220",
    "1.1.1.1",  # Cloudflare
    "1.0.0.1",
    "8.8.8.8",  # Google
    "8.8.4.4",
    "8.26.56.26",  # Comodo
    "8.20.247.20",
    "9.9.9.9",  # Quad9
    "149.112.112.112",
    "64.6.64.6",  # Verisign
    "64.6.65.6"
]

def windows_dns_servers():
    # Run ipconfig
    cmd_output = subprocess.check_output(["ipconfig", "-all"]).decode("utf-8")
    # Split ipconfig output by a newline
    ipconfig_all_list = cmd_output.split("\n")
    
    # Make an empty list to store DNS servers
    dns_ips = []
    # Go through all the lines of the output
    for i in range(0, len(ipconfig_all_list)):
        # If the text "DNS Servers" is found, extract everything after the colon
        if "DNS Servers" in ipconfig_all_list[i]:
            first_ip = ipconfig_all_list[i].split(":")[1].strip()
            # Append the IP to the list
            dns_ips.append(first_ip)
            k = i + 1
            # Determine if there are multiple DNS servers by detecting the
            # lack of a colon; if there are, then append the list with those
            while k < len(ipconfig_all_list) and ":" not in ipconfig_all_list[k]:
                ip = ipconfig_all_list[k].strip()
                dns_ips.append(ip)
                k += 1
            break
    
    return dns_ips

def unix_dns_servers():
    # Make an empty list to store DNS servers
    dns_ips = []
    # Open the DNS resolver file
    with open("/etc/resolv.conf") as fp:
        for cnt, line in enumerate(fp):
            columns = line.split()
            # Determine the text after "nameserver"
            if columns[0] == "nameserver":
                ip = columns[1:][0]
                # Append the server to the list
                dns_ips.append(ip)

    return dns_ips
    
def user_dns_servers():
    # Platform is Windows
    if os.name == "nt":
        return windows_dns_servers()
    # Platform is UNIX-based
    elif os.name == "posix":
        return unix_dns_servers()
    # Platform is unknown
    return None

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
notified_ips = []

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
    
    global knownTCP_IPs, knownUDP_IPs, knownICMP_IPs, email_enabled, public_ip,all_enabled
    # "localhost", 127.0.0.1; can sometimes be private address
    localIPAddr = socket.gethostbyname(socket.gethostname())
    
    # Declare source address here once so we don't have to do it
    # for every type of packet
    source_ip_address = pkt[IP].src
    
    if public_ip == "":
        public_ip = get("https://checkip.amazonaws.com").text.strip()
    
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
                # with the key as the IP address and the value as an empty list;
                # get the "value" if it already does
                scanned_ports = knownTCP_IPs.get(source_ip_address, [])
                
                # If the port hasn't been seen before, append it to the list
                if pkt[TCP].dport not in scanned_ports:
                    scanned_ports.append(pkt[TCP].dport)
                
                # Update the key/value pair with the new list of ports that the IP address has tried to scan
                knownTCP_IPs[source_ip_address] = scanned_ports
                
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
        if source_ip_address in dns_server_exceptions:
            return False
        
        # Remainder of logic is the same as TCP (202)
        scanned_ports = knownUDP_IPs.get(source_ip_address, [])
        
        if pkt[UDP].dport not in scanned_ports:
            scanned_ports.append(pkt[UDP].dport)
        
        knownUDP_IPs[source_ip_address] = scanned_ports
        
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
            print("+50 ICMP requests originating from the IP address: " + source_ip_address)
            # Ensure that we have not emailed the user about this IP before
            if email_enabled and source_ip_address not in notified_ips:
                email("Possible DOS attack (at least 50 ICMP requests) from: " + source_ip_address)
                # After we send the email, add the IP address in question
                # to the list so we don't spam the user with emails re. the same IP
                notified_ips.append(source_ip_address)
            del knownICMP_IPs[source_ip_address]
        
        return True
    else:
        return False

open_port_results = "Port scan results for "

def check_socket(host, port):
    # Prepare the port results to send via email if option is set
    global open_port_results
    # Initialize socket
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        # If port is open, socket connect function returns 0
        if sock.connect_ex((host, port)) == 0:
            port_result_text = "Port " + str(port) + " (" + socket.getservbyport(port) + ") is open"
            print(port_result_text)
            port_result_text += "\n"
            open_port_results += port_result_text
    
    return None

def list_open_ports():
    # Get public IP address
    ip = get("https://checkip.amazonaws.com").text.strip()
    print("Scanning ports on: " + ip)
    
    # Append the IP to the email
    global open_port_results
    open_port_results += (ip + ":\n\n")
    
    # Go through all ports and check if it's open
    for port in range(0, 65536):
        check_socket(ip, port)
    
    if email_enabled:
        email(open_port_results)
    
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
    
    # Append the user's DNS servers to the exception list
    for dns_server in user_dns_servers():
        if dns_server not in dns_server_exceptions:
            dns_server_exceptions.append(dns_server)
    
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
