# RNA Network Defense Tool

The RNA Network Defense Tool is a tool designed to run on the router. It is capable of detecting different port scan variants such as TCP SYN scans, FIN scans, UDP scans, including ICMP flooding. Different options exist allowing you to receive email notifications.

## Getting Started

The following dependencies require installation:

`sudo pip install requests`

`sudo pip install scapy`

`sudo pip install sockets`

`sudo pip install unpack`

`sudo pip install email-to`

In terminal, navigate to the directory of RNA.py and run using Python 2.
`sudo python RNA.py
*Note: To view malicious network traffic, pass the -v option. To have an email sent to you when suspicious traffic is seen, pass -e. To do a scan of your own network, pass -l. To see all TCP, UDP, or ICMP traffic that might be malicious, pass -a.

## Authors

* © 2020 Anthony Agatiello, Robert Whitman
