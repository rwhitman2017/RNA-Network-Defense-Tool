# RNA Network Defense Tool

The RNA Network Defense Tool is a tool designed to run on the router. It is capable of detecting different port scan variants such as TCP SYN scans, FIN scans, UDP scans, and additionally it can detect ICMP flooding. Different options exist allowing you to receive email notifications realtime when these potential attacks take place.

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

# In order to enable email functionality, you must preform the following steps.
1. Open the RNA.py file in a text editor.
2. Find the following lines of code:
`def email(output):
    fromaddr = "YourEmail@Host.com"
    password = "Enter In Your Password Here"
    toaddrs  = fromaddr`
3. Within this code, enter in your email address and your password where appropriate.
4. Locate the following line of code:
`#s = smtplib.SMTP('stmpserver.mail.com', 587)  <- Replace with your email`
5. Replace what is inside the parenthesis with your appropriate mail server.
For example, if you are using outlook: s = smtplib.SMTP('smtp-mail.outlook.com', 587)
Alternatively, if you are using gmail: s = smtplib.SMTP('smtp.gmail.com', 587)
## Authors

* © 2020 Anthony Agatiello, Robert Whitman
