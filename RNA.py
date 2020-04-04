from sys import stdin, stdout
import random
import argparse


def email():  # Number of jumps put in terminal.
    return "email"


PARSER = argparse.ArgumentParser()  # Read in command line arguments
PARSER.add_argument("-blockportscan", help="Block port scans", type=int)
PARSER.add_argument(
    "-blockscan",
    required=True,
    help="Option to block port scanning on your host network",
    type=float,
)
PARSER.add_argument(
    "-email",
    required=True,
    help="1 to enable email notifications, 0 to disable",
    type=int,
    choices=range(0, 2),
)

ARGS = PARSER.parse_args()
printMe = ""

if ARGS.email:
    printMe = email()
    print(printMe)

if ARGS.blockscan:  # If trials exist, assign it, else set default trials (1000).
    print("block")
else:
    print("Not blocked")
    
    """TODO:
    Need to figure out if we are being port scanned..
    Basic steps we need to do - 
    First, see if packet is originating from our box, to do that
    make sure its an ip packet... if it is and ip is source, return false
    if it returns true it means that it needs to be filtered. We can act
    on any number of tcp packets that are destined for any of the ports we define
    in some predefined or userdefined list......"""
