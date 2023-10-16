from rich import print as rprint
from rich.table import Table
from rich.markdown import Markdown
import os
from scapy.all import *
import argparse
import threading
from queue_structure import Queue
from scanner import Scanner

def clear():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def getArgs():
    parser = argparse.ArgumentParser(
        prog="Port Sniper",
        description="A simple and efficient TCP port-scanner"
        )

    
    parser.add_argument('-s', '--scan', 
    type=str, 
    help="specify a scan type, default is SYN scan", 
    choices=["syn", "connect"],
    default="syn",
    dest="scan")


    parser.add_argument('-i','--ip', 
                        type=str, 
                        help='The machine IP to scan', 
                        dest='ip', 
                        required=True)

    parser.add_argument('-p','--port', 
                        type=str, 
                        help='Port range to scan seperated by a dash, ex: 80 or 1-100', 
                        dest='port', 
                        required=True)
    
    

    
    args = parser.parse_args()

    return args


def QueuePorts():
    args = getArgs()
    portQueue = Queue()
    if '-' in args.port:
        split_args = args.port.split('-')
        for port in range(int(split_args[0]), int(split_args[1]) + 1):
            portQueue.enqueue(port)
    else:
        split_args = args.port.split()
        for port in range(len(split_args)):
            portQueue.enqueue(int(split_args[port]))
    return portQueue

def discoverHosts(args):
    scanner = Scanner(args.ip, args.port)
    ping = scanner.ping()
    if not ping:
        rprint(f"[bold red]Host {args.ip} seems to be down, try again later![/bold red]")
        exit()




def synScan(args):
    portQueue = QueuePorts()
    table = Table(title=f"SYN scan results:")
    table.add_column("Port")
    table.add_column("Status")
    table.add_column("Service")
    closedPorts = 0
    noOpenPorts = True
    
    discoverHosts(args)
    

    while not portQueue.isEmpty():
        port = portQueue.dequeue()
        scanner = Scanner(args.ip, port)
        
        response = scanner.syn()
        
        if not response:
            table.add_row(f"{port}/TCP", "filtered", "Unknown")
            noOpenPorts = False
        elif response[1] == 'SA':
            table.add_row(f"{port}/TCP", "open", f"{response[0]}")
            noOpenPorts = False
            
        elif response[1] == 'RA':
            closedPorts += 1
            

    rprint(f"Closed Ports: {closedPorts}\n")

    if noOpenPorts:
        return rprint("[bold red] All scanned ports are closed, nothing to display![/bold red]")
    else:
        rprint(table)
    


def connectScan(args):
    portQueue = QueuePorts()
    table = Table(title=f"Connect scan results:")
    table.add_column("Port")
    table.add_column("Status")
    table.add_column("Service")
    closedPorts = 0
    noOpenPorts = True
    
    discoverHosts(args)
    

    while not portQueue.isEmpty():
        port = portQueue.dequeue()
        scanner = Scanner(args.ip, port)
        
        response = scanner.connect()
        
        if not response:
            table.add_row(f"{port}/TCP", "filtered", "Unknown")
            noOpenPorts = False
        elif response[1] == 'SA':
            table.add_row(f"{port}/TCP", "open", f"{response[0]}")
            noOpenPorts = False
            
        elif response[1] == 'RA':
            closedPorts += 1
            

    rprint(f"Closed Ports: {closedPorts}\n")

    if noOpenPorts:
        return rprint("[bold red] All scanned ports are closed, nothing to display![/bold red]")
    else:
        rprint(table)

    
    


    
def Display(args):
    clear()
    rprint("""
 __   __   __  ___     __          __   ___  __  
|__) /  \ |__)  |     /__` |\ | | |__) |__  |__) 
|    \__/ |  \  |     .__/ | \| | |    |___ |  \ 
                                                 
[bold red]Author:[/bold red] Ameer Moustafa
[bold red]Github:[/bold red] https://github.com/Ameer-Moustafa/PortSniper                                                 
\n""")

    rprint(f"""
    [bold red]Target Info:[/bold red]\n
    [bold]IP:[/bold] {args.ip}
    [bold]Ports:[/bold] {args.port}\n""")


def main():
    args = getArgs()
    Display(args)
    if args.scan == "syn":
        synScan(args)
    elif args.scan == "connect":
        connectScan(args)

        


main()


# TO-DO
# Handle RST packets with IP tables
# iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP - to prevent RST
# iptables -F - to reset iptables when done
# Target overview in display(), IP, ports to scan, mac address?, etc (in progress)
# Different scans with scapey

# Read https://nmap.org/book/toc.html - Host Discovery, Port scanning overview. How nmap handles open, closed, filtered states

# Delay argument for port scans, can add a flag like nmap with default value

# https://thepacketgeek.com/scapy/building-network-tools/part-10/#sweep-and-scan

# Future features
# Ability to read hosts/ports from files
# Ability to write results to files
