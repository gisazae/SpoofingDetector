from scapy.all import *
from clint.textui import colored
import os, ip_misc, time

conf.verb = 0
#Set sniffer to promiscuous mode
conf.sniff_promisc = True

'''
Obtains current gateway IP address
'''
def get_gateway_ip():
    #Via ICMP request
    p = sr1(IP(dst="www.example.com", ttl=0)/ICMP()/"",timeout=2)
    if p:
        return p.src
    #via traceroute
    else:
        p,q = traceroute('1.1.1.1', maxttl=1)
        return p[0][1]['IP'].src

'''
Obtains the MAC address from a local IP
ip: the IP address of the host we want the MAC address
'''
def get_mac(ip):
    p = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),timeout=2,retry=10)
    return p[0][0][1].src

'''
Displays alert messages on screen
msg: the message to be displayed on screen
'''
def alert(msg):
    print colored.yellow("[WARNING]:"), msg

'''
Evaluates the packet layers and sends it to corresponding evaluation functions
packet: the packet to be processed
'''
def process_packet(packet):
    if packet.haslayer(ARP):
        arp_spoofing_detect(packet)
    elif packet.haslayer(IP):
        if packet.haslayer(TCP):
            syn_flood_detect(packet)

'''
Logs the number of requests a host makes every minute and alerts if suspicious ammount of requests are
detected on 1 minute interval.
packet: the packet to be evaluated
'''
def syn_flood_detect(packet):
    #logging phase
    src = packet[IP].src
    current_minutes = time.localtime().tm_min
    if packet[TCP].flags == 2:
        if requests_log.has_key(src):
            if requests_log[src]['minute'] == current_minutes:
                requests_log[src]['requests'] += 1
            else:
                requests_log[src]['requests'] = 0
                requests_log[src]['minute'] = current_minutes
        else:
            requests_log[src] = {}
            requests_log[src]['requests'] = 0
            requests_log[src]['minute'] = current_minutes
    #evaluation phase
    for ip in requests_log.keys():
        if requests_log[ip]['requests'] >= 500:
            alert("High number of requests per minute " + str(requests_log[ip]['requests']) + " from " + ip + " possible flooding attack?")

'''
Checks ARP traffic and evaluates if the network gateway ip is being spoofed.
packet: the packet to be evaluated
'''
def arp_spoofing_detect(packet):
    hwsrc = packet[ARP].hwsrc
    psrc = packet[ARP].psrc
    if psrc == gateway_ip and hwsrc != gateway_mac:
        alert("ARP spoofing detected from " + hwsrc)

'''
Initializes needed global variables and starts the sniffing session, sending the packets to a processing function
interface: networking interface to sniff from
'''
def start_sniffer(interface):
    #global variables declaration
    global gateway_ip
    global gateway_mac
    global requests_log
    requests_log = {}
    pre_gateway_ip = get_gateway_ip()
    gateway_ip = raw_input("Enter gateway IP ["+pre_gateway_ip+"]:") or pre_gateway_ip
    if ip_misc.check_IP(gateway_ip):
        gateway_mac = get_mac(gateway_ip)
        print colored.blue("[INFO]:"), "Sniff session started\n"
        sniff(iface=interface,prn=process_packet)
        print "\nSniff session finished"
    else:
        print "Malformed IP given"
