import re, os
from scapy.all import *

'''
Check if ip address is correctly formed
'''
def check_IP(ip):
    pattern = re.compile("^(([0-9]){1,3}\.([0-9]){1,3}\.([0-9]){1,3}\.([0-9]){1,3})$")
    return pattern.match(ip)

'''
Check if port number is between range 1-65535
'''
def check_port(port):
    return int(port) in range(1, 65536)

'''
Enables IPv4 forwarding for routing purposes
'''
def enable_forward():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

'''
Disables IPv4 forwarding
'''
def disable_forward():
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

'''
Redirects http traffic to this machine's proxy (sslstrip)
'''
def start_http_redirect(port):
    os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port " + str(port))

'''
Stops http redirect to sslstrip proxy
'''
def stop_http_redirect(port):
    os.system("iptables -t nat -D PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port " + str(port))

'''
Redirects DNS queries to this machine's DNS
'''
def start_dns_redirect():
    os.system("iptables -t nat -A PREROUTING -p udp --destination-port 53 -j REDIRECT --to-port 53")

'''
Stops DNS query redirect
'''
def stop_dns_redirect():
    os.system("iptables -t nat -D PREROUTING -p udp --destination-port 53 -j REDIRECT --to-port 53")

