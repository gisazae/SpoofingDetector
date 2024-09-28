"""
    Main user interface
    minimalistic menu-based console UI
"""
import sys, os
from clint.textui import colored
from modules.sniffer import start_sniffer
from modules import arp, syn_flood, dhcp, ssl

def clearScreen():
    os.system('clear')
    os.system('ps -ef|grep spoof')

def start_menu():
    clearScreen()
    main_menu()

'''
Calls a function from the menu according to user input
root: parent or current menu (for backwards navigation)
choice: user input choice
'''
def exec_menu(root, choice):
    clearScreen()
    ch = choice.lower()
    if ch == '':
        menu_actions[root]()
    else:
        try:
            menu_actions[ch]()
        except KeyError:
            print("Invalid selection, try again.\n")
            menu_actions[root]()

'''
Main menu
'''
def main_menu():
    banner()
    print titleStripes() * 15, "MAIN MENU", titleStripes() * 15
    print "1.\tGenerate attacks."
    print "2.\tStart attacks detector."
    print "99.\tExit.\n"
    choice = raw_input(">>")
    exec_menu('main_menu', choice)

'''
Attacks menu
'''
def attacks_menu():
    print titleStripes()*15,"GENERATE ATTACKS",titleStripes()*15
    print "0.\tMain menu."
    print "11.\tARP poisoning MITM."
    print "12.\tSYN flooding DoS."
    print "13.\tRogue DHCP server MITM."
    print "14.\tSSLStrip2 (SSL strip + dns server)."
    print "99.\tExit.\n"
    choice = raw_input(">>")
    exec_menu('1', choice)

'''
Detection menu
'''
def detection_menu():
    print titleStripes()*15,"ATTACK DETECTION",titleStripes()*15
    print "0.\tMain menu."
    print "21.\tStart."
    print "99.\tExit.\n"
    choice = raw_input(">>")
    exec_menu('2', choice)

'''
Launch ARP poisoning attack
'''
def arp_poison():
    if arp.poison():
        print colored.green("ARP poisoning attack completed.")
    else:
        print colored.red("Attack could not be completed.")
    attacks_menu()

'''
Launch SYN flooding attack
'''
def syn_flooding():
    syn_flood.flood()
    attacks_menu()

'''
Launch DHCP rogue attack
'''
def rogue_dhcp():
    dhcp.rogue_dhcp()
    attacks_menu()

def ssl_strip2():
    ssl.launch()
    attacks_menu()

'''
Launch attacks detection sniffer
'''
def sniffer():
    interface = raw_input("Interface [eth0]:") or "eth0"
    os.system("clear")
    start_sniffer(interface)
    detection_menu()

def exit():
    sys.exit()

'''
Shows a banner
'''
def banner():
    print(
        colored.cyan("""
                                    .------.
                                   (        )_
                                 ('    )     ,)
                               ('    )   )  )
                                '( )    ) )'
                                  ''''''''""") +
        colored.green("""
  ___   _      ___   _                 /
 [(_)] |=|    [(_)] |=|               /
  '-`  |_|     '-`  |_|              /
 /:::/  /     /:::/  /              /
       |____________|______________/""") +
colored.red("""
                        |
                ___   _/
               [(_)] |=|
                '-`  |_|
               /:::/
    """))

def titleStripes():
    return colored.blue("=")

'''
Menu actions (by number, except for the main menu)
'''
menu_actions = {
        '99': exit,
        '0': main_menu,
        '1': attacks_menu,
        '2': detection_menu,
        '11': arp_poison,
        '12': syn_flooding,
        '13': rogue_dhcp,
        '14': ssl_strip2,
        '21': sniffer
        }
