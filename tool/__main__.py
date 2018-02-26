import sys, platform, os
from menu import *

if str(platform.system()) != 'Linux':
    print "Only linux system supported on this version!!"
    sys.exit()

if os.getlogin() != 'root':
    print "Need to be root in order to work!"
    sys.exit()

start_menu()
