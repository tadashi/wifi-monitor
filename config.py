#! /usr/bin/env python

import os
import re
import string

class Configure(object):
    def __init__(self, interface, threshold):
        super(Configure, self).__init__()

        self.int = interface
        self.thr = threshold

        self.ip_addr = ''
        self.ether_addr =''

        
    def get_addr(self):
        
        p = os.popen("/sbin/ifconfig %s" % self.int)
        t = p.read()
        p.close()
        
        self.ip_addr =  re.search("inet addr:([0-9.]+)",t).group(1)

        self.ether_addr = re.search("HWaddr ([0-9a-fA-F:]+)", t).group(1)
        #print string.lower(self.ether_addr)
