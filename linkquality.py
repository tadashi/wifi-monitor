#! /usr/bin/env python

import os
import re
import string

#from framfilter import Framefilter

class LinkQuality(object):
    def __init__(self, addr):
        super(LinkQuality, self).__init__()

        # TAG
        self.addr = addr

        self.retry = 0
        self.all = 0
        self.rate = []

    def __repr__(self):
        return "LinkQuality(addr=%s, retry=%u, all=%u, rate=%s)" % (self.addr, self.retry, self.all, self.rate)
    
    def __getitem__(self, idx):
        if idx == 0:
            return self.addr
        if idx == 1:
            return self.retry
        elif idx == 2:
            return self.all
        elif idx == 3:
            return self.rate

    def __setitem__(self, idx, val):
        if idx == 0:
            self.addr = val
        if idx == 1:
            self.retry = val
        elif idx == 2:
            self.all = val
        elif idx == 3:
            self.rate = val

    def __len__(self):
        return 4

    def calculate(self):
        tx_loss = self.retry % self.all
        
        rtetx = 1.0 / ( 1.0 - tx_loss )
        
        return rtetx

    def refresh(self):
        if not (self.all % 1000):
            print "      rt etx  [%s]  : %.2f" % (self.addr, self.calculate())
            self.all = 0
            self.retry = 0
        

