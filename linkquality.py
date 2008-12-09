#! /usr/bin/env python

import os
import re
import string

from average import WeightedAverage


class LinkQuality(object):
    def __init__(self, addr, min, channel):
        super(LinkQuality, self).__init__()

        # TAG value
        self.addr = addr

        # Local values
        self.channel = channel
        self.snr = WeightedAverage(100, min) # min = snr_threshold
        self.retry = 0
        self.all = 0
        self.rate = []

    def __repr__(self):
        return "LinkQuality(addr=%s, channel=%i, snr=%f, retry=%u, all=%u, rate=%s)" % (self.addr, self.channel, self.snr.emavalue(0.8), self.retry, self.all, self.rate)
    
    def __getitem__(self, idx):
        if idx == 0:
            return self.addr
        if idx == 1:
            return self.channel
        if idx == 2:
            return self.snr
        if idx == 3:
            return self.retry
        elif idx == 4:
            return self.all
        elif idx == 5:
            return self.rate

    def __setitem__(self, idx, val):
        if idx == 0:
            self.addr = val
        if idx == 1:
            self.channel = val
        if idx == 2:
            self.snr = val
        if idx == 3:
            self.retry = val
        elif idx == 4:
            self.all = val
        elif idx == 5:
            self.rate = val

    def __len__(self):
        return 6

    def calculate(self):
        try:
            tx_loss = float(self.retry) / self.all
            rtetx = 1.0 / ( 1.0 - tx_loss )

            return rtetx

        except ZeroDivisionError:
            return 0.0        


    def refresh(self):
        #if not (self.all % 1):
        if self.all > 80:
            print "      rt etx  [%s]  : %.2f" % (self.addr, self.calculate())
            self.all = 0
            self.retry = 0

            return 1

        return 0

