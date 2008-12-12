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
        self.lq = 10.0

        # Local values
        self.channel = channel
        self.snr = WeightedAverage(100, min) # min = snr_threshold
        self.retry = 0
        self.all = 0
        self.rate = []
        self.rtetx = {}
        self.rtetx2 = []

    def __repr__(self):
        return "LinkQuality(addr=%s, lq=%f, channel=%i, snr=%f, retry=%u, all=%u, rate=%s, rtetx=%s, rtetx=%s)" % (self.addr, self.lq, self.channel, self.snr.emavalue(0.8), self.retry, self.all, self.rate, self.rtetx, self.rtetx2)
    
    def __getitem__(self, idx):
        if idx == 0:
            return self.addr
        if idx == 1:
            return self.lq
        if idx == 2:
            return self.channel
        if idx == 3:
            return self.snr
        if idx == 4:
            return self.retry
        elif idx == 5:
            return self.all
        elif idx == 6:
            return self.rate
        elif idx == 7:
            return self.rtetx
        elif idx == 8:
            return self.rtetx2

    def __setitem__(self, idx, val):
        if idx == 0:
            self.addr = val
        if idx == 1:
            self.lq = val
        if idx == 2:
            self.channel = val
        if idx == 3:
            self.snr = val
        if idx == 4:
            self.retry = val
        elif idx == 5:
            self.all = val
        elif idx == 6:
            self.rate = val
        elif idx == 7:
            self.rtetx = val
        elif idx == 8:
            self.rtetx2 = val

    def __len__(self):
        return 9

    def calculate(self, timestamp, rtt):
        try:
            tx_loss = float(self.retry) / self.all
            tmp_rtetx = 1.0 / ( 1.0 - tx_loss )

            self.rtetx[timestamp] = [ tmp_rtetx, rtt ]
            self.lq = tmp_rtetx

            self.rtetx2.append([timestamp, tmp_rtetx])

            return tmp_rtetx

        except ZeroDivisionError:
            return 1.0


    def refresh(self, timestamp, rtt):
        #print "rtt", rtt
        if self.all > 200: # Data frames = same as ff.tx_frame
            print "      rtETX [%s]  : %.2f, rtt : %.2f" % (self.addr, self.calculate(timestamp, rtt), rtt)
            self.all = 0
            self.retry = 0

            return 1

        return 0
