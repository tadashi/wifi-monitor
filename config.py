#! /usr/bin/env python

import os
import re
import string

FREQ_11g = {
    '2.412' : 1,
    '2.417' : 2,
    '2.422' : 3,
    '2.427' : 4,
    '2.432' : 5,
    '2.437' : 6,
    '2.442' : 7,
    '2.447' : 8,
    '2.452' : 9,
    '2.457' : 10,
    '2.462' : 11
    }

FREQ_11a = {
    '5.18' : 36,
    '5.2'  : 40,
    '5.21' : 42,
    '5.22' : 44,
    '5.24' : 48,
    '5.25' : 50,
    '5.26' : 52,
    '5.28' : 56,
    '5.29' : 58,
    '5.3'  : 60,
    '5.32' : 64,
    '5.745' : 149,
    '5.76'  : 152,
    '5.765' : 153,
    '5.785' : 157,
    '5.8'   : 160,
    '5.805' : 161,
    '5.825' : 165
    }

FREQ = FREQ_11g + FREQ_11a

class Configure(object):
    def __init__(self, aiface, miface):
        super(Configure, self).__init__()

        # Ad-hoc interface
        self.ip_addr, self.ether_addr = self.get_addr(aiface)

        # Monitor interface
        self.channel = self.get_channel(miface)
        self.ip_daddr = self.get_daddr(self.channel)

    def get_addr(self, int):
        
        p = os.popen("/sbin/ifconfig %s" % int)
        t = p.read()
        p.close()
        
        ether_addr = string.lower(re.search("HWaddr ([0-9a-fA-F:]+)", t).group(1))
        ip_addr =  re.search("inet addr:([0-9.]+)",t).group(1)

        print "Monitoring Address : MAC[%s], IP[%s]" % (string.lower(ether_addr), string.lower(ip_addr))

        return ip_addr, ether_addr

    def get_channel(self, int):
        p = os.popen("/sbin/iwconfig %s" % int)
        t = p.read()
        p.close()

        tmp_channel = string.lower(re.search("Frequency:([0-9].[0-9]+)", t).group(1))
        channel = FREQ[tmp_channel]

        print "Monitoring Frequency: Channel %i : %s GHz" % (channel, tmp_channel)

        return channel

    def get_daddr(self, channel):
        if channel = 40:
            return '192.168.4.4'

        elif channel = 60:
            return '192.168.6.5'


    def next(self):
        # 11b/g
        if self.channel < 11:
            self.channel = self.channel + 5
            return self.channel + 5
        elif self.channel == 11:
            self.channel = 1
            return 1

        # 11a
        elif self.channel > 36 and self.channel < 64:
            self.channel = self.channel + 4
            return self.channel + 4
        elif self.channel == 64:
            self.channel = 36
            return 36
    
        else:
            self.channel 1
            return 1
