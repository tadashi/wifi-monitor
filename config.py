#! /usr/bin/env python

import os
import re
import string

from ap import AP

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

# From the view point of Robooc6
Robohoc4 = AP(40, '192.168.4.6', '192.168.4.4', '192.168.100.4', '00:80:92:3e:18:11')
Robohoc5 = AP(60, '192.168.6.6', '192.168.6.5', '192.168.100.5', '00:80:92:3d:45:df')
Robohoc = [ Robohoc4, Robohoc5 ]

class Configure(object):
    def __init__(self, aiface, miface):
        super(Configure, self).__init__()

        # Ad-hoc interface
        self.ip_aaddr, self.ether_aaddr = self.info_addr(aiface)

        # Monitor interface
        self.ip_maddr, self.ether_maddr = self.info_addr(miface)
        self.channel = self.get_channel(miface)
        self.ip_saddr, self.ip_daddr, self.ether_daddr = self.get_addr(self.channel) # Static info
        
        # Overlay interface
        self.vip_daddr = ''

    def info_addr(self, int):
        
        p = os.popen("/sbin/ifconfig %s" % int)
        t = p.read()
        p.close()
        
        ether_addr = string.lower(re.search("HWaddr ([0-9a-fA-F:]+)", t).group(1))
        ip_addr =  re.search("inet addr:([0-9.]+)",t).group(1)

        print "Interface : MAC[%s], IP[%s]" % (string.lower(ether_addr), string.lower(ip_addr))

        return ip_addr, ether_addr

    def get_channel(self, int):
        p = os.popen("/sbin/iwconfig %s" % int)
        t = p.read()
        p.close()

        tmp_channel = str(re.search("Frequency:([0-9].[0-9]+)", t).group(1))
        channel = FREQ_11a[tmp_channel]

        print "Monitoring Frequency: Channel %i : %s GHz" % (channel, tmp_channel)

        return channel

    def get_addr(self, channel):
        if channel == Robohoc4.ch:
            return Robohoc4.sip, Robohoc4.dip, Robohoc4.dether

        elif channel == Robohoc5.ch:
            return Robohoc5.sip, Robohoc5.dip, Robohoc5.dether

        else:
            print "WARNING: "

    def next(self):
        if self.channel == Robohoc4.ch:
            self.channel = Robohoc5.ch
            self.ip_saddr = Robohoc5.sip
            self.ip_daddr = Robohoc5.dip
            self.ether_daddr = Robohoc5.dether
            self.vip_daddr = Robohoc5.dcip

        elif self.channel == Robohoc5.ch:
            self.channel = Robohoc4.ch
            self.ip_saddr = Robohoc4.sip
            self.ip_daddr = Robohoc4.dip
            self.ether_daddr = Robohoc4.dether
            self.vip_daddr = Robohoc4.dcip

        else:
            print "WARNING: "
