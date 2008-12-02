#! /usr/bin/env python

import sys
import pcap
import string
import time
import socket
import struct
import getopt

from average import WeightedAverage

## Necesarry Filters
SNR = 0
SRC = 1
DST = 2

##
# RX frame                               TX frame                             
# <------- Radiotap -------->            <------- Radiotap -------->            
# |                         |            |                         |          
# +----+----+----+----------+---//---+   +----+----+----+----------+---//---+ 
# |    |    |    |          |        |   |    |    |    |          |        | 
# | 00 | 00 | 1a | ........ |   aa   |   | 00 | 00 | 17 | ........ |   bb   | 
# |    |    |    |          |        |   |    |    |    |          |        | 
# +----+----+----+----------+---//---+   +----+----+----+----------+---//---+ 
#             ^                                      ^                        
#             |                                      |                        
#             +--- length = 26                       +--- length = 23         
#
# bit 'aa' = bit 'bb' << 3
# then, OFFSET = 3
##

#### 802.11a bitrate/modulation
DATARATE_11a = [6.0, 9.0, 12.0, 18.0, 24.0, 36.0, 48.0, 54.0]
DATARATE_11g = [1.0, 2.0, 5.5, 11.0] + DATARATE_11a

#### Radiotap Header
DATARATE = 17
CHANNEL_FREQ = 18 # 18, 19
SSISIGNAL = 25

RADIOTAP_RX = { 
   DATARATE:DATARATE,
   CHANNEL_FREQ:CHANNEL_FREQ,
   SSISIGNAL:SSISIGNAL
   }

RADIOTAP_TX = { 
   DATARATE:DATARATE 
   }
             

#### IEEE 802.11 MAC Header
OFFSET = 3

## Bit number in RX frame
SUBTYPE = 26
RETRY_FLAG = 27
DST_ADDR = 30 # 30 - 35
SRC_ADDR = 36 # 36 - 41
BSSID = 42 # 42 - 47

IEEE_DATA_RX = { 
   SUBTYPE:SUBTYPE,
   RETRY_FLAG:RETRY_FLAG,
   DST_ADDR:DST_ADDR,
   SRC_ADDR:SRC_ADDR,
   BSSID:BSSID 
   }

IEEE_DATA_TX = { 
   SUBTYPE:SUBTYPE - OFFSET,
   RETRY_FLAG:RETRY_FLAG - OFFSET,
   DST_ADDR:DST_ADDR - OFFSET,
   SRC_ADDR:SRC_ADDR - OFFSET,
   BSSID:BSSID - OFFSET
   }

RX = { 
   SRC_ADDR:IEEE_DATA_RX[SRC_ADDR],
   DST_ADDR:IEEE_DATA_RX[DST_ADDR],
   SSISIGNAL:RADIOTAP_RX[SSISIGNAL],
   SUBTYPE:IEEE_DATA_RX[SUBTYPE],
   DATARATE:RADIOTAP_RX[DATARATE],
   RETRY_FLAG:IEEE_DATA_RX[RETRY_FLAG]
   }

TX = {
   SRC_ADDR:IEEE_DATA_TX[SRC_ADDR],
   DST_ADDR:IEEE_DATA_TX[DST_ADDR],
   SUBTYPE:IEEE_DATA_TX[SUBTYPE],
   DATARATE:RADIOTAP_TX[DATARATE],
   RETRY_FLAG:IEEE_DATA_TX[RETRY_FLAG]
   }

### Class FrameFilter
##--------------------------------------------------------------------------
## FUNCTION  : 
## PURPOSE   : 
## ARGUMENTS : 
## RETURN    : 
## External Library : 
##--------------------------------------------------------------------------
class FrameFilter(object):
    def __init__(self, maddr, daddr, th, ft):
        super(FrameFilter, self).__init__()

        # Global Values
        self.ft = ft
        self.th = th
        self.maddr = maddr
        self.dst_addr = daddr

        self.addr_snr = {}
        self.addr_retry = {}

        self.rx_frame = 0
        self.tx_frame = 0

        self.rate = []
        self.rt = 0

    def set_rules(self, rule):
        """docstring for set_rules"""
        self.rules.append(rule)

    def dump_hex(self, raw):
        return map(lambda x: '%.2x' % x, map(ord, raw))

    def filter_data(self, bytes, key):
        if bytes[key[SUBTYPE]] == '08':
            return 1
        
        else:
            #print "FRAME is NOT DATA"
            return 0

    def filter_src_addr(self, bytes, saddr, key):
        tmp_addr = string.join(bytes[key[SRC_ADDR]:key[SRC_ADDR] + 6], ':')
        if cmp(tmp_addr, saddr) == 0:
            return 1

        else:
            return 0

    def filter_dst_addr(self, bytes, daddr, key):
        tmp_addr = string.join(bytes[key[DST_ADDR]:key[DST_ADDR] + 6], ':')
        if cmp(tmp_addr, daddr) == 0:
            return 1

        else:
            return 0

    def filter_bitrate(self, bytes, key):
        tmp_rate = string.atoi(bytes[key[DATARATE]], 16) / 2.0
        #print tmp_rate, string.atoi(bytes[key[DATARATE]], 16)
        if tmp_rate not in DATARATE_11g:
            #print "DATARATE is UNKNOWN"
            return 0
        
        else:
            self.rate.append(tmp_rate)
            return 1

    def filter_snr(self, bytes, key):
        tmp_snr = int(string.atoi(bytes[key[SSISIGNAL]], 16))
        self.push_snr(tmp_snr, self.get_src_addr(bytes, key))
        if tmp_snr > self.th:
            return 1

        else:
            #print "FILTERD by SNR"
            return 0

        return 1

    def push_snr(self, snr, saddr):
        self.addr_snr[saddr].push(snr)

    def get_src_addr(self, bytes, key):
        tmp_addr = string.join(bytes[key[SRC_ADDR]:key[SRC_ADDR] + 6], ':')
        if not self.addr_snr.has_key(tmp_addr):
            self.addr_snr[tmp_addr] = WeightedAverage(100, 0)
            print "received addresses with snr: ", self.addr_snr

        return tmp_addr

    def filter_retry_count(self, bytes, key):
        #print "addr_snr", self.addr_snr
        tmp_addr = string.join(bytes[key[DST_ADDR]:key[DST_ADDR] + 6], ':')
        print bytes[key[RETRY_FLAG]], int(bytes[key[RETRY_FLAG]], 16)

        if int(bytes[key[RETRY_FLAG]], 16) & 0x08 == 8:
            self.push_retry_count(tmp_addr)
            return 1

        else:
            #print "FRAME is not retransmitted"
            return 0


    def push_retry_count(self, addr):
        if not self.addr_retry.has_key(addr): # First time
            self.addr_retry[addr] = 0
            return self.addr_retry[addr] # 0

        else:
            self.addr_retry[addr] += 1
            return self.addr_retry[addr]

    def print_rx_filter(self, int):
        #print self.rate
        #print self.rx_frame

        if not (self.rx_frame % 1000):
            print "%s: monitoring RX frame [%u]" % (int, self.rx_frame)
            #print self.addr_snr
            for saddr in self.addr_snr:
                #print self.addr_snr[saddr].emavalues
                #print self.addr_snr[saddr].values
                print "      EMA SNR[%s]  : %f" % (saddr, self.addr_snr[saddr].emavalue(0.8))

    def print_tx_filter(self, int):
        #print self.rate
        #print self.tx_frame

        if not (self.tx_frame % 1000):
            print "%s: monitoring TX frame [%u]" % (int, self.tx_frame)
            #print self.addr_snr

            for daddr in self.addr_retry:
                print "      rt count[%s]  : %i" % (daddr, self.addr_retry[daddr])
            
            print "      8 available bit-rates"
            for rate in DATARATE_11a:
                print "            %.1f Mb/s  : %i" % (rate, self.rate.count(rate))


    def filter_rx(self, raw):
        """docstring for filter_rx"""
        self.rx_frame += 1
        bytes = self.dump_hex(raw)
        
        if self.filter_data(bytes, RX):
            #if self.ft[DST]:  # When packets are sent to this node
            if 0: # promiscous
                if not self.filter_dst_addr(bytes, self.maddr, RX):
                    return 0

            if self.ft[SNR]:
                if not self.filter_snr(bytes, RX):
                    return 0
        
            return 1


    def filter_tx(self, raw):
        """docstring for filter_tx"""
        self.tx_frame += 1
        bytes = self.dump_hex(raw)
        
        if self.filter_data(bytes, RX):
            if self.ft[SRC]: # When packets are send by this node
                if not self.filter_src_addr(bytes, self.maddr, RX):
                    return 0
                
            if self.ft[DST]:
                if not self.filter_dst_addr(bytes, self.dst_addr, RX):
                    return 0

            if self.filter_bitrate(bytes, RX):
                if self.filter_retry_count(bytes, RX):
                    pass

            return 1


    def filter(self, pktlen, raw, timestamp):
        """docstring for filter"""

        self.filter_rx(raw)
        self.filter_tx(raw)
