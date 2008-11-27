#! /usr/bin/env python

import sys
import pcap
import string
import time
import socket
import struct
import getopt

import WeightedAverge from average

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
    def __init__(self, maddr, saddr, daddr):
        super(FrameFilter, self).__init__()

        self.maddr = maddr
        self.saddr = saddr
        self.daddr = daddr

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
            print "FRAME is NOT DATA"
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
        tmp_rate = string.atof(bytes[key[DATARATE]], 16) / 2.0
        if tmp_rate not in DATARATE_11g:
            print "DATARATE is UNKNOW"
            return 0
        
        else:
            self.rate.append(tmp_rate)
            return 1

    def filter_snr(self, bytes, key):
        tmp_snr = int(string.atoi(bytes[key[SSISIGNAL]], 16))
        self.push_snr(tmp_snr, self.get_src_addr(bytes))
        if tmp_snr > snr_threshold:
            return 1

        else:
            print "FILTERD by SNR"
            return 0

        return 1

    def push_snr(self, bytes, saddr):
        self.snr[saddr].emapush(int(string.atoi(bytes[key[SSISIGNAL]], 16)))

    def get_src_addr(self, bytes):
        tmp_addr = string.join(bytes[key[SRC_ADDR]:key[SRC_ADDR] + 6], ':')
        if not self.addr_snr.has_key(tmp_addr):
            self.addr_snr[tmp_addr] = WeightedAverage(100, 0)
            print "received addresses with snr: ", self.ff.addr_snr

        return tmp_addr

    def get_retry_count(self, bytes, key):
        tmp_addr = string.join(bytes[key[SRC_ADDR]:key[SRC_ADDR] + 6], ':')
        if bytes[key[RETRY_FLAG]] & 0x08 == 8:
            if self.addr_snr.has_key(tmp_addr):
                self.addr_retry[tmp_addr] += 1
                return self.add_retry[tmp_addr]

        else:
            print "FRAME is retransmitted"
            return 0

    def print_rx_filter(self):
        #print self.rate
        #print self.rx_frame

        if not (self.rx_frame % 100):
            print "%s monitoring" % interface
            print "      average snr           : %f" % self.snr.emavalue(0.8)
            print "      retransmission count  : %i" % self.rt
            
            print "      8 available bit-rates :"
            for rate in ['6.0', '9.0', '12.0', '18.0', '24.0', '36.0', '48.0', '54.0']: # 11a
                print "            %s Mb/s : %i" % (rate, self.rate.count(float(rate)))
