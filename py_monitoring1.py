#! /usr/bin/env python

import sys
import pcap
import string
import time
import socket
import struct
import getopt

import average

SNR_FILTER = 0
SRC_FILTER = 1
DST_FILTER = 2

FILTER = { SNR_FILTER:False,
           SRC_FILTER:False,
           DST_FILTER:False }

try:
   optlist, args = getopt.getopt(sys.argv[1:], "i:t:d:s:", longopts=["interface=", "threshold=", "src-addr=", "dst-addr="])
except getopt.GetoptError:
   sys.exit(0)

for opt, args in optlist:
   if opt in ("-i", "--interface"):
       interface = args
   if opt in ("-t", "--threshold"):
       snr_threshold = int(args)
       FILTER[SNR_FILTER] = True
   if opt in ("-s", "--src-addr"):
       src_addr = args
       FILTER[SRC_FILTER] = True
   if opt in ("-d", "--dst-addr"):
       dst_addr = args
       FILTER[DST_FILTER] = True

protocols = { socket.IPPROTO_TCP:'tcp',
              socket.IPPROTO_UDP:'udp',
              socket.IPPROTO_ICMP:'icmp'}

BITRATE = 17
CHANNEL_FREQ = 18 # 18, 19
SSISIGNAL = 25

RADIOTAP = { BITRATE:BITRATE,
             CHANNEL_FREQ:CHANNEL_FREQ,
             SSISIGNAL:SSISIGNAL}

SUBTYPE = 26
RETRY_FLAG = 27
DST_ADDR = 30 # 30 - 35
SRC_ADDR = 36 # 36 - 41
BSSID = 42 # 42 - 47

IEEE_DATA = { SUBTYPE:SUBTYPE,
              RETRY_FLAG:RETRY_FLAG,
              DST_ADDR:DST_ADDR,
              SRC_ADDR:SRC_ADDR,
              BSSID:BSSID}

RX = { SRC_ADDR:IEEE_DATA[SRC_ADDR],
       DST_ADDR:IEEE_DATA[DST_ADDR],
       SSISIGNAL:RADIOTAP[SSISIGNAL],
       SUBTYPE:IEEE_DATA[SUBTYPE],
       BITRATE:RADIOTAP[BITRATE],
       RETRY_FLAG:IEEE_DATA[RETRY_FLAG]}

##### FROME HERE, CLASS DEFINITION
class FrameFilter(object):
    def __init__(self, average):
        super(FrameFilter, self).__init__()
        
        self.rx_frame = 0
        self.tx_frame = 0
        self.rate = []
        self.rt = 0
        self.snr = average

    def set_rules(self, rule):
        """docstring for set_rules"""
        self.rules.append(rule)

    def dump_hex(self, raw):
        return map(lambda x: '%.2x' % x, map(ord, raw))

    def filter_data(self, bytes):
        if bytes[IEEE_DATA[SUBTYPE]] == '08':
            return 1
        
        else:
            #print "FRAME is NOT DATA"
            return 0


    def filter_src_addr(self, bytes, saddr):
        if FILTER[SRC_FILTER]:
            if cmp(string.join(bytes[RX[SRC_ADDR]:RX[SRC_ADDR] + 6], ':'), saddr) == 0:
                return 1

            else:
                print "FILTERD by SRC_ADDR"
                return 0
        
        return 1

    def filter_dst_addr(self, bytes, daddr):
        if FILTER[DST_FILTER]:
            if cmp(string.join(bytes[RX[DST_ADDR]:RX[DST_ADDR] + 6], ':'), daddr) == 0:
                return 1

            else:
                print "FILTERD by DST_ADDR"
                return 0

        return 1

    def filter_snr(self, bytes):
        if FILTER[SNR_FILTER]:
            if int(string.atoi(bytes[RX[SSISIGNAL]], 16)) > snr_threshold:
                self.snr.emapush(int(string.atoi(bytes[RX[SSISIGNAL]], 16)))
                return 1

            else:
                print "FILTERD by SNR"
                return 0

        return 1

    def filter_bitrate(self, bytes):
        if string.atoi(bytes[RX[BITRATE]], 16) / 2.0 == 0:
            print "BITRATE is UNKNOW"
            return 0

        else:
            self.rate.append(string.atoi(bytes[RX[BITRATE]], 16) / 2.0)
            return 1

    def get_retry_count(self, raw):
        if ord(raw[RX[RETRY_FLAG]]) & 0x08 == 8:
            print "FRAME is retransmitted"
            self.rt += 1

    def filter_rx(self, paketlen, raw, timestamp):
        """docstring for filter_rx"""

        self.rx_frame += 1
        bytes = self.dump_hex(raw)

        if self.filter_data(bytes):
            if self.filter_src_addr(bytes):
                if self.filter_dst_addr(bytes):
                    if self.filter_snr(bytes):
                        if self.filter_bitrate(bytes):
                            self.get_retry_count(raw)

    def filter_tx(self, raw):
        """docstring for filter_tx"""
        
        self.tx_frame += 1
        bytes = self.dump_hex(raw)
        
        if self.filter_data(bytes):
            if self.filter_src_addr(bytes):
                if self.filter_dst_addr(bytes):
                    if self.filter_snr(bytes):
                        if self.filter_bitrate(bytes):
                            self.get_retry_count(raw)
    
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

##--------------------------------------------------------------------------
## FUNCTION  : decode_ip_packet, dumphex, print_ip_packet
## PURPOSE   : capture and print TCP, UDP, ICMP packets
## ARGUMENTS : 
## RETURN    : 
## External Library : pcap
##--------------------------------------------------------------------------
def decode_ip_packet(s):
    d={}
    d['version']=(ord(s[0]) & 0xf0) >> 4
    d['header_len']=ord(s[0]) & 0x0f
    d['tos']=ord(s[1])
    d['total_len']=socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['id']=socket.ntohs(struct.unpack('H',s[4:6])[0])
    d['flags']=(ord(s[6]) & 0xe0) >> 5
    d['fragment_offset']=socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
    d['ttl']=ord(s[8])
    d['protocol']=ord(s[9])
    d['checksum']=socket.ntohs(struct.unpack('H',s[10:12])[0])
    d['source_address']=pcap.ntoa(struct.unpack('i',s[12:16])[0])
    d['destination_address']=pcap.ntoa(struct.unpack('i',s[16:20])[0])
    if d['header_len']>5:
        d['options']=s[20:4*(d['header_len']-5)]
    else:
        d['options']=None
    d['data']=s[4*d['header_len']:]
    return d


def dumphex(s):
    bytes = map(lambda x: '%.2x' % x, map(ord, s))
    for i in xrange(0,len(bytes)/16):
        print '        %s' % string.join(bytes[i*16:(i+1)*16],' ')
    print '        %s' % string.join(bytes[(i+1)*16:],' ')
        

def print_packet(pktlen, data, timestamp):
    if not data:
        return

    if data[12:14]=='\x08\x00':
        decoded=decode_ip_packet(data[14:])
        print '\n%s.%f %s > %s' % (time.strftime('%H:%M',
                                time.localtime(timestamp)),
                                timestamp % 60,
                                decoded['source_address'],
                                decoded['destination_address'])
        for key in ['version', 'header_len', 'tos', 'total_len', 'id',
                                'flags', 'fragment_offset', 'ttl']:
            print '    %s: %d' % (key, decoded[key])
        print '    protocol: %s' % protocols[decoded['protocol']]
        print '    header checksum: %d' % decoded['checksum']
        print '    data:'
        dumphex(decoded['data'])
 

if __name__=='__main__':

    if len(sys.argv) < 2:
        print 'usage: monitoring_py.py -i <interface> [-s <src_address> -d <dst_address> -t <SNR_theshold> ]'
        sys.exit(0)

    a = average.WeightedAverage(100, 40)
    f = FrameFilter(a)
    p = pcap.pcapObject()

    #dev = pcap.lookupdev()
    dev = interface
    #net, mask = pcap.lookupnet(dev)

    # note:    to_ms does nothing on linux
    p.open_live(dev, 1600, 0, 100)
    #p.dump_open('dumpfile')

    #p.setfilter(string.join(sys.argv[2:],' '), 0, 0)
    
    # try-except block to catch keyboard interrupt.    Failure to shut
    # down cleanly can result in the interface not being taken out of promisc.
    # mode
    #p.setnonblock(1)
    try:
        while 1:
        #    p.dispatch(1, print_packet)

        # specify 'None' to dump to dumpfile, assuming you have called
        # the dump_open method
        #    p.dispatch(0, None)

        # the loop method is another way of doing things
        #    p.loop(1, print_packet)
            #p.loop(1, f.filter_rx)

        # as is the next() method
        # p.next() returns a (pktlen, data, timestamp) tuple 
            apply(f.filter_rx,p.next())
            f.print_rx_filter()

    except KeyboardInterrupt:
        print '%s' % sys.exc_type
        print 'shutting down'
        print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()
