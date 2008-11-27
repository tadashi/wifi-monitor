#! /usr/bin/env python

import sys
import pcap
import string
import time
import socket
import struct
import getopt

from framefilter import FrameFilter

MY_ADDRESS = '0e:0a:79:72:f1:32' # SHOULD be got from system call

SNR = 0
SRC = 1
DST = 2

FILTER = { SNR:False,
           SRC:False,
           DST:False }

try:
   optlist, args = getopt.getopt(sys.argv[1:], "i:t:d:s:", longopts=["interface=", "threshold=", "src-addr=", "dst-addr="])
except getopt.GetoptError:
   sys.exit(0)

for opt, args in optlist:
   if opt in ("-i", "--interface"):
       interface = args
   if opt in ("-t", "--threshold"):
       snr_threshold = int(args)
       FILTER[SNR] = True
   if opt in ("-s", "--src-addr"):
       src_addr = args
       FILTER[SRC] = True
   if opt in ("-d", "--dst-addr"):
       dst_addr = args
       FILTER[DST] = True

if __name__=='__main__':

    if len(sys.argv) < 2:
        print 'usage: monitoring_py.py -i <interface> [-s <src_address> -d <dst_address> -t <SNR_theshold> ]'
        sys.exit(0)

    ff = FrameFilter(MY_ADDRESS, snr_threshold, FILTER)
    p = pcap.pcapObject()

    #dev = pcap.lookupdev()
    dev = interface
    #net, mask = pcap.lookupnet(dev)

    # note:    to_ms does nothing on linux
    p.open_live(dev, 96, 0, 100)
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
            apply(ff.filter, p.next())
            ff.print_rx_filter(dev)
            ff.print_tx_filter(dev)

    except KeyboardInterrupt:
        print '%s' % sys.exc_type
        print 'shutting down'
        print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()
