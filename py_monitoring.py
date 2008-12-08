#! /Usr/bin/env python

import sys
import pcap
import string
import time
import socket
import struct
import getopt

from framefilter import FrameFilter
from config import Configure

snr_threshold = 0 # default

SNR = 0
SRC = 1
DST = 2

FILTER = { SNR:False,
           SRC:True,
           DST:True }

try:
   optlist, args = getopt.getopt(sys.argv[1:], "t:m:x:s:d:", 
                                 longopts=["adhoc-interface=", "monitor-interface=", "threshold=",
                                           "src-addr-filter=", "dst-addr-filter="])
except getopt.GetoptError:
   print 'usage: python py_monitoring.py -t <transmit_interface> -m <monitor_interface> -x <snr_threshold> [ -s -1 -d -1 ]'
   sys.exit(0)

for opt, args in optlist:
   if opt in ("-t", "--adhoc-interface"):
      adhoc_interface = args
   if opt in ("-m", "--monitor-interface"):
      monitor_interface = args
   if opt in ("-x", "--threshold"):
      snr_threshold = int(args)
      FILTER[SNR] = True
   if opt in ("-s", "--src-addr-filter"):
      FILTER[SRC] = False
   if opt in ("-d", "--dst-addr-filiter"):
      FILTER[DST] = False


def set_interface(iface, channel):
   cmd = "iwconfig %s channel %i" % (iface, channel)
   
   os.system(cmd)
   print "----> DONE \" %s \"" % cmd


if __name__=='__main__':

    if len(sys.argv) < 2:
       print 'usage: sudo py_monitoring.py -t <transmit_interface> -m <monitor_interface> -x <snr_threshold> [ -s -1 -d -1 ]'
       sys.exit(0)

    working_iface_adhoc = adhoc_interface
    working_iface_monitor = re.compile('0').sub('2', adhoc_interface)
    backup_iface_adhoc = monitor_interface
    backup_iface_monitor = re.compile('1').sub('3', monitor_interface)

    try:
       while 1:
          cf = Configure(working_iface_adhoc, backup_iface_adhoc)
          ff = FrameFilter(cf.ether_addr, cf.channel, snr_threshold, FILTER)
          
          p = pcap.pcapObject()
          p.open_live(backup_iface_monitor, 96, 0, 100)
    
          while ff.rx_frame < 1000:
             apply(ff.filter, p.next())
             #ff.print_rx_filter(monitor_interface)
             ff.print_tx_filter(working_iface_adhoc)

          set_interface(backup_iface_adhoc, cf.next()):

          print "Netperf Starts"
          nf = Netperf()
          nf.run('ping -s 1024 -c 100 -i 0.01 %s' % cf.ip_daddr)
          print "Netperf Ends"

    except KeyboardInterrupt:
       print '%s' % sys.exc_type
       print 'Shutting down'
       print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()
