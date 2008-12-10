#! /Usr/bin/env python

import os
import re
import sys
import pcap
import string
import time
import socket
import struct
import getopt

from framefilter import FrameFilter
from config import Configure
from netperf import Netperf

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

def set_interface(iface, cf):
   if cf.ip_aaddr != cf.ip_saddr:
      cmd = "iwconfig %s channel %i && ifconfig %s %s down up" % (iface, cf.channel, iface, cf.ip_saddr)
      os.system(cmd)
      print "----> DONE \" %s \"" % cmd

   else:
      cmd = "iwconfig %s channel %i" % (iface, cf.channel)
      os.system(cmd)
      print "----> DONE \" %s \"" % cmd

if __name__=='__main__':

    if len(sys.argv) < 2:
       print 'usage: sudo py_monitoring.py -t <transmit_interface> -m <monitor_interface> -x <snr_threshold> [ -s -1 -d -1 ]'
       sys.exit(0)

    working_iface_adhoc = adhoc_interface
    working_iface_monitor = re.compile('[0-1]').sub('2', adhoc_interface)
    backup_iface_adhoc = monitor_interface
    backup_iface_monitor = re.compile('[0-1]').sub('3', monitor_interface)
    print "Interfaces: [wa: %s] [wm: %s] [ba: %s] [bm: %s]" % (working_iface_adhoc, working_iface_monitor, backup_iface_adhoc, backup_iface_monitor)

    cf = Configure(working_iface_adhoc, backup_iface_adhoc)
    ff = FrameFilter(cf, snr_threshold, FILTER)
    p = pcap.pcapObject()
    p.open_live(backup_iface_monitor, 96, 0, 100)

    try:
       while 1:
          while ff.rx_frame < 101: # Only beacon frames counted
             apply(ff.filter, p.next())
             #ff.print_rx_filter(backup_iface_monitor)
             ff.print_tx_filter(working_iface_adhoc) # maybe 1s

          # Initialization
          print "cf.ether_daddr", cf.ether_daddr
          current_lq = ff.addr_lq[cf.ether_daddr].lq # rtetx of scanned neighbor host
          ff.rx_frame = 0 # RX frame count set 0 for next channel
          ff.tx_frame = 0 # TX frame count set 0 for next channel
          cf.next() # Configuration for next channel
          set_interface(backup_iface_adhoc, cf) # Setup interface for next channel

          # Algorithm 2
          if ff.is_higher(cf.ether_daddr):
             print "Netperf Starts "
             #nf = Netperf(cf.ip_daddr)
             #nf.run('ping', '-q -s 1024 -c 100 -i 0.01 %s > /dev/null' % cf.ip_daddr)
             nf.run('netperf', '-l 1 -H %s > /dev/null' % cf.ip_daddr) # 0s
             print "Netperf Ends"

          try:
             previous_lq = ff.addr_lq[cf.ether_daddr].lq
             print "cur %f, pre %f" % (current_lq, previous_lq)
             if current_lq + 0.1 < previous_lq: # previous rtetx of counterpart
                print "HANDOVER WILL BE CONDUCTED HERE"

          except KeyError:
             print "FIRST TIME"

    except KeyboardInterrupt:
       print '%s' % sys.exc_type
       print 'Shutting down'
       print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()

       print "ff.frame : %i [frame]" % ff.frame
       print "ff.rx_frame : %i [frame]" % ff.rx_frame

       for daddr in ff.addr_lq:
          #print ff.addr_lq[daddr]
          print "Robohoc [%s] %s" % (daddr, ff.addr_lq[daddr].rtetx)
