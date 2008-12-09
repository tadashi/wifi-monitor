#! /usr/bin/env python

import subprocess

class Netperf(object):
    def __init__(self, addr):
        super(Netperf, self).__init__()

        self.addr = addr
        self.sts = 0

    def run(self, cmd, arg):
        #self.sts = subprocess.call([cmd, opt, arg], shell=False)
        self.sts = subprocess.Popen(cmd + " " + arg, shell=True)
        #print "Netperf: '%s %s ' " %  (cmd, arg)

    def status(self):
        if self.sts == 0:
            return 1
        else:
            return 0

