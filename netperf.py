#! /usr/bin/env python

import subprocess

class Netperf(object):
    def __init__(self, addr):
        super(Netperf, self).__init__()

        self.addr = addr
        self.sts = 0

    def run(self, cmd, opt, arg):
        self.sts = subprocess.call([cmd, opt, arg], shell=False)

    def status(self):
        if self.sts == 0:
            return 1
        else:
            return 0

