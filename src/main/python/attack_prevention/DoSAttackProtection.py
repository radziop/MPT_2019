#!/usr/bin/env python

import logging
from ..PythonServer import PacketStreamerHandler


class DoSAttackProtection(object):

    def __init__(self):
        self.logger = PacketStreamerHandler.log