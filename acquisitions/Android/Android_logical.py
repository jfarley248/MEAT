'''
   Copyright (c) 2019 Jack Farley
   This file is part of MEAT
   Usage or distribution of this software/code is subject to the
   terms of the GNU GENERAL PUBLIC LICENSE.
   Android/logical.py
'''

from helpers.adb import adb_commands
from helpers.adb import sign_cryptography

import sys
import time
import os
import adbe
import subprocess
from helpers import system

class androidLogical(object):
    def __init__(self, output, remoteFolder, logging):

        self.device = None
        self.client = None
        self.adb_server = None
        self.output = output
        self.remoteFolder = remoteFolder
        self.logging = logging or logging.getLogger(__name__)
        self.startAcquisition()


    '''Connect to adb server'''
    def getClient(self):
        client = AdbClient(host="127.0.0.1", port=5037)

        self.client = client

        x = client.version()
        y = self.client.version()

        z = 0

    '''Connect to device'''
    def getDevices(self):
        devices = self.client.devices()
        if len(devices) > 1:
            self.logging.error(
                "More than one device connected. Please only attach device that is going to be acquisitioned")
            system.exitProgram()
        if devices is None or len(devices) == 0:
            self.logging.error(
                "No device connected. Please attach device that is going to be acquisitioned")
            system.exitProgram()

        self.device = devices[0]



    def startAcquisition(self):


        '''Uses getClient to connect to ADB server'''
        self.logging.info("Attempting to connect to ADB server")
        try:
            self.getClient()
            self.logging.info("Successfully connected to ADB server")
        except Exception as ex:
            self.logging.exception("Could not connect to ADB server. Exception was: " + str(ex))

        
        self.logging.info("Finding Devices")
        try:
            self.getDevices()
            self.logging.info("Successfully found device: " + self.device.serial)
        except Exception as ex:
            self.logging.exception("Could not connect to device. Exception was: " + str(ex))


        x = self.device.pull("/", self.output)
        v=0
