'''
   Copyright (c) 2020 BlackStone Discovery
   This file is part of MEAT
   Usage or distribution of this software/code is subject to the
   terms of the GNU GENERAL PUBLIC LICENSE.
   iOS_backup.py
'''

from pymobiledevice2.usbmux.usbmux import USBMux
from pymobiledevice2.lockdown import LockdownClient
from pymobiledevice2.mobilebackup2 import MobileBackup2

def get_serial():
    mux = USBMux()
    if not mux.devices:
        mux.process(0.1)
    sn = mux.devices[0].serial
    return sn


class backup(object):

    def __init__(self, output, logging, password = None):
        self.logging = logging or logging.getLogger(__name__)
        self.output = output
        self.startAcquisition()

    def startAcquisition(self):

        sn = get_serial()
        lockdown_object = LockdownClient(sn)
        backup_object = MobileBackup2(udid=sn, logger=self.logging, backupPath=self.output)
        backup_object.backup()
        x = 0