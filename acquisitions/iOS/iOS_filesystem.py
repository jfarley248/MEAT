'''
   Copyright (c) 2019 Jack Farley
   This file is part of MEAT
   Usage or distribution of this software/code is subject to the
   terms of the GNU GENERAL PUBLIC LICENSE.
   iOS_filesystem.py
'''

import sys
import csv
from helpers.system2 import get_serial, hasher
from pymobiledevice2.lockdown import LockdownClient
from pymobiledevice2.afc import AFC2Client




class filesystem(object):

    def __init__(self, output, remoteFolder, md5, sha1, csv_path, logging):
        self.logging = logging or logging.getLogger(__name__)
        self.output = output
        self.remoteFolder = remoteFolder
        self.csv_path = csv_path
        self.md5 = md5
        self.sha1 = sha1

        '''Start Hash CSV handling'''
        if not self.sha1 and not self.md5:
            logging.debug("User has chose not to hash files")
            self.csv_path = None
        self.startAcquisition()

    def startAcquisition(self):

        sn = get_serial(self.logging)
        lockdown = LockdownClient(sn)

        device_found_mes = f"""\n
Device Found!
Device Name: {lockdown.allValues['DeviceName']}
Device Model: {lockdown.allValues['ProductType']}
iOS Version: {lockdown.allValues['ProductVersion']}
Device Build: {lockdown.allValues['BuildVersion']}
WiFi Address: {lockdown.allValues['WiFiAddress']}
Hardware Model: {lockdown.allValues['HardwareModel']}
        """

        self.logging.info(device_found_mes)

        #print(device_found_mes)


        afc2_service = lockdown.startService("com.apple.afc2")
        afc = AFC2Client(lockdown=lockdown)

        self.remoteFolder = self.remoteFolder.replace('\'', '')

        afc.pull_directory(self.remoteFolder, self.output)
        if self.md5 or self.sha1:
            with open(self.csv_path, "w", newline='') as csvfile:
                csvfile_obj = csv.writer(csvfile)
                if self.md5 and self.sha1:
                    csvfile_obj.writerow(["File Name", "Full Path", "MD5", "SHA-1"])
                elif self.md5:
                    csvfile_obj.writerow(["File Name", "Full Path", "MD5"])
                elif self.sha1:
                    csvfile_obj.writerow(["File Name", "Full Path", "SHA-1"])
                hasher(self.output, self.md5, self.sha1, csvfile_obj, self.logging)


