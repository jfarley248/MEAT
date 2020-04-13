'''
   Copyright (c) 2019 Jack Farley
   This file is part of MEAT
   Usage or distribution of this software/code is subject to the
   terms of the GNU GENERAL PUBLIC LICENSE.
   Android/logical.py
'''

from adb.client import Client as AdbClient
import subprocess
from helpers import system

class androidPhysical(object):
    def __init__(self, output, logging):

        self.device = None
        self.client = None
        self.adb_server = None
        self.output = output
        self.logging = logging or logging.getLogger(__name__)
        self.startAcquisition()


    '''Connect to adb server'''
    def getClient(self):
        client = AdbClient(host="127.0.0.1", port=5037)
        self.client = client


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


    def getMaxPart(self):
        '''Gets a listing of the partitions for the device, also kind of an odd list manipulation...'''
        partitions = self.device.shell("cat /proc/partitions")
        partitions = partitions.split()
        partitions = partitions[4:]
        del partitions[0::4]
        del partitions[0::3]

        self.logging.info("Found the following partitions:")
        for partition in partitions[1::2]:
            self.logging.info(partition)

        '''Turn the sizes of each partition into an int'''
        for partition in partitions[0::2]:
            partitions[partitions.index(partition)] = int(partition)

        '''Whacky way of getting largest partition, the one we want to dd'''
        largest_size = max(partitions[0::2])
        largest_partition = partitions[partitions.index(largest_size) + 1]

        self.logging.info(
            ("The largest partition on the device is {} with a size of {} Kilobytes").format(largest_partition,
                                                                                             largest_size))

        return largest_partition

    def startAdb(self):
        self.logging.debug("Starting ADB Server")
        adb_server = subprocess.Popen(["platform-tools\\adb.exe", "start-server"], stdout=subprocess.PIPE, shell=True)
        adb_msg = adb_server.communicate()
        if len(adb_msg) > 0:
            self.logging.debug("adb_msg is: " + str(adb_msg))
        self.adb_server = adb_server

    def killAdb(self):
        self.logging.debug("Killing ADB Server")
        adb_kill = subprocess.Popen(["platform-tools\\adb.exe", "kill-server"], stdout=subprocess.PIPE, shell=True)
        adb_kill_msg = adb_kill.communicate()
        if len(adb_kill_msg) > 0:
            self.logging.debug("adb_kill_msg is: " + str(adb_kill_msg))

        adb_kill.kill()
        self.adb_server.kill()

    def execute(self, partition):
        file_output = self.output + "\\image2.dd"

        dd_command = "\"dd if=/dev/block/{}\"".format(partition)



        self.logging.info("Starting physical acquisition, this may take a long time...")
        physical_service = subprocess.Popen(["platform-tools\\adb.exe", "shell", "su", "-c", dd_command, ">", file_output],
                                          stdout=subprocess.PIPE, shell=True)
        physical_service.wait()
        physical_msg = physical_service.communicate()
        self.logging.info("Finished physical acquisition")
        if len(physical_msg) > 0:
            self.logging.debug("backup_msg is: " + str(physical_msg))



        self.logging.debug("Killing physical subprocesses")
        try:
            physical_service.kill()
            self.logging.debug("Successfully killed physical subprocess")
        except Exception as ex:
            self.logging.exception("Could not kill physical subprocesses. Exception was: " + str(ex))


    def startAcquisition(self):

        '''Starts ADB Server'''
        self.startAdb()

        '''Runs ADB Client'''
        self.getClient()

        '''Gets the device we want'''
        self.getDevices()

        '''Gets the largest partition on the device'''
        partition = self.getMaxPart()

        '''Kills ADB clients'''
        try:
            self.logging.debug("Trying to kill ADB Clients")
            self.client.kill()
            self.killAdb()
            self.logging.debug("Successfully killed ADB Clients")
        except Exception as ex:
            self.logging.exception("Could not kill ADB Clients. Exception was: " + str(ex))

        '''Executes dd command based on the largets partition'''
        self.execute(partition)
