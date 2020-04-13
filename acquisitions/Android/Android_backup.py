'''
   Copyright (c) 2019 Jack Farley
   This file is part of MEAT
   Usage or distribution of this software/code is subject to the
   terms of the GNU GENERAL PUBLIC LICENSE.
   Android/logical.py
'''

import subprocess

class androidBackup(object):
    def __init__(self, output, logging):

        self.output = output
        self.logging = logging or logging.getLogger(__name__)
        self.startAcquisition()



    def startAcquisition(self):

        file_output = self.output + "\\backup.ab"

        self.logging.debug("Starting ADB Server")
        adb_server = subprocess.Popen(["platform-tools\\adb.exe", "start-server"], stdout=subprocess.PIPE, shell=True)
        adb_msg = adb_server.communicate()
        self.logging.debug("adb_msg is: " + str(adb_msg))

        self.logging.info("Starting backup, please follow prompts on device...")
        backup_service = subprocess.Popen(["platform-tools\\adb.exe", "backup", "-all", "-f", file_output], stdout=subprocess.PIPE, shell=True)
        backup_msg = backup_service.communicate()
        self.logging.info("Finished Android backup")
        self.logging.debug("backup_msg is: " + str(backup_msg))

        self.logging.debug("Killing ADB Server")
        adb_kill = subprocess.Popen(["platform-tools\\adb.exe", "kill-server"], stdout=subprocess.PIPE, shell=True)
        adb_kill_msg = adb_kill.communicate()
        self.logging.debug("adb_kill_msg is: " + str(adb_kill_msg))

        self.logging.debug("Killing subprocesses")
        adb_server.kill()
        backup_service.kill()
        adb_kill.kill()