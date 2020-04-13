'''
   Copyright (c) 2019 Jack Farley
   This file is part of MEAT
   Usage or distribution of this software/code is subject to the
   terms of the GNU GENERAL PUBLIC LICENSE.
   iOS_physical.py
'''

import time
import paramiko
import sys
from subprocess import Popen
from helpers import system
from pymobiledevice2.usbmux.usbmux import USBMux
from pymobiledevice2.lockdown import LockdownClient
from pymobiledevice2.afc import AFCShell, AFC2Client

class physical(object):

    def __init__(self, ip, port, username, password, output, remoteFolder, logging):
        self.logging = logging or logging.getLogger(__name__)
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password
        self.output = output
        self.remoteFolder = remoteFolder
        self.tcp_conn = None
        self.ssh_client = None
        #self.startAcquisition()
        self.fuck()



    def get_serial(self):
        mux = USBMux()
        if not mux.devices:
            mux.process(0.1)
        sn = mux.devices[0].serial
        return sn



    def fuck(self):

        sn = self.get_serial()
        lockdown = LockdownClient(sn)
        #afc2_service = lockdown.startService("com.apple.afc2")
        lockdown.startService("com.apple.afc2")
        afc = AFC2Client(lockdown)


        #content = afc.get_file_contents('/jb/offsets.plist')

        afc.pull_directory('/', self.output)
        x =0












































    '''Closes TCPRelay'''
    def closeTcpRelay(self):
        try:
            self.logging.debug("Trying to stop TCPRelay now")
            self.tcp_conn.kill()
        except Exception as ex:
            self.logging.exception("Could not stop TCPRelay! Exception was: " + str(ex))


    '''Starts TCPrelay in the background for connection over USB'''
    def openTcpRelay(self):
        try:
            self.logging.debug("Attempting to create tcprelay connection")

            '''Executes the python script'''
            self.tcp_conn = Popen([sys.executable, "helpers\\tcprelay.py"])

            '''Sleep for 2 seconds to make sure connection is established before executing commands'''
            time.sleep(2)
            self.logging.debug("Successfully started TCPRelay")

        except Exception as ex:
            self.logging.exception("Unable to start TCPRelay. Exception was: " + str(ex))


    '''Connects via SSH using Paramiko module'''
    def openSsh(self):
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.logging.debug("Trying to connect to device over ssh now")
            self.ssh_client.connect(self.ip, self.port, username=self.username, password=self.password, look_for_keys=False)
            self.logging.info(("Successfully SSH'd to {}").format(self.ip))
        except Exception as ex:
            self.logging.exception("Failed to establish ssh connection. Exception was: " + str(ex))

    '''Tries to close SSH connection'''
    def closeSsh(self):
        try:
            self.logging.debug(("Trying to close SSH connection to {}").format(self.ip))
            self.ssh_client.close()
            self.logging.info(("Successfully closed SSH connection to {}").format(self.ip))
        except Exception as ex:
            self.logging.exception(("Failed to close SSH connection to {} Exception was: {}").format(self.ip, str(ex)))

    '''Checks for the neccessary binaries to perform acquisition'''
    def checkRequirements(self):

        '''Gets all commands redy to find the neccessary binaries'''
        self.logging.debug("Starting to check binary requirements on the iOS device now")
        apfs_check = "ls /System/Library/Filesystems/apfs.fs/apfs.util"
        dd_check = "ls /bin/dd"
        jtool_check = "ls /usr/bin/jtool"

        '''Checks for apfs.util existence'''
        self.logging.debug("Checking for apfs.util existence. This should be here on every device")
        stdin, stdout, stderr = self.ssh_client.exec_command(apfs_check)
        apfs_exist = stdout.read()
        apfs_exist = apfs_exist.decode("utf-8")
        if apfs_exist != "/System/Library/Filesystems/apfs.fs/apfs.util\n":
            self.logging.error("Could not find apfs.util in /System/Library/Filesystems/apfs.fs/")
            self.closeSsh()
            self.closeTcpRelay()
            system.exitProgram()
        '''Checks for dd existence'''
        self.logging.debug("Checking for dd existence in /bin/dd")
        stdin, stdout, stderr = self.ssh_client.exec_command(dd_check)
        dd_exist = stdout.read()
        dd_exist = dd_exist.decode("utf-8")
        if dd_exist != "/bin/dd\n":
            self.logging.error("Could not find dd in /bin/")
            self.closeSsh()
            self.closeTcpRelay()
            system.exitProgram()

        '''Checks for jtool existence'''
        self.logging.debug("Checking for jtool existence in /usr/bin/")
        stdin, stdout, stderr = self.ssh_client.exec_command(jtool_check)
        jtool_exist = stdout.read()
        jtool_exist = jtool_exist.decode("utf-8")
        if jtool_exist != "/usr/bin/jtool\n":
            self.logging.error("Could not find dd in /usr/bin/")
            self.closeSsh()
            self.closeTcpRelay()
            system.exitProgram()

    '''Gets entitlements from apfs.util and stores them in ~/ent.xml'''
    def stealEntitlements(self):
        jtool_command = "jtool --ent /System/Library/Filesystems/apfs.fs/apfs.util > ~/ent.xml"
        self.logging.debug("Copying entitlements from apfs.util now")
        stdin, stdout, stderr = self.ssh_client.exec_command(jtool_command)
        error = stderr.read().decode("utf-8")
        if len(error) > 0:
            self.logging.error("Error copying entitlements from apfs.util. Error was: " + error)
            self.closeSsh()
            self.closeTcpRelay()
            system.exitProgram()


    '''Overwrites the dd command entitlements with apfs.utils entitlements'''
    def overwriteDdEnt(self):
        command = "jtool --sign --inplace --ent ~/ent.xml /bin/dd"
        self.logging.debug("Inserting entitlements to dd now")
        stdin, stdout, stderr = self.ssh_client.exec_command(command)
        error = stderr.read().decode("utf-8")
        if len(error) > 0:
            self.logging.error("Error inserting entitlements to dd. Error was: " + error)
            self.closeSsh()
            self.closeTcpRelay()
            system.exitProgram()

    def extract(self):
        command = " dd if=/dev/disk0s1s1"

        '''Executes command and stores output values'''
        try:
            info = ((
                        "Executing command {}, this may take a lot of time and it may appear frozen").format(
                command))
            self.logging.info(info)
            stdin, stdout, stderr = self.ssh_client.exec_command(command)
        except Exception as ex:
            self.closeSsh()
            self.closeTcpRelay()
            self.logging.exception(('''Exception when trying to execute command: {}
                     Exception was: {}''').format(command, str(ex)))

        '''Reads bytes from output into a variable'''
        raw_file = stdout.read()

        '''Sets up output file in path given by user and opens as binary file'''
        try:
            self.logging.debug(("Trying to set up file {}").format(self.output + "\\iOS-Physical.dd"))
            out_file = open(self.output + "\\iOS-Physical.dd", 'wb')
            self.logging.debug(("Successfully set up file {}").format(self.output + "\\iOS-Physical.dd"))
        except Exception as ex:
            self.logging.exception(("Exception trying to set up file: {} Exception was: {}"
                                    "").format(self.output + "\\iOS-Physical.dd", str(ex)))

        '''Writes bytes to the output tar file'''
        try:
            self.logging.debug(("Trying to write file {}").format(self.output + "\\iOS-Physical.dd"))
            out_file.write(raw_file)
            self.logging.info(("Successfully wrote file {}").format(self.output + "\\iOS-Physical.dd"))
        except Exception as ex:
            self.logging.exception(("Exception trying to write file: {} Exception was: {}"
                                    "").format(self.output + "\\iOS-Physical.dd", str(ex)))

    def startAcquisition(self):

        '''Opens TcpRelay'''
        self.openTcpRelay()

        '''Oopens SSH connection'''
        self.openSsh()

        '''Executes command'''
        self.checkRequirements()
        self.stealEntitlements()
        self.overwriteDdEnt()
        self.extract()

        '''Closes SSH connection'''
        self.closeSsh()

        '''Closes TCPRelay connection'''
        self.closeTcpRelay()
















