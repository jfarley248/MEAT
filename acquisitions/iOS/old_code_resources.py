'''
   Copyright (c) 2019 Jack Farley
   This file is part of MEAT
   Usage or distribution of this software/code is subject to the
   terms of the GNU GENERAL PUBLIC LICENSE.
   iOS_filesystem.py
'''

import time
import paramiko
import logging
import sys
from stat import S_ISDIR
from subprocess import Popen
from helpers.system import downloadRecursiveSftp


class iOS_filesystem(object):

    def __init__(self, ip, port, username, password, output, remoteFolder, logging):
        self.logging = logging or logging.getLogger(__name__)
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password
        self.output = output
        self.remoteFolder = remoteFolder.replace("\\", "/")
        self.tcp_conn = None
        self.ssh_client = None
        self.sftp_client = None

        self.startAcquisition()

    def isdir(self, path):
        # https://stackoverflow.com/questions/6674862/recursive-directory-download-with-paramiko
        try:
            return S_ISDIR(self.sftp_client.stat(path).st_mode)
        except IOError:
            # Path does not exist, so by definition not a directory
            return False

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

            logging.getLogger("paramiko").setLevel(logging.WARNING)
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.logging.debug("Trying to connect to device over ssh now")
            self.ssh_client.connect(self.ip, self.port, username=self.username, password=self.password,
                                    look_for_keys=False, timeout=60)

            self.logging.info(("Successfully SSH'd to {}").format(self.ip))

            # tr = self.ssh_client.get_transport()
            # tr.default_max_packet_size = 100000000
            # tr.default_window_size = 100000000



        except Exception as ex:
            self.logging.exception("Failed to establish ssh connection. Exception was: " + str(ex))

    def openSftp(self):

        self.logging.debug("Opening STFP")
        self.sftp_client = self.ssh_client.open_sftp()
        self.sftp_client.get_channel().in_window_size = 2097152
        self.sftp_client.get_channel().out_window_size = 2097152
        self.sftp_client.get_channel().in_max_packet_size = 2097152
        self.sftp_client.get_channel().out_max_packet_size = 2097152

        transport = self.ssh_client.get_transport()
        transport.default_window_size = paramiko.common.MAX_WINDOW_SIZE
        transport.packetizer.REKEY_BYTES = pow(2, 40)  # 1TB max, this is a security degradation!
        transport.packetizer.REKEY_PACKETS = pow(2, 40)  # 1TB max, this is a security degradation!\

        transport = paramiko.Transport((self.ip, self.port))
        transport.default_window_size = paramiko.common.MAX_WINDOW_SIZE
        transport.packetizer.REKEY_BYTES = pow(2, 40)  # 1TB max, this is a security degradation!
        transport.packetizer.REKEY_PACKETS = pow(2, 40)  # 1TB max, this is a security degradation!

        """
        with paramiko.Transport(self.ip, self.port) as transport:
            transport.default_window_size = paramiko.common.MAX_WINDOW_SIZE
            transport.packetizer.REKEY_BYTES = pow(2, 40)  # 1TB max, this is a security degradation!
            transport.packetizer.REKEY_PACKETS = pow(2, 40)  # 1TB max, this is a security degradation!

            transport.connect(username=self.username, password=self.password, gss_deleg_creds=False)
            with paramiko.SFTPClient.from_transport(transport) as sftp:
                self.sftp_client = sftp

        """

    def closeSftp(self):
        self.logging.debug("Closing STFP")
        self.sftp_client.close()

    '''Tries to close SSH connection'''

    def closeSsh(self):
        try:
            self.logging.debug(("Trying to close SSH connection to {}").format(self.ip))
            self.ssh_client.close()
            self.logging.info(("Successfully closed SSH connection to {}").format(self.ip))
        except Exception as ex:
            self.logging.exception(("Failed to close SSH connection to {} Exception was: {}").format(self.ip, str(ex)))

    '''Executes tar command'''

    def executeOrder66(self):

        try:
            self.logging.info("MEAT is starting the extraction process")
            downloadRecursiveSftp(self.sftp_client, self.remoteFolder, self.output, self.logging)
            self.logging.info("MEAT has succeeded in extracting the filesytem")
        except Exception as ex:
            self.logging.exception("MEAT has failed during the extraction process. Exception was: " + str(ex))
            self.closeTcpRelay()

    def startAcquisition(self):

        '''Opens TcpRelay'''
        self.openTcpRelay()

        '''Start SSH and make sure it closes on exit'''
        try:
            self.ssh_client = paramiko.SSHClient()
            logging.getLogger("paramiko").setLevel(logging.WARNING)
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.logging.debug("Trying to connect to device over ssh now")
            self.ssh_client.connect(self.ip,
                                    self.port,
                                    username=self.username,
                                    password=self.password,
                                    look_for_keys=False,
                                    timeout=60)

            transport = self.ssh_client.get_transport()
            transport.default_window_size = paramiko.common.MAX_WINDOW_SIZE
            transport.packetizer.REKEY_BYTES = pow(2, 40)  # 1TB max, this is a security degradation!
            transport.packetizer.REKEY_PACKETS = pow(2, 40)  # 1TB max, this is a security degradation!

            self.logging.info(("Successfully SSH'd to {}").format(self.ip))

            '''Tunnels SFTP over SSH'''
            self.openSftp()

            self.executeOrder66()

            '''Closes SFTP tunnel'''
            self.closeSftp()

            '''Closes SSH connection'''
            # self.closeSsh()

            '''Closes TCPRelay connection'''
            self.closeTcpRelay()



        finally:
            if self.ssh_client:
                self.ssh_client.close()

        '''Executes command
        #https://stackoverflow.com/questions/45891553/paramiko-hangs-on-get-after-ownloading-20-mb-of-file/48170689

        with paramiko.Transport(self.ip, self.port) as transport:
            transport.Sec
            transport.default_window_size = paramiko.common.MAX_WINDOW_SIZE
            transport.packetizer.REKEY_BYTES = pow(2, 40)  # 1TB max, this is a security degradation!
            transport.packetizer.REKEY_PACKETS = pow(2, 40)  # 1TB max, this is a security degradation!

            transport.connect(username=self.username, password=self.password, gss_deleg_creds=False)
            with paramiko.SFTPClient.from_transport(transport) as sftp:
                self.sftp_client = sftp

        '''


