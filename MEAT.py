'''
   Copyright (c) 2019 Jack Farley
   This file is part of MEAT
   Usage or distribution of this software/code is subject to the
   terms of the GNU GENERAL PUBLIC LICENSE.
   MEAT.py
'''


from __future__ import unicode_literals
from __future__ import print_function
import os
import logging
import time
from datetime import datetime
from argparse import ArgumentParser, RawTextHelpFormatter
from helpers import system2
import zipfile
import sys
import tarfile
from acquisitions.iOS import iOS_filesystem, iOS_physical, iOS_logical, iOS_backup
#from acquisitions.Android import Android_logical, Android_backup, Android_physical


ASCII_BANNER2 = '''
███╗   ███╗   ███████╗    █████╗ ████████╗
████╗ ████║   ██╔════╝   ██╔══██╗╚══██╔══╝
██╔████╔██║   █████╗     ███████║   ██║   
██║╚██╔╝██║   ██╔══╝     ██╔══██║   ██║   
██║ ╚═╝ ██║██╗███████╗██╗██║  ██║██╗██║██╗
╚═╝     ╚═╝╚═╝╚══════╝╚═╝╚═╝  ╚═╝╚═╝╚═╝╚═╝
                                          
                                                      
'''

def get_argument():


    parser = ArgumentParser(description='MEAT - Mobile Evidence Acquisition Toolkit', formatter_class=RawTextHelpFormatter)

    parser.add_argument("-iOS", help="Perform Acquisition on iOS Device", action="store_true")

    #parser.add_argument("-Android", help="Perform Acquisition on Android Device", action="store_true")

    parser.add_argument("-filesystem", help="Perform Filesystem Acquisition - ", action="store_true")

    parser.add_argument("-filesystemPath", help="Path on target device to acquire. Only use with --filesystem argument\n"
                                                 "Default will be \"/\"", default="/", type=str, dest='filesystemPath')

    parser.add_argument("-logical", help="Perform Logical Acquisition\n"
                                          "iOS - Uses AFC to gain access to jailed content", action="store_true")

    #parser.add_argument("-physical", help="Perform Physical Acquisition", action="store_true")

    #parser.add_argument("-backup", help="Perform Acquisition via backup, Android only", action="store_true")
    parser.add_argument("-md5", help="Hash pulled files with the MD5 Algorithm. Outputs to Hash_Table.csv", action="store_true")
    parser.add_argument("-sha1", help="Hash pulled files with the SHA-1 Algorithm. Outputs to Hash_Table.csv", action="store_true")


    #parser.add_argument("-ip", type=str, dest='ip', help='IP Address for acquisition via network. If connecting over USB do not use this argument', default="localhost")
    #parser.add_argument("-port", type=int, dest='port', help='Port for acquisition via network. If connecting over USB do not use this argument', default=2222)
    #parser.add_argument("-username", type=str, dest='username', help='Root username for iOS device. Default will be \"root\"', default="root")
    #parser.add_argument("-pw", type=str, dest='password', help='Root password for device. Default will be \"alpine\" for iOS', default="alpine")



    parser.add_argument("-o", required=True, type=str, dest='outputDir',
                        help='Directory to store results')

    parser.add_argument("-v", help="increase output verbosity", action="store_true")

    parser.add_argument("-outputType",
                        help="What the output will be, FOLDER, ZIP, or TAR\n"
                             "Default will be FOLDER", default="FOLDER", type=str, dest='output_type')


    args = parser.parse_args()




    '''Log output path'''
    logOut = os.path.join(args.outputDir, 'MEAT.log')
    if not os.path.isdir(args.outputDir):
        os.makedirs(args.outputDir)

    '''Sets up logger'''
    if args.v:
        logging.basicConfig(handlers=[logging.StreamHandler(), logging.FileHandler(logOut)], level=logging.DEBUG,
                            format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                            datefmt='%m-%d %H:%M')

    else:
        logging.basicConfig(handlers=[logging.StreamHandler(), logging.FileHandler(logOut)], level=logging.INFO,
                            format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                            datefmt='%m-%d %H:%M')

    log = logging.getLogger()
    log.debug("Starting MEAT")


    return args


def main():



    '''Gets arguments'''
    args = get_argument()

    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    logging.info("Extraction Starting on: " + dt_string + " Local Time")
    time_start = time.perf_counter()



    '''Log output path'''
    csv_path = os.path.join(args.outputDir, 'Hash_Table.csv')

    mode = -1
    if args.output_type.upper() == "FOLDER":
        mode = 0
    if args.output_type.upper() == "ZIP":
        mode = 1
    if args.output_type.upper() == "TAR":
        mode = 2
    if mode == -1:
        logging.error("You did not enter a valid outputType. Try again")
        return

    '''Starts iOS Acquisitions'''
    if args.iOS:

        '''Starts iOS Filesystem Acquisition'''
        if args.filesystem:
            try:
                logging.info("Starting iOS Filesystem Acquisition")
                filesystem_output = os.path.join(args.outputDir, "iOS_Filesystem")
                iOS_filesystem.filesystem( filesystem_output, args.filesystemPath, args.md5, args.sha1, csv_path, logging)

                if mode == 1:
                    system2.handle_zip_pull("iOS_Filesystem", args.outputDir, filesystem_output, logging)

                if mode == 2:
                    system2.handle_tar_pull("iOS_Filesystem", args.outputDir, filesystem_output, logging)

            except Exception as ex:
                logging.exception("Exception while performing iOS Filesystem Acquisition. Exception was: " + str(ex))

        '''Starts iOS Logical Acquisition'''
        if args.logical:
            try:
                logging.info("Starting iOS Logical Acquisition")
                logical_output = os.path.join(args.outputDir, "iOS_Logical")
                iOS_logical.logical(logical_output, args.md5, args.sha1, csv_path, logging)

                if mode == 1:
                    system2.handle_zip_pull("iOS_Logical", args.outputDir, logical_output, logging)

                if mode == 2:
                    system2.handle_tar_pull("iOS_Logical", args.outputDir, logical_output, logging)

            except Exception as ex:
                logging.exception("Exception while performing iOS Logical Acquisition. Exception was: " + str(ex))

        '''Starts iOS Physical Acquisition'''
        #if args.backup:
        #    try:
        #        logging.warning("iOS Backups are not supported yet, please use iTunes instead")
        #    except Exception as ex:
        #        logging.exception("Exception while performing iOS Backup. Exception was: " + str(ex))

    '''Starts Android Acquisitions'''
    '''
    if args.Android:
        #Starts Android Logical Acquisition
        if args.logical:
            try:
                logging.info("Starting Android Logical Acquisition")
                Android_logical.androidLogical("", args.outputDir, logging)
                logging.info("Successfully performed Android Logical Acquisition")
            except Exception as ex:
                logging.exception("Exception while performing Android Logical Acquisition. Exception was: " + str(ex))
    '''





    '''
        if args.backup:
            try:
                logging.info("Starting Android Backup Acquisition")
                Android_backup.androidBackup(args.outputDir, logging)
                logging.info("Successfully performed Android Backup")
            except Exception as ex:
                logging.exception("Exception while performing Android Backup. Exception was: " + str(ex))
    '''



    '''Starts Android Physical Acquisition'''
    '''
        if args.physical:
            try:
                logging.info("Starting Android Physical Acquisition")
                Android_physical.androidPhysical(args.outputDir, logging)
                logging.info("Successfully performed Android Physical Acquisition")
            except Exception as ex:
                logging.exception("Exception while performing Android Physical Acquisition. Exception was: " + str(ex))
                
    '''

    time_stop = time.perf_counter()
    total_time = (time_stop - time_start) / 60
    logging.info("Program finished in: " + str(total_time) + " minutes")
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    logging.info("Program Finished on: " + dt_string + " Local Time")

if __name__ == "__main__":
    print(
        ASCII_BANNER2 + "M.E.A.T. - Mobile Evidence Acquisition Toolkit\nWritten by Jack Farley - BlackStone Discovery\n\n")

    main()
