'''
   Copyright (c) 2019 Jack Farley
   This file is part of MEAT
   Usage or distribution of this software/code is subject to the
   terms of the GNU GENERAL PUBLIC LICENSE.
   system.py

    This file handles some windows operations

   ------------
'''
from __future__ import unicode_literals
from __future__ import print_function
import sys
import logging
import os
import stat
import hashlib
import csv
import glob
from pymobiledevice2.usbmux.usbmux import USBMux



BLOCKSIZE = 65536


def setup_csv(csv_path, md5, sha1):
    """
    Sets up Hash_Table.csv to track all file hashes
    :param csv_path: Path to the CSV file to write to
    :param md5: Boolean value if MD5 algorithm is chosen
    :param sha1: Boolean value if SHA-1 algorithm is chosen
    :return:
    """
    with open(csv_path, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)

        if md5 and sha1:
            csv_writer.writerow(["File Name", "Full Path", "MD5", "SHA-1"])
        elif md5:
            csv_writer.writerow(["File Name", "Full Path", "MD5"])
        elif sha1:
            csv_writer.writerow(["File Name", "Full Path", "SHA-1"])


def get_serial(log):
    mux = USBMux()
    if not mux.devices:
        mux.process(0.1)
    if len(mux.devices) == 0:
        log.error("No devices are connected")
        sys.exit()
    if len(mux.devices) > 1:
        log.error("Multiple devices attached. Please attach only one device")
        sys.exit()
    sn = mux.devices[0].serial
    return sn

def exitProgram():
    logging.info("Exiting program...")
    sys.exit()

def sha1_hasher(file_path):
    sha1_hash_obj = hashlib.sha1()
    with open(file_path, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while len(buf) > 0:
            sha1_hash_obj.update(buf)
            buf = afile.read(BLOCKSIZE)
    sha1_hash_value = sha1_hash_obj.hexdigest()
    return sha1_hash_value


def md5_hasher(file_path):
    sha1_hash_obj = hashlib.md5()
    with open(file_path, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while len(buf) > 0:
            sha1_hash_obj.update(buf)
            buf = afile.read(BLOCKSIZE)
    md5_hash_value = sha1_hash_obj.hexdigest()
    return md5_hash_value

def hasher(path, md5, sha1, csv_file, log):

    file_list = []
    hash_list = []
    files = [f for f in glob.glob(path + "/**/*", recursive=True)]
    for full_file_path in files:
        if os.path.isfile(full_file_path):
            filename = full_file_path.split("\\")[::-1][0]

            if sha1 and md5:
                log.debug("SHA-1 Hashing: " + full_file_path)
                sha1_hash = sha1_hasher(full_file_path)
                log.debug("MD5 Hashing: " + full_file_path)
                md5_hash = md5_hasher(full_file_path)
                csv_file.writerow([filename, full_file_path, md5_hash, sha1_hash])
            if sha1 and not md5:
                log.debug("SHA-1 Hashing: " + full_file_path)
                sha1_hash = sha1_hasher(full_file_path)
                csv_file.writerow([filename, full_file_path, sha1_hash])
            if not sha1 and md5:
                log.debug("MD5 Hashing: " + full_file_path)
                md5_hash = md5_hasher(full_file_path)
                csv_file.writerow([filename, full_file_path, md5_hash])
        else:
            continue
    return hash_list, file_list


'''Function to hash files via MD5'''
def md5Hash(path, hash_to_check = None, hash_check_type = None, return_dict = None, file_list_dict = None):

    file_list = []
    hash_list = []

    files = [f for f in glob.glob(path + "/**/*", recursive=True)]
    for filename in files:
        if os.path.isfile(filename):
            hasher = hashlib.md5()
            with open(filename, 'rb') as afile:
                buf = afile.read(BLOCKSIZE)
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = afile.read(BLOCKSIZE)
            hash = hasher.hexdigest()
            if hash_to_check is not None:
                if hash == hash_to_check:
                    logging.info("Hash Match!!")
                    logging.info("Hash: " + hash_to_check + " Matched File: " + str(filename))
            hash_list.append(hash)
            file_list.append(filename)
            if return_dict is not None and hash_check_type == 1:
                return_dict[hash] = hash
                file_list_dict[filename] = filename
            else:
                continue
        else:
            continue
    return hash_list, file_list













'''Function to test existence of directory'''
def checkFolder(directory):
    logging.debug("Checking existence for directory: " + str(directory))
    if os.path.isdir(directory):
        logging.debug("Directory: " + str(directory) + " exists")
        return 1

    else:
        '''Returns false if directory doesn't exist'''
        logging.error("DIRECTORY: " + str(directory) + " DOESNT EXIST")
        return 0


def downloadSymFolder(sftp, remote_folder, local_folder, sym_folder_name, log):
    log.info(str(remote_folder))

def downloadFolder(sftp, remote_folder, local_folder, folder_name, log):
    """

    :param sftp: SFTP Object
    :param remote_folder: The folder to be accessed on the iOS device
    :param local_folder: The folder to output data to on the local machine
    :param folder_name: folder name
    :param log: logger object
    :return:
    """

    if "fsevents" in remote_folder or "fsevents" in folder_name:
        x = 0

    #log.info(str(remote_folder) + str(folder_name))

    '''Special handling if parent directory is / - root'''
    '''USE full_dir_path variable to access to folder from now on'''
    if remote_folder == '/':
        full_dir_path = remote_folder + folder_name
    else:
        full_dir_path = remote_folder

    '''Create empty directory of same name to local folder'''
    local_folder = local_folder + "\\" + folder_name

    '''Strip bad chars out from path so Windows won't die'''
    local_folder = local_folder.strip()

    '''If that directory doesn't exist, we shall do it ourselves'''
    if not os.path.exists(local_folder):
        os.makedirs(local_folder)
    log.info("Created Directory: " + str(full_dir_path))



    '''List all items in directory'''
    for fileattr in sftp.listdir_attr(full_dir_path):

        '''Name of the file or folder'''
        object_name = fileattr.filename
        permissions = fileattr.st_mode

        '''New full path of the file or folder we will then send to downloadRecursiveSftp()'''
        new_full_path = full_dir_path + "/" + object_name

        checkData(sftp, new_full_path, local_folder, permissions, object_name, log)







def downloadFile(sftp, remote_file, local_folder, file_name, log):

    #log.info(str(remote_file))
    #log.info(str(file_name))

    if "fsevent" in remote_file or "fsevent" in file_name:
        x = 0

    '''The local file that will be created on the host machine'''
    local_file = local_folder + "\\" + file_name

    try:
        sftp.get(remote_file, local_file)
        log.info("Downloaded file: " + str(remote_file))
    except Exception as ex:
            log.exception("Exception occurred while downloading remote file: " + str(remote_file) +
                          "\nException was; " + str(ex))

def downloadSymFile(sftp, remote_file, local_folder, sym_file_name, log):
    log.info(str(remote_file))


def checkData(sftp, remote_folder, local_folder, permissions, object_name, log):





    '''Check is object folder AND NOT a symlink'''
    if stat.S_ISDIR(permissions) and not stat.S_ISLNK(permissions):
        downloadFolder(sftp, remote_folder, local_folder, object_name, log)

    '''Check is object folder AND IS a symlink'''
    if stat.S_ISDIR(permissions) and stat.S_ISLNK(permissions):
        downloadSymFolder(sftp, remote_folder, local_folder, object_name, log)

    '''Check if object is regular file AND NOT a symlink'''
    if stat.S_ISREG(permissions) and not stat.S_ISLNK(permissions):
        downloadFile(sftp, remote_folder, local_folder, object_name, log)

    '''Check if object is regular file AND IS a symlink'''
    if stat.S_ISREG(permissions) and stat.S_ISLNK(permissions):
        downloadSymFile(sftp, remote_folder, local_folder, object_name, log)


def downloadRecursiveSftp(sftp, remote_folder, local_folder, log):
    """

    :param sftp: sftp object
    :param remote_folder: The folder to be accessed on the iOS device
    :param local_folder: The folder to output data to on the local machine
    :param log: logger object
    :return:
    """


    """Special processing for root directory"""
    if remote_folder == "/":
        local_folder = local_folder + "\\" + "iOS_FILESYSTEM"
        '''Creates new folder if it does not exist'''
        if not os.path.exists(local_folder):
            os.makedirs(local_folder)

    '''Find all files and directories in specified folder: remote_folder'''
    '''remote_folder should adhere to the naming conventions of Linux paths'''
    for fileattr in sftp.listdir_attr(remote_folder):

        '''We can use the st_mode to see if the object is a file, directory, a symlink, etc'''
        permissions = fileattr.st_mode

        '''Name of the file or folder'''
        object_name = fileattr.filename

        #log.info(str(object_name))

        '''Check is object folder AND NOT a symlink'''
        if stat.S_ISDIR(permissions) and not stat.S_ISLNK(permissions):
            if "drwx------" in fileattr.longname:
                log.warning("Permission denied for directory: " + object_name)
            else:
                downloadFolder(sftp, remote_folder, local_folder, object_name, log)

        '''Check is object folder AND IS a symlink'''
        if stat.S_ISDIR(permissions) and stat.S_ISLNK(permissions):
            downloadSymFolder(sftp, remote_folder, local_folder, object_name, log)

        '''Check if object is regular file AND NOT a symlink'''
        if stat.S_ISREG(permissions) and not stat.S_ISLNK(permissions):
            downloadFile(sftp, remote_folder + object_name, local_folder, object_name, log)

        '''Check if object is regular file AND IS a symlink'''
        if stat.S_ISREG(permissions) and stat.S_ISLNK(permissions):
            downloadSymFile(sftp, remote_folder + object_name, local_folder, object_name, log)





















def test(sftp):
    name = ".HFS+ Private Directory Data"
    for fileattr in sftp.listdir_attr(name):
        x = 0


def get_folders(sftp, log, fileattr, remote_folder, local_folder):
    if fileattr.filename[-1:] == "\r":
        filename = fileattr.filename[:-1]

    new_folder = remote_folder + "/" + fileattr.filename
    if new_folder.startswith("//"):
        new_folder = new_folder[1:]
    if not stat.S_ISLNK(fileattr.st_mode):
        downloadRecursiveSftp(sftp, new_folder, local_folder, log)
    else:
        resolved_sym = sftp.readlink(new_folder)






def downloadRecursiveSftp2(sftp, remote_folder, local_folder, log):

    #test(sftp)

    if remote_folder != "/":
        ios_to_win = remote_folder.replace("/", "\\")
        local_extraction_folder = local_folder + ios_to_win
        local_extraction_folder = local_extraction_folder.replace("\\\\", "\\")
    else:
        local_extraction_folder = local_folder
    if not os.path.isdir(local_extraction_folder):
        os.makedirs(local_extraction_folder)

    for fileattr in sftp.listdir_attr(remote_folder):
        if stat.S_ISDIR(fileattr.st_mode) is not 0:
            get_folders(sftp, log, fileattr, remote_folder, local_folder)




        else:
            remote_file = remote_folder + "/" + fileattr.filename
            local_extraction_file = local_extraction_folder + "\\" + fileattr.filename
            log.debug("Extracting file: " + str(remote_file) + " to " + str(local_extraction_folder))

            #sftp.get(remote_file, local_extraction_file)
            if stat.S_ISLNK(fileattr.st_mode) != 0:

                if "/" not in sftp.readlink(remote_file):
                    dest = (local_extraction_file).replace("/", "\\")
                    source = (local_folder + remote_folder + "\\" + sftp.readlink(remote_file)).replace("/", "\\")
                    os.symlink(source, dest)
                else:
                    resolved_sym = sftp.readlink(remote_file)
                    new_local_path = (((local_folder + resolved_sym)[::-1]).split("/"))
                    del new_local_path[0]
                    new_local_path = ("\\".join(new_local_path))[::-1]
                    if not os.path.isdir(new_local_path):
                        os.makedirs(new_local_path)
                    #sftp.get(resolved_sym, new_local_path + "\\" + fileattr.filename)
                    source = new_local_path + "\\" + fileattr.filename
                    #os.symlink(source, local_extraction_file)
            else:
                #sftp.get(remote_file, local_extraction_file)
                x = 0





