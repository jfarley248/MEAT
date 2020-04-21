# M.E.A.T. - Mobile Evidence Acquisition Toolkit
Meet M.E.A.T! 

This toolkit aims to help forensicators perform different kinds of acquisitions on iOS and Android devices.

##### Requirements to run from source
* Windows Machine
* Python 3.7

## Types of Acquisitions Supported

### iOS Devices

#### Logical

Using the logical acquisition flag on MEAT will instruct the tool to extract files and folders accessible through AFC on jailed devices. The specific folder that allows access is: \private\var\mobile\Media, which includes fodlers such as:
* AirFair
* Books
* DCIM
* Downloads
* general_storage
* iTunes_Control
* MediaAnalysis
* PhotoData
* Photos
* PublicStaging
* Purchases
* Recordings

#### Filesystem
### iOS Device Prerequisites

* Jailbroken iOS Device
* AFC2 Installed via Cydia

Using the filesystem acquisition flag on MEAT will instruct the tool to tar the root directory, and send over the completed tar file back to the host machine.

This method requires the device to be jailbroken with the following packages intstalled:

* Apple File Conduit 2

This method can also be changed by the user using the -filesystemPath flag to instruct MEAT to only tar up a specified folder, useful if you're doing app analysis and only want the app data.


##### MEAT Help
```
usage: MEAT.py [-h] [-iOS] [-filesystem] [-filesystemPath FILESYSTEMPATH]
               [-logical] [-md5] [-sha1] -o OUTPUTDIR [-v]

MEAT - Mobile Evidence Acquisition Toolkit

optional arguments:
  -h, --help            show this help message and exit
  -iOS                  Perform Acquisition on iOS Device
  -filesystem           Perform Filesystem Acquisition - 
  -filesystemPath FILESYSTEMPATH
                        Path on target device to acquire. Only use with --filesystem argument
                        Default will be "/"
  -logical              Perform Logical Acquisition
                        iOS - Uses AFC to gain access to jailed content
  -md5                  Hash pulled files with the MD5 Algorithm. Outputs to Hash_Table.csv
  -sha1                 Hash pulled files with the SHA-1 Algorithm. Outputs to Hash_Table.csv
  -o OUTPUTDIR          Directory to store results
  -v                    increase output verbosity

Process finished with exit code 0


```

### Things to do in the future
* Add Android support
* Add ability for the user to specify block device for android physical acquisitions
* Add support for iTunes backups
* Add Unix and MacOS support (email me if you want this!)





