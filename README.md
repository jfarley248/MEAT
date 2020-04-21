# M.E.A.T. - Mobile Evidence Acquisition Toolkit
Meet M.E.A.T! 

This toolkit aims to help forensicators perform different kinds of acquisitions on iOS and Android devices.

##### Requirements to run from source
* Windows Machine
* Python 3.7

## Types of Acquisitions Supported

### iOS Devices

#### Logical

Using the logical acquisition flag on MEAT will instruct the tool to extract files and folders accessible through AFC on jailed devices, such as:
* Camera Roll
* Downloads
* Recordings
* iTunes Sync Data
* 

#### Filesystem

Using the filesystem acquisition flag on MEAT will instruct the tool to tar the root directory, and send over the completed tar file back to the host machine.

This method requires the device to be jailbroken with the following packages intstalled:

* Apple File Conduit 2

This method can also be changed by the user using the -filesystemPath flag to instruct MEAT to only tar up a specified folder, useful if you're doing app analysis and only want the app data.


##### MEAT Help
```
usage: MEAT.py [-h] [-iOS] [-Android] [-filesystem]
               [-filesystemPath FILESYSTEMPATH] [-logical] [-physical]
               [-backup] [-ip IP] [-port PORT] [-username USERNAME]
               [-pw PASSWORD] -o OUTPUTDIR [-v]

MEAT - Mobile Evidence Acquisition Toolkit

optional arguments:
  -h, --help            show this help message and exit
  -iOS                  Perform Acquisition on iOS Device
  -Android              Perform Acquisition on Android Device
  -filesystem           Perform Filesystem Acquisition
                        	iOS & Android- Uses tar to archive contents of --filesystemPath
  -filesystemPath FILESYSTEMPATH
                        Path on target device to acquire. Only use with --filesystem argument
                        	Default will be "/"
  -logical              Perform Logical Acquisition
                        	iOS - Uses AFC to gain access to jailed content
                        	Android - Descrption Not Available
  -physical             Perform Physical Acquisition
  -backup               Perform Acquisition via backup, Android only
  -ip IP                IP Address for acquisition via network. If connecting over USB do not use this argument
  -port PORT            Port for acquisition via network. If connecting over USB do not use this argument
  -username USERNAME    Root username for iOS device. Default will be "root"
  -pw PASSWORD          Root password for device. Default will be "alpine" for iOS
  -o OUTPUTDIR          Directory to store results
  -v                    increase output verbosity

```

### Things to do in the future
* Add Android support
* Add ability for the user to specify block device for android physical acquisitions
* Add support for iTunes backups
* Add Unix and MacOS support (email me if you want this!)



# M.E.A.T Documentation

## iOS Filesystem Acquisition

### iOS Device Prerequisites

* Jailbroken iOS Device under iOS 13
* AFC2 Installed via Cydia


