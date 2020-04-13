# M.E.A.T. - Mobile Evidence Acquisition Toolkit
Meet M.E.A.T! 

This toolkit aims to help forensicators perform different kinds of acquisitions on iOS and Android devices.

##### Requirements to run from source
* Windows Machine
* Python 3.7
* The following packages installed via pip:

`pip.exe install paramiko construct biplist pure-python-adb pyasn1 future six`

## Types of Acquisitions Supported

### iOS Devices

#### Logical

Using the logical acquisition flag on MEAT will instruct the tool to extract files and folders accessible through AFC on jailed devices, such as:
* Camera Roll
*

#### Filesystem

Using the filesystem acquisition flag on MEAT will instruct the tool to tar the root directory, and send over the completed tar file back to the host machine.

This method requires the device to be jailbroken with the following packages intstalled:

* Tar 
* Apple File Conduit 2
* OpenSSH

This method can also be changed by the user using the -filesystemPath flag to instruct MEAT to only tar up a specified folder, useful if you're doing app analysis and only want the app data.

#### Physical

Using the physical acquisition flag on MEAT will instruct the tool to do a few things:

1. Extract entitlements from /System/Library/Filesystems/apfs.fs/apfs.util to an xml in the home directory of the device
2. Use JTool to sign the dd command with the extracted entitlements
3. Use dd to image the /dev/disk0s1s1 and send the data over to the host computer

Needless to say the device must be jailbroken with the following packages installed:

* JTool
* Apple File Conduit 2
* OpenSSH

### Android Devices
#### Backup

Using the backup acquisition flag on MEAT will instruct the tool to create an ADB backup of the device

#### Logical

Using the logical acquisition flag on MEAT will instruct the tool to extract files and folders accessible through ADB on non rooted devices:

#### Physical

Using the physical acquisition flag on MEAT will instruct the tool to use dd to create an image of the largest partition on the disk

## Usage

##### Example Usages

*Logical Acquisition of an iOS Device*

`MEAT.py -o "D:\OutputDirectory" -iOS -logical`

*ADB Backup of an Android Device*

`MEAT.py -o "D:\OutputDirectory" -Android -backup`

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
* Add ability for the user to specify block device for android physical acquisitions
* Add support for iTunes backups
* Add Unix and MacOS support (email me if you want this!)



# M.E.A.T Documentation

## iOS Filesystem Acquisition

### iOS Device Prerequisites

* Jailbroken iOS Device under iOS 13
* AFC2 Installed via Cydia

## Filesystem & Logical Acquisition Process - Simple Explanation

1.) Using the `get_serial()` fucntion M.E.A.T queries connected devices by running USBMux and returns the first device's 
serial number
   
2.) Using the serial number acquired from running USBMux, we then create a `LockdownClient` object by handing it the device's 
serial number

3.) Using our `LockdownClient` object, we then start an Apple File Condiut service using: 

`lockdown.startService("com.apple.afc2")` for jailbroken devices

`lockdown.startService("com.apple.afc")` for non-jailbroken devices

4.) Once the AFC/AFC2 service has started, we then create an `AFCClient` / `AFC2Client` object. This object allows us to interact with the 
filesystem of the device

5.) We then call `pull_directory` to pull the driectory that the user has specified, coupled with the output folder :

`afc.pull_directory('/', self.output)`

### Filesystem & Logical Acquisition Process - Detailed Explanation

#### 1.) Starting M.E.A.T.

Running M.E.A.T. is as easy as giving it the following parameters:

```

usage: MEAT.py [-h] [-iOS] [-Android] [-filesystem]
               [-filesystemPath FILESYSTEMPATH] [-logical] [-physical]
               [-backup] -o OUTPUTDIR [-ip IP] [-port PORT]
               [-username USERNAME] [-pw PASSWORD] [-v]

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
  -o OUTPUTDIR          Directory to store results
  -ip IP                IP Address for physical acquisition via network. If connecting over USB do not use this argument
  -port PORT            Port for physical acquisition via network. If connecting over USB do not use this argument
  -username USERNAME    Root username for iOS device using physical acquisition. Default will be "root"
  -pw PASSWORD          Root password for device using physical acquisition. Default will be "alpine" for iOS
  -v                    increase output verbosity

```

This may seem like a lot, so here are the two commands you will use to start iOS Filesystem and Logical Acquisitions:

`-iOS -filesystem -o "H:\MEAT_OUT" -v`

Tells M.E.A.T. to perform a Filesystem Acquisition, and since no `-filesystempath` is used, it will extract everything

`-iOS -logical -o "H:\MEAT_OUT2" -v`

Tells M.E.A.T. to perform a Logical Acquisition


#### 2.) M.E.A.T. starts the Acquisition of your choice

M.E.A.T. will start the acquisition process by parsing all user arguments and create an Acquisition Object based on the 
acquisition the user has chosen

`iOS_filesystem.filesystem( args.outputDir, args.filesystemPath, logging)`

This code starts a Filesystem Acquisition and gives the object the output directory to store the acquisition contents, 
the path to the folder that the user has chose, defualt is /, and the logging object, which will output messages to the console 

The object initializes itself with these given variables:

```
    def __init__(self, output, remoteFolder, logging):
        self.logging = logging or logging.getLogger(__name__)
        self.output = output
        self.remoteFolder = remoteFolder
        self.startAcquisition()

```

The object automatically calls `startAcquisition()` and thus begins the acquisition


#### 3.) Obtaining the device's serial number by calling the `get_serial()` function:
```
def get_serial():
    mux = USBMux()
    if not mux.devices:
        mux.process(0.1)
    sn = mux.devices[0].serial
    return sn
```
USBMux is how iTunes communicates to iOS devices over USB. iPhones connected in normal mode (not Recovery or DFU mode) 
will be connected to and now we can start relaying requests to the device [0].

USBMux then processes devices using:
 
 `mux.process(0.1)` 
 
 We can then grab the serial number of the first device by using:
 
 `mux.devices[0].serial`
 
 This returns a string of the serial number of the first connected device
 
 Note that the iOS device MUST be paired with the host computer by clicking Trust on the iOS device
 

#### 4.) The `LockdownClient` must be created by supplying it with the serial number that we recieved from `get_serial()`

The `LockdownClient` initializes itself with several variables such as:
* HostID
* Unique Chip ID
* iOS Version
* UDID

The `LockdownClient` allows us to start other services, which we will need to do in the next step

#### 5.) Depending on the level of access we have to the iOS device, we will start an Apple File Conduit service

Apple File Conduit, or AFC is a system service that allows access files in the /private/var/mobile/Media directory on 
every iOS device [1].

The normal AFC service is the service we will start for Logical Acquisitions, since we don't need to jailbreak the device 
to be able to start this service

However, when the device is jailbroken, we gain the ability to edit the /System/Library/Lockdown/Services.plist file to 
add a service that runs under root with access to the root filesystem [1].

Installing the Apple File Conduit 2 package via Cydia (jailbreak package manager) on a jailbroken device grants us the access mentioned above, and 
is absolutely neccessary to perform a Filesystem Acquisition.

Starting the AFC / AFC2 service is done by calling upon our `LockdownClient` service we created by calling `startService`:

`lockdown.startService("com.apple.afc2")`

`lockdown.startService("com.apple.afc")`

Note that `lockdown` is the `LockdownClient` object we created

#### 6.) Calling `pull_directory()`

We then call upon the `pull_directory()` function of pymobiledevice2, which as the name suggests, recursively pulls an 
entire directory. Supplied with the folder that is going to be extracted and the output folder on the local machine will 
allow this function to successfully complete it's operation

#### 7.) Enumerating files and folders






# References
[0] https://www.theiphonewiki.com/wiki/Usbmux

[1] https://www.theiphonewiki.com/wiki/AFC
