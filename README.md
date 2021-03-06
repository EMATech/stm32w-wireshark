stm32w-wireshark
================

A command line utility to read packet capture from the USB dongle supplied with the STMicroelectronics STM32-RFCKIT running their Wireshark server firmware.

Copyright
---------

(c) 2012, Joe Desbonnet, jdesbonnet@gmail.com

Version
-------

0.1 (11 April 2012)

Compile
-------

```gcc -o stm32w-wireshark stm32w-wireshark.c -lrt```

Usage
-----

stm32w-wireskark [-q] [-v] [-h] [-d level] [-f format] device channel

### Options

- -d level 	 Set debug level, 0 = min (default), 9 = max verbosity
- -f format 	 Output format: pcap (default) | hex 
- -q 	 Quiet mode: suppress warning messages.
- -v 	 Print version to stderr and exit
- -h 	 Display this message to stderr and exit

### Parameters

- device:  the unix device file corresponding to the dongle device (often /dev/ttyACM0)
- channel: the 802.15.4 channel. Allowed values from 11 to 26.

More informations
-----------------

http://jdesbonnet.blogspot.com/2012/04/stm32w-rfckit-as-802154-network.html
