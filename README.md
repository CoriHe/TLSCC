# TLSCC
Practical part of the Master-thesis:
"Network covert channels in Transport Layer Security protocol and their detection"
submitted to the FernUniversitaet in Hagen at 2020-02-23

# Abstract:
Information hiding is the art of embedding data in certain entities in a way, that an uninformed
party isn’t able to detect and uncover it. Steganography, which is for example used to secretly
embed data in pictures, music and other data, is one form of it. Network covert channels are
another variant of information hiding, which uses certain characteristica of network protocols
to create a communication channel between parties, that strive to keep not only the content
confidential, but even the fact, that the communication took place at all. With the rise of
the internet, the need for a standardized protocol for encrypted network communication lead
to the specification of the TLS protocol, that enables clients and servers to communicate
in a secure way. In this work, the possibilities to create network covert channels over TLS
encrypted connections are evaluated.

In this repository included are:
* Makefile
* tlscc.c
* extractcc.c

****************************************************************************
# tlscc  
A program to transmit data through a covert channel using the TLS protocol

This program establishes a connection to a TLS enabled service and injects
covert data into the connection.

Author:  Corinna Heinz <ch@sysv.de>                                      
License: Creative Commons Zero (CC0)                                     

****************************************************************************


****************************************************************************
# extractcc
A program to extract data from a covert channel using the TLS protocol                                                 

THis program passively listens on a network interface for TLS connections
with covert data and extracts this covert data from the stream. The TLS
stream itself is neither modified nor decrypted.

Author:  Corinna Heinz <ch@sysv.de>
License: Creative Commons Zero (CC0)

****************************************************************************

# Prerequisites

libcrypto (part of OpenSSL)
libpcap   (for packet capturing)

# Compilation

If necessary, edit the paths in the Makefile for openssl, then just run make

# Example

First, start the extract program on an interface, that can see the TLS connection.
This can for example be the outgoing interface of the host, that runs the tlscc
program. The program must run as root, since it needs raw access to the network
traffic.

$ sudo ./extractcc -vi eth1 &
Listening for TLS connections on interface eth1...

Then, run the tlscc injector. This command connects to the https service of
the FernUniversitaet in Hagen and injects the content of the local file
"/etc/motd".

$ ./tlscc -qh www.fernuni-hagen.de -f /etc/motd
Trying 132.176.XXX.XXX... Success!

The extractor should see the connection and extract the covert data.

TLS hello detected, tracking connection...
Found TLS covert channel signature in connection 192.168.0.100:39318 -> 132.176.XXX.XXX:443
[IV-FILE] extract.motd.IV.2 (286 bytes)
Time elapsed             : 266 ms
Total  bytes transmitted : 3221 bytes
Covert bytes transmitted : 296 bytes
Covert bytes pending     : 0 bytes
Total          bandwidth : 96.87 kbit/s
Covert channel bandwidth : 8.90 kbit/s
Covert channel percentage: 9.19%
266,3221,296,0,296,0,0
Connection terminated by FIN, Setting timeout to 3 secs

