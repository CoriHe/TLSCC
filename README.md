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
* MAKEFILE
* tlscc.c
* extractcc.c

****************************************************************************
# tlscc  
A program to transmit data through a covert channel using the TLS protocol
                                                                          
This program is part of the master thesis "Network covert channels in Transport Layer Security protocol and their detection" 
submitted to the FernUniversitaet in Hagen at 2020-02-23                              
                                                                         
Author:  Corinna Heinz <ch@sysv.de>                                      
License: Creative Commons Zero (CC0)                                     

****************************************************************************


****************************************************************************
# extractcc
A program to extract data from a covert channel using the TLS protocol                                                 
                                                                         
This program is part of the master thesis "Network covert channels in    
Transport Layer Security protocol and their detection" submitted to      
the FernUniversitaet in Hagen at 2020-02-23                              
                                                                          
Author:  Corinna Heinz <ch@sysv.de>
License: Creative Commons Zero (CC0)
****************************************************************************
