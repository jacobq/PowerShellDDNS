PowerShellDDNS
==============
PowerShell script to update dynamic DNS information
Copyright (c) 2012, Jacob Quant
MIT License, http://www.opensource.org/licenses/mit-license.php

This script was designed to provide a simple, automatable way to update DNS information on http://freedns.afraid.org or similar services

Usage: update-dynamic-dns.ps1 <Parameters>
Parameters:
	-a, --address <IP Address>                        Specifies a fixed IP address to be used (incompatible with -l)
	-b, --base-url <URL>                              Specifies the base URL to which the request will be sent. 
                                                      The default is http://freedns.afraid.org/dynamic/update.php
	-c, --authorization-code <Code>                   Specifies the authorization code to use (will be appended to the base URL)
	-d, --dhcp-only                                   When set, the script will exclude network adapters that are not configured to use DHCP
	-h, --help                                        Display this message
	-i, --ignore-rfc1918-addresses                    When set, the script will exclude any private (RFC1918 reserved) addresses from being used (has no effect without -l)
	-l, --use-local-ip [<Network Connection Name>]    When set, the script uses an IP address from the system instead of sending a fixed address or relying on the remote server (incompatible with -a)
	-v, --version                                     When set, the program just displays version information and then exits
