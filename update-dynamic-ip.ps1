# PowerShell script to update dynamic DNS information
# Copyright (c) 2012, Jacob Quant
# MIT License, http://www.opensource.org/licenses/mit-license.php
# ----------------------------------------------------------------------------
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
# ----------------------------------------------------------------------------
$global:usage_information = @"
 Usage: update-dynamic-dns.ps1 <Parameters>
 Parameters
 -a, --address <IP Address>                        Specifies a fixed IP address to be used (incompatible with -l)
 -b, --base-url <URL>                              Specifies the base URL to which the request will be sent. 
                                                   The default is http://freedns.afraid.org/dynamic/update.php
 -c, --authorization-code <Code>                   Specifies the authorization code to use (will be appended to the base URL)
 -d, --dhcp-only                                   When set, the script will exclude network adapters that are not configured to use DHCP
 -h, --help                                        Display this message
 -i, --ignore-rfc1918-addresses                    When set, the script will exclude any private (RFC1918 reserved) addresses from being used (has no effect without -l)
 -l, --use-local-ip [<Network Connection Name>]    When set, the script uses an IP address from the system instead of sending a fixed address or relying on the remote server (incompatible with -a)
 -v, --version                                     When set, the program just displays version information and then exits
"@
$global:version_information = "v1.0, 20120604"

$config = New-Module -Name DynamicDNSUpdaterConfiguration {            
    [string]$address = ""            
    [string]$base_url = "http://freedns.afraid.org/dynamic/update.php"
    [string]$authorization_code = ""
    [bool]$show_help = $false
    [bool]$use_remote_ip = $true
    [bool]$dhcp_only = $false
    [bool]$ignore_rfc1918 = $true
    [string]$network_connection_name = ""
    [int]$adapter_index = 0
    [bool]$version = $false

    function load_from_arguments($parameters) {
        for($i = 0; $i -lt $parameters.length; $i++) {
            switch ($parameters[$i]) { 
                {($_ -eq "-a") -or ($_ -eq "--address")} {$script:address = $parameters[++$i]} 
                {($_ -eq "-b") -or ($_ -eq "--base-url")} {$script:base_url = $parameters[++$i]} 
                {($_ -eq "-c") -or ($_ -eq "--authorization-code")} {$script:authorization_code = $parameters[++$i]} 
                {($_ -eq "-d") -or ($_ -eq "--dhcp-only")} {$script:dhcp_only = $true}
                {($_ -eq "-h") -or ($_ -eq "--help")} {$script:show_help = $true}
                {($_ -eq "-i") -or ($_ -eq "--ignore-rfc1918-addresses")} {$script:ignore_rfc1918 = $true}
                {($_ -eq "-l") -or ($_ -eq "--use-local-ip")} {
                    $script:use_remote_ip = $false;
                    if ($parameters[$i+1][0] -ne "-") {
                        $script:network_connection_name = $parameters[++$i]                       
						# Get interface index of adapter named with -s option
						#$interface_index = (gwmi Win32_NetworkAdapter | where { $_.NetConnectionID -eq $script:network_connection_name }).InterfaceIndex
						#$index = (gwmi Win32_NetworkAdapter | where { $_.NetConnectionID -eq $script:network_connection_name }).Index
                        $script:adapter_index = (gwmi Win32_NetworkAdapter | where { $_.NetConnectionID -eq $script:network_connection_name }).InterfaceIndex
                        if ($script:adapter_index -eq $null -or $script:adapter_index -eq 0) {throw "Error: could not determine adapter index for $script:network_connection_name"} 
                    } 
                } 
                #{($_ -eq "-r") -or ($_ -eq "--use-remote-ip")} { $script:use_remote_ip = $true } 
                {($_ -eq "-v") -or ($_ -eq "--version")} {"Version = $global:version_information"}
                default {throw "Unknown option received by load_from_arguments ($_)!"}
            }

        }
    
    }            
    Export-ModuleMember -Variable * -Function *                
} -asCustomObject   


#DEBUG
#$args|Format-List|Out-Host

$config.load_from_arguments($args)
if ($config.show_help -eq $true) {
    $global:usage_information
    exit
}


#DEBUG
#$config | Format-List

# Get a list of all interesting IP addresses on the system
$condition_to_ignore_local = "-not(`$_ -like 'fe80::*')"
$condition_to_ignore_rfc1918 = "-not(`$_ -like '192.168.*') -and -not(`$_ -like '172.16.*') -and -not(`$_ -like '10.*')"
$condition_to_require_dhcp = "`$_.DHCPEnabled -eq `$true"
$condition_to_use_specific_adapter  = "(`$_.InterfaceIndex -eq `$config.adapter_index)"

# Make array of conditions we want to apply
$conditions = @($condition_to_ignore_local)

$ip_address = gwmi Win32_NetworkAdapterConfiguration | where { $_.IPAddress }

#"Interfaces w/ IP addresses detected:"
#$ip_address
"-----"

if ($config.use_remote_ip -eq $false) {
    if ($config.network_connection_name.length -gt 0) {
        $conditions += $condition_to_use_specific_adapter
    } 
    else {
        if ($config.ignore_rfc1918) {
            $conditions += $condition_to_ignore_rfc1918
        }
        if ($config.dhcp_only) {
            $conditions += $condition_to_require_dhcp
        }
    }
    $ip_address = $ip_address | where { iex( $([string]::join(" -and ", $conditions)) ) } | select -Expand IPAddress 
    # If there is more than one result then just take the first one and hope it's right :)
    if ($ip_address -and $ip_address.GetType().Name -eq "Object[]") {
        $ip_address = $ip_address[0]
    } 
}

#DEBUG
#"Conditions:"
#$([string]::join(" -and ", $conditions)) 
#"-----"


#"Result:"
#$ip_address

# Prepare HTTP request to update the dynamic DNS entry
$url_parameters = @()
if ($config.authorization_code.length -gt 0) {
    $url_parameters += $config.authorization_code
}
if ($config.use_remote_ip -eq $false) {
    $url_parameters += "address=$ip_address"
}
"URL to POST --> " + $config.base_url + "?" + $([string]::join("&", $url_parameters)) 


$webclient = New-Object System.Net.WebClient
$payload = "";
$result = $webclient.UploadString($config.base_url + "?" + $([string]::join("&", $url_parameters)), $payload)
$result | Format-List
