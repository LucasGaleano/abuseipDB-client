#! /usr/bin/env python3

from time import sleep
from abuseIpDbClient import AbuseIpDb
import configparser
import pynetbox
import ipaddress

def log_to_file(file, data):
    with open(file,'a') as logfile:
        data['app'] = "abuseipDB"
        logfile.write(str(data).replace("'",'"').replace("True","true").replace("False","false"))
        logfile.write('\n')

def split_cidr(cidr, minMask):
    cidr = ipaddress.IPv4Network(cidr.strip('\n'))
    if int(minMask) <= cidr.prefixlen:
        return [cidr.with_prefixlen]
    try:   
        return [net.with_prefixlen for net in cidr.subnets(new_prefix=int(minMask))]
    except Exception as e:
        print(cidr,e)
        return []

def print_errors(result):
    for error in result['errors']:
        print(f"[-] {error['detail']}") 
        log_to_file('log.json',error) 

def has_reputation(reportedIp):
    return reportedIp['abuseConfidenceScore'] > 0

def add_netbox_info(reportedIp):
    print(f"[+] Checking {reportedIp['ipAddress']} in Netbox.")
    netboxRequest = nb.ipam.ip_addresses.filter(address=reportedIp['ipAddress'])
    ips = list(netboxRequest)
    if ips:
        ip = ips[0]
        reportedIp['netbox'] = {}
        reportedIp['netbox']['description'] = ip.description
        reportedIp['netbox']['dns_name'] = ip.dns_name
        reportedIp['netbox']['status'] = ip.status
        reportedIp['netbox']['tenant'] = ip.tenant
        reportedIp['netbox']['created'] = ip.created
        reportedIp['netbox']['test'] = ip.address
    return reportedIp


config = configparser.ConfigParser()
config.read('config')

if 'netbox' in config:
    nb = pynetbox.api(config['netbox']['host'], token=config['netbox']['token'].strip())

abuseipdb = AbuseIpDb(config['abuseipDB']['token'].strip())

while True:
    try:
        with open('cidr.txt','r') as cidrs:
            for cidr in cidrs.readlines():
                cidr = cidr.strip('\n')
                print(f"[+] Checking {cidr}")
                for cidr24 in split_cidr(cidr, '24'):
                    result = abuseipdb.check_block(cidr24)
                    if 'errors' in result:
                        print_errors(result)
                    else:
                        result = result['data']
                        log_to_file('log.json', result)
                        for reportedIp in result['reportedAddress']:
                            if has_reputation(reportedIp):
                                print(f"[-] Reported IP {reportedIp['ipAddress']} found.")
                                reportedIpDetails = abuseipdb.check(reportedIp['ipAddress'])
                                if 'errors' in reportedIpDetails:
                                    print_errors(reportedIpDetails)
                                else:
                                    if 'netbox' in config:
                                        reportedIpDetails = add_netbox_info(reportedIpDetails['data'])
                                    log_to_file('log.json', reportedIpDetails)
    except Exception as e:
        print(f"[-] Error: {e}")
                  
    sleepTime = 60*60*24 
    print(f"[+] Waiting {sleepTime} seconds.")
    sleep(sleepTime)


#block with no ip reported
# {
#     "networkAddress":"87.117.96.0",
#     "netmask":"255.255.255.0",
#     "minAddress":"87.117.96.1",
#     "maxAddress":"87.117.96.254",
#     "numPossibleHosts":254,
#     "addressSpaceDesc":"Internet",
#     "reportedAddress":[      
#     ]
# }

#block with ip reported
# {
#    "networkAddress":"185.40.106.0",
#    "netmask":"255.255.255.0",
#    "minAddress":"185.40.106.1",
#    "maxAddress":"185.40.106.254",
#    "numPossibleHosts":254,
#    "addressSpaceDesc":"Internet",
#    "reportedAddress":[
#       {
#          "ipAddress":"185.40.106.117",
#          "numReports":1,
#          "mostRecentReport":"2022-01-21T01:48:38+00:00",
#          "abuseConfidenceScore":4,
#          "countryCode":"TR"
#       }
#    ]
# }

#IP with ip reputation
#{'ipAddress': '185.40.106.117', 'numReports': 1, 'mostRecentReport': '2022-01-21T01:48:38+00:00', 'abuseConfidenceScore': 4, 'countryCode': 'TR'}

