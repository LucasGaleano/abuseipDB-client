#! /usr/bin/env python3

from http import client
from time import sleep
from abuseIpDbClient import AbuseIpDb

def log_to_file(file, data):
    with open(file,'a') as logfile:
        data['app'] = "abuseipDB"
        logfile.write(str(data))
        logfile.write('\n')


def print_errors(result):
    for error in result['errors']:
        print(f"[-] {error['detail']}") 
        log_to_file('log.json',error) 


with open('abuseIpDb.key','r') as key:
    abuseipdb = AbuseIpDb(key.readline().strip())

while True:
    with open('cidr.txt','r') as cidrs:
        for cidr in cidrs.readlines():
            cidr = cidr.strip('\n')
            print(f"[+] Checking {cidr}")
            result = abuseipdb.check_block(cidr)
            if 'errors' in result:
                print_errors(result)
            else:
                result = result['data']
                log_to_file('log.json', result)
                for reportedIp in result['reportedAddress']:
                    if reportedIp['abuseConfidenceScore'] > 0:
                        print(f"[-] Reported IP {reportedIp['ipAddress']} found.")
                        reportedIpDetails = abuseipdb.check(reportedIp['ipAddress'])
                        if 'errors' in reportedIpDetails:
                            print_errors(reportedIpDetails)
                        else:
                            log_to_file('log.json', reportedIpDetails['data'])
                            
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

