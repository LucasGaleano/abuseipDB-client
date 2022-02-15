from http import client
from math import ulp
from this import d
from abuseIpDbClient import AbuseIpDb


def print_errors(result):
    for error in result['errors']:
        print(f"[-] {error['detail']}")  

with open('abuseIpDb.key','r') as key:
    abuseipdb = AbuseIpDb(key.readline())

with open('cidr.txt','r') as cidrs:
    for cidr in cidrs.readlines():
        cidr = cidr.strip('\n')
        print(f"[+] Checking {cidr}")
        result = abuseipdb.check_block(cidr)
        #print(result)
        if 'errors' in result:
            print_errors(result)
        else:
            result = result['data']        
            for reportedIp in result['reportedAddress']:
                if reportedIp['abuseConfidenceScore'] > 0:
                    print(f"[-] reported IP {reportedIp['ipAddress']}")
                    reportedIpDetails = abuseipdb.check(reportedIp['ipAddress'])
                    if 'status' in result:
                        print_errors(result)
                    else:
                        print(reportedIp)
                        reportedIpDetails['data']['abuseipDB'] = "abuseipDB"
                        with open('log.json','a') as logfile:
                            logfile.write(str(reportedIpDetails['data']))
                            logfile.write('\n')

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
