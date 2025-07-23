#! /usr/bin/env python3

from time import sleep
import time
from datetime import datetime
from abuseIpDbClient import AbuseIpDb
import configparser
import json
import ipaddress
import requests
import re
from cidr_parser import CIDRParser


def log_to_json(data):
    # with open(file,'a') as logfile:
    data['app'] = "abuseipDB"
    data['timestamp'] = datetime.isoformat(datetime.now())
    print(json.dumps(data))
        # logfile.write(json.dumps(data))
        # logfile.write('\n')

def split_cidr(cidr, minMask):
    if ':' in cidr:
        cidr = ipaddress.IPv6Network(cidr.strip('\n'))
    else:
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
        log_to_json(error) 

def has_reputation(reportedIp):
    return reportedIp['abuseConfidenceScore'] > 0

def check_errors(result):
    if 'errors' in result:
        print_errors(result)
        return None
    return result['data']

def check_ip(IP):
    print(f"[-] Reported IP {IP['ipAddress']} found.")
    reportedIpDetails = abuseipdb.check(IP['ipAddress'])
    return check_errors(reportedIpDetails)


def check_block(cidr):
    result = abuseipdb.check_block(cidr)
    return check_errors(result)

def add_netbox_info(reportedIp):
    print(f"[+] Checking {reportedIp['ipAddress']} in Netbox.")
    netboxRequest = nb.ipam.ip_addresses.filter(address=reportedIp['ipAddress'])
    ips = list(netboxRequest)
    if ips:
        ip = ips[0]
        reportedIp['netbox'] = {}
        reportedIp['netbox']['description'] = ip.description
        reportedIp['netbox']['dns_name'] = ip.dns_name
        reportedIp['netbox']['status'] = str(ip.status)
        reportedIp['netbox']['tenant'] = str(ip.tenant)
        reportedIp['netbox']['created'] = ip.created
        reportedIp['netbox']['address'] = ip.address
    return reportedIp


def get_token(text):
    return re.search('token" value="(.*)"',text).group(1)


def takedown_IP(IP, user, password):
    url_login = 'https://www.abuseipdb.com/login'
    data_login = {'_token': '',
            'email': user,
            'password': password}

    headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'}

    s = requests.Session()
    temp = s.get('https://www.abuseipdb.com/login', headers=headers)
    data_login['_token'] = get_token(temp.text)

    x = s.post(url_login, json = data_login, headers=headers)
    time.sleep(5)


    temp = s.get('https://www.abuseipdb.com/takedown/'+IP, headers=headers)
    url_takedown = 'https://www.abuseipdb.com/user/takedown-request'
    data_takedown = {'_token': get_token(temp.text),
            'details': '',
            'ip': IP}

    x = s.post(url_takedown, json = data_takedown, headers=headers)
    time.sleep(5)
    
    return x.text.find('alert-success') != -1



config = configparser.ConfigParser()
config.read('abuseipDB.conf')

# Initialize netbox api
# if 'netbox' in config:
#     nb = pynetbox.api(config['netbox']['host'], token=config['netbox']['token'].strip())

# Initialize abusedbip API
#
abuseipdb = AbuseIpDb(config['abuseipDB']['tokens'].split(','))



while True:
    with open('cidr.txt','r') as cidrs_file:
        cidrs = CIDRParser(cidrs_file.readlines())

    print(cidrs)
    check_ip(reportedIp)

    # for cidr in cidrs.readlines():
    #     cidr = cidr.strip('\n')
    #     print(cidr)


    sleepTime = 60*60*24 
    print(f"[+] Waiting {sleepTime} seconds.")
    sleep(sleepTime)



while True:
    try:
        with open('cidr.txt','r') as cidrs:
            for cidr in cidrs.readlines():
                cidr = cidr.strip('\n')
                print(f"[+] Checking {cidr}")
                for cidr24 in split_cidr(cidr, '24'):
                    result = check_block(cidr24)
                    if result:
                        log_to_json(result)
                        # Check for the reported IP inside the result.
                        for reportedIp in result['reportedAddress']:
                            if has_reputation(reportedIp):
                                reportedIpDetails = check_ip(reportedIp)
                                # I closed the value between an array so Wazuh can read it as number.
                                reportedIpDetails['abuseConfidence'] = [{"score":reportedIpDetails['abuseConfidenceScore']}]
                                reportedIpDetails['abuseipDB_url'] = f'https://www.abuseipdb.com/check/{reportedIpDetails["ipAddress"]}'
                                if config['abuseipDB']['user'] != "user":
                                    result = takedown_IP(reportedIp['ipAddress'], config['abuseipDB']['user'], config['abuseipDB']['password'])
                                    if result:
                                        print(f"[+] request takedown {reportedIp['ipAddress']}")
                                if reportedIpDetails:
                                    if 'netbox' in config:
                                        reportedIpDetails = add_netbox_info(reportedIpDetails)
                                    log_to_json(reportedIpDetails)

    except Exception as e:
        print(f"[-] Error: {e}")

    # Wait for 1 day.               
    sleepTime = 60*60*24 
    print(f"[+] Waiting {sleepTime} seconds.")
    sleep(sleepTime)
