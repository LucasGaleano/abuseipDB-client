#! /usr/bin/env python3

from time import sleep
import time
from abuseIpDbClient import AbuseIpDb
import configparser
import ipaddress
import requests
import re
from cidr_parser import CIDRParser
from loggingHelper import logger


def split_cidr(cidr, minMask):
    if ':' in cidr:
        cidr = ipaddress.IPv6Network(cidr.strip('\n'), strict=False)
    else:
        cidr = ipaddress.IPv4Network(cidr.strip('\n'), strict=False)
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
        logger.log_to_json(error) 

def has_reputation(reportedIp):
    return reportedIp['abuseConfidenceScore'] > 0

def check_errors(result):
    if 'errors' in result:
        print_errors(result)
        return None
    return result['data']


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

    
def is_address(valor: str) -> bool:
    try:
        ipaddress.ip_address(valor)
        return True
    except ValueError:
        return False

def is_network(valor: str) -> bool:
    return not is_address(valor)

def check_ip(cidr):
    if is_network(cidr):
        for cidr24 in split_cidr(cidr, '24'):
            result = check_block(cidr24)
            for reportedIp in result['reportedAddress']:
                if has_reputation(reportedIp):
                    reportedIpDetails = check_ip(reportedIp)

    #print(f"[-] Reported IP {ip} found.")
    reportedIpDetails = abuseipdb.check(ip)
    return check_errors(reportedIpDetails)

def return_ips_with_reputation(block):
    ips = []
    for cidr24 in split_cidr(block, '24'):
        result = check_block(cidr24)
        #print(result)
        for reportedIp in result['reportedAddress']:
            if has_reputation(reportedIp):
                ips.append(reportedIp['ipAddress'])
    return ips

def check_block(cidr):
    result = abuseipdb.check_block(cidr)
    return check_errors(result)


config = configparser.ConfigParser()
config.read('abuseipDB.conf')

abuseipdb = AbuseIpDb(config['abuseipDB']['tokens'].split(','))
sleepTime = int(config['general']['sleep_time_sec']) 


if __name__ == "__main__":
    while True:
        with open('cidr.txt','r') as cidrs_file:
            cidrs = CIDRParser(cidrs_file.readlines())

        for cidr in cidrs.cidr_strings:
            ips = []
            if is_network(cidr):
                ips = return_ips_with_reputation(cidr)
            else:
                ips.append(cidr)
            for ip in ips:
                result = check_ip(ip)
                logger.log_to_json(result)

        print(f"[+] Waiting {sleepTime/60} min.")
        sleep(sleepTime)



# while True:
#     try:
#         with open('cidr.txt','r') as cidrs:
#             for cidr in cidrs.readlines():
#                 cidr = cidr.strip('\n')
#                 print(f"[+] Checking {cidr}")
#                 for cidr24 in split_cidr(cidr, '24'):
#                     result = check_block(cidr24)
#                     if result:
#                         log_to_json(result)
#                         # Check for the reported IP inside the result.
#                         for reportedIp in result['reportedAddress']:
#                             if has_reputation(reportedIp):
#                                 reportedIpDetails = check_ip(reportedIp)
#                                 # I closed the value between an array so Wazuh can read it as number.
#                                 reportedIpDetails['abuseConfidence'] = [{"score":reportedIpDetails['abuseConfidenceScore']}]
#                                 reportedIpDetails['abuseipDB_url'] = f'https://www.abuseipdb.com/check/{reportedIpDetails["ipAddress"]}'
#                                 if config['abuseipDB']['user'] != "user":
#                                     result = takedown_IP(reportedIp['ipAddress'], config['abuseipDB']['user'], config['abuseipDB']['password'])
#                                     if result:
#                                         print(f"[+] request takedown {reportedIp['ipAddress']}")
#                                 if reportedIpDetails:
#                                     if 'netbox' in config:
#                                         reportedIpDetails = add_netbox_info(reportedIpDetails)
#                                     log_to_json(reportedIpDetails)

#     except Exception as e:
#         print(f"[-] Error: {e}")

#     # Wait for 1 day.               
#     sleepTime = 60*60*24 
#     print(f"[+] Waiting {sleepTime} seconds.")
#     sleep(sleepTime)
