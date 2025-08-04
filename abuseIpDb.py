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
from telegramClient import telegramClient
from datetime import datetime
import json


def print_errors(result):
    for error in result['errors']:
        print(f"[-] {error['detail']}") 
        logger.log_to_json(error) 

def has_reputation(reportedIp):
    return reportedIp['abuseConfidenceScore'] > 0

def check_errors(result, errorMessage):
    print(result)
    if 'errors' in result:
        print_errors(result)
        raise ValueError(errorMessage)
        return None
    return result['data']


def get_token(text):
    return re.search('token" value="(.*)"',text).group(1)


def takedown_IP(IP, user, password) -> str:
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

    alreadyReportText = 'Takedown request already pending for this IP address.'
    successfulText = 'alert-success'
    if alreadyReportText != -1:
        return alreadyReportText
    if x.text.find(successfulText) != -1:
        return "takedown successful"

    raise ValueError("Error taking down the IP")


def check_ip(ip):
    reportedIpDetails = abuseipdb.check(ip)
    logger.log_to_console(f'ip checked: {ip}')
    return check_errors(reportedIpDetails,"Invalid IP to check in abuseipDB")

def return_ips_with_reputation(block):
    ips = []
    for cidr24 in CIDRParser.split_cidr(block, '24'):
        result = check_block(cidr24)
        logger.log_to_console(f'block checked: {cidr24}')
        # logger.log_to_console(result)
        for reportedIp in result['reportedAddress']:
            if has_reputation(reportedIp):
                ips.append(reportedIp['ipAddress'])
    logger.log_to_console(f'ips with reputation: {ips}')
    return ips

def check_block(cidr):
    result = abuseipdb.check_block(cidr)
    return check_errors(result, 'invalid cidr to check in abuseipDB')

def send_telegram_notification(message, title):
    telegramResponse = telegram.sendMessage(message,title=title)
    logger.log_to_json(telegramResponse)
    if telegramResponse['ok']:
        print('telegram notification sent')


config = configparser.ConfigParser()
config.read('abuseipDB.conf')

abuseipdb = AbuseIpDb(config['abuseipDB']['token'].split(','))
sleepTime = int(config['general']['sleep_time_sec'])
telegramNotificationEnable = False
takedownIPEnable = False

try:
    if config['telegram']['enable'] == 'yes':
        telegram = telegramClient(botToken=config['telegram']['token'], chatID=config['telegram']['chat_id'])
        telegramNotificationEnable = True
        logger.log_to_json({"info":str("Telegram notification enable")})
except:
    logger.log_to_json({"info":str("Telegram notification disable")})

try:
    if config['takedown']['enable'] == 'yes':  
        takedownUsername = config['takedown']['user']
        takedownPassword = config['takedown']['password']
        takedownIPEnable = True
        logger.log_to_json({"info":str("IP takedown enable")})
except:
    logger.log_to_json({"info":str("IP takedown disable")})


if __name__ == "__main__":
    while True:
        cidrs = CIDRParser()
        with open('cidr.txt','r') as cidrs_file:
            for cidr in cidrs_file.readlines():
                try:
                    cidrs.add_cidr(cidr)
                except Exception as e:
                    logger.log_to_json({"error":str(e)})

        for cidr in cidrs.cidr_strings:
            ips = []
            if CIDRParser.is_network(cidr):
                ips = return_ips_with_reputation(cidr)
            else:
                ips.append(cidr)
            for ip in ips:
                try:
                    logger.log_to_console(f'IP to check: {ip}')
                    result = check_ip(ip)
                    logger.log_to_console(f'result: {result}')
                    result['app'] = "abuseipDB"
                    result['timestamp'] = datetime.isoformat(datetime.now())
                    result['abuseipDB_url'] = f'https://www.abuseipdb.com/check/{result["ipAddress"]}'

                    if has_reputation(result):
                        logger.log_to_json(result)
                        if telegramNotificationEnable:
                            send_telegram_notification(message=result, title="AbuseipDB")
                        if takedownIPEnable:
                            ip = result['ipAddress']
                            takedownResult = takedown_IP(ip, takedownUsername, takedownPassword)
                            if takedownResult:
                                logger.log_to_json({"info":takedownResult,"ipAddress":result['ipAddress']})

                except Exception as e:
                    logger.log_to_json({"error":str(e)})

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
