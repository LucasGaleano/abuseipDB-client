import requests
from random import choice

class AbuseIpDb(object):

    CATEGORIES = {
        'DDOS_ATTACK': '4',
        'FTP_BRUTE_FORCE': '5',
        'PING_OF_DEATH': '6',
        'PHISHING': '7',
        'FRAUD_VOIP': '8',
        'OPEN_PROXY': '9',
        'WEB_SPAM': '10',
        'EMAIL_SPAM': '11',
        'BLOG_SPAM': '12',
        'VPN_IP': '13',
        'PORT_SCAN': '14',
        'HACKING': '15',
        'SQL_INJECTION': '16',
        'SPOOFING': '17',
        'BRUTE_FORCE': '18',
        'BAD_WEB_BOT': '19',
        'EXPLOITED_HOST': '20',
        'WEB_APP_ATTACK': '21',
        'SSH': '22',
        'IOT_TARGETED': '23',
    }

    default = {"CONFIDENCE_MINIMUM": 100,
               "LIMIT": 10000}

    def __init__(self, api_keys: list[str], subscriber=False):
        if not api_keys:
            raise ValueError('An API key is required')
        self._api_keys = api_keys
        self._subscriber = subscriber

    def __getattr__(self, name):
        raise NotImplementedError('{} not available in APIv2'.format(name))

    def _get_response(self, endpoint, query):
        BASE_URL = 'https://api.abuseipdb.com/api/v2/{endpoint}'
        KNOWN_ENDPOINTS = {
            'blacklist': 'GET',
            'bulk-report': 'POST',
            'check': 'GET',
            'check-block': 'GET',
            'report': 'POST',
        }
        if endpoint not in KNOWN_ENDPOINTS.keys():
            msg = 'Unknown endpoint "{}"'
            raise NotImplementedError(msg.format(endpoint))
        headers = {'Key': choice(self._api_keys), 'Accept': 'application/json'}
        response = requests.request(
            method=KNOWN_ENDPOINTS[endpoint],
            url=BASE_URL.format(endpoint=endpoint),
            headers=headers, params=query)
        return response.json()

    def blacklist(self, confidence_minimum=None, limit=None):
        query = {}
        if self._subscriber and confidence_minimum:
            if confidence_minimum < 25 or confidence_minimum > 100:
                msg = 'Confidence minimum "{}" not in the range from 25 to 100)'
                raise ValueError(msg.format(confidence_minimum))
            query['confidenceMinimum'] = str(confidence_minimum)
        if limit is not None:
            if limit < 1:
                raise ValueError('Limit must be greater than 0')
            if limit > self.default["LIMIT"] and not self._subscriber:
                msg = 'Limit {} is above {}, which is not allowed, unless you\'re a subscriber'
                raise ValueError(msg.format(limit, self.default["LIMIT"]))
            query['limit'] = str(limit)
        return self._get_response('blacklist', query)

    def bulk_report(self, file_name):
        raise NotImplementedError('bulk_report not yet available.  Implementation still pending.')

    def check(self, ip_address, max_age_in_days=None):
        query = {
            'ipAddress': ip_address,
            'maxAgeInDays': max_age_in_days
        }
        return self._get_response('check', query)

    def check_block(self, cidr_network, max_age_in_days=None):
        query = {
            'network': cidr_network,
            'maxAgeInDays': max_age_in_days
        }
        return self._get_response('check-block', query)

    def report(self, ip_address, categories, comment=None):
        query = {
            'ip': ip_address,
            'categories': categories,
            'comment': comment,
        }
        return self._get_response('report', query)