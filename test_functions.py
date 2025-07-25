from abuseIpDb import return_ips_with_reputation, is_network

# def test_es_red_valida():
#     result = return_ips_with_reputation("192.168.1.0/24")
#     assert isinstance(result, list), "La función debería devolver una lista"


def test_es_red_valida():
    assert is_network("192.168.1.0/24") is True

def test_es_red_invalida():
    assert is_network("192.168.1.123") is False

def test_es_red_valida2():
    assert is_network("192.168.1.123/32") is True

'''
check_block
{'networkAddress': '8.8.8.0', 'netmask': '255.255.255.0', 'minAddress': '8.8.8.0', 'maxAddress': '8.8.8.255', 'numPossibleHosts': 256, 'addressSpaceDesc': 'Internet', 'reportedAddress': [{'ipAddress': '8.8.8.0', 'numReports': 1, 'mostRecentReport': '2025-07-21T05:22:17+00:00', 'abuseConfidenceScore': 4, 'countryCode': 'US'}, {'ipAddress': '8.8.8.1', 'numReports': 1, 'mostRecentReport': '2025-07-21T05:22:14+00:00', 'abuseConfidenceScore': 4, 'countryCode': 'US'}, {'ipAddress': '8.8.8.2', 'numReports': 1, 'mostRecentReport': '2025-07-21T05:22:13+00:00', 'abuseConfidenceScore': 4, 'countryCode': 'US'}, {'ipAddress': '8.8.8.3', 'numReports': 1, 'mostRecentReport': '2025-07-21T05:22:16+00:00', 'abuseConfidenceScore': 4, 'countryCode': 'US'}, {'ipAddress': '8.8.8.5', 'numReports': 1, 'mostRecentReport': '2025-07-21T05:22:18+00:00', 'abuseConfidenceScore': 4, 'countryCode': 'US'}, {'ipAddress': '8.8.8.7', 'numReports': 1, 'mostRecentReport': '2025-07-21T05:22:17+00:00', 'abuseConfidenceScore': 4, 'countryCode': 'US'}, {'ipAddress': '8.8.8.8', 'numReports': 81, 'mostRecentReport': '2025-07-23T03:12:26+00:00', 'abuseConfidenceScore': 0, 'countryCode': 'US'}, {'ipAddress': '8.8.8.11', 'numReports': 1, 'mostRecentReport': '2025-07-21T05:22:15+00:00', 'abuseConfidenceScore': 4, 'countryCode': 'US'}]}

check_ip
{'ipAddress': '8.8.8.0', 'isPublic': True, 'ipVersion': 4, 'isWhitelisted': False, 'abuseConfidenceScore': 4, 'countryCode': 'US', 'usageType': 'Content Delivery Network', 'isp': 'Google LLC', 'domain': 'google.com', 'hostnames': [], 'isTor': False, 'totalReports': 1, 'numDistinctUsers': 1, 'lastReportedAt': '2025-07-21T05:22:17+00:00'}

'''