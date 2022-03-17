# abuseipDB-client

## How it works
Create a config file name absueipDB.conf with this information in the root directory. (there is a example file in the repository)

```
[abuseipDB]
token = token_key

[netbox]
token = token_key
host = https://example.com
```

## What it does
Checks all the networks in the file cidr.txt against abuseipDB API and records the IPs inside the networks with reputation score.
The script also checks the IP with reputation against netbox if the api key is provide in the config file.

## Logging
The script will log all the events to log.json as a json format.
