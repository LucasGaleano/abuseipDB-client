# abuseipDB-client

This script will check the networks in cidr.txt, divide the networks in /24 mask and check against abuseIPDB looking for IPs with reputation.


## How it works
Create a config file name abuseipDB.conf with this information in the root directory. (there is a example file in the repository)

```
[abuseipDB]
token = token_key

[takedown]
token = token_key
host = https://example.com
```

## Create a virtual enviroment
python3 -m venv test
source test/bin/activate

Don't forget the pip3 install -r requirements.txt

then start the program `python3 abuseipDB.py`

I recommend run the program on the background with the command `screen` or adding a '&' at the end of the command.

## What it does
Checks all the networks in the file cidr.txt against abuseipDB API and records the IPs inside the networks with reputation score.
The IPs are also saved with the title of the block in the cidr.txt
for example:

```
[example inc.]
1.1.1.1/29
2.2.2.2/22
3.3.3.3

[evil corp.]
4.4.4.4/30
5.5.5.5
```

### Jira integration

The program will create and update a ticket in jira relate with the IP found, except for the ticket with the status of 'Done'

### Telegram integration

The program has a threshold which after the value define will send a notificacion to a group in telegram. 

## Logging
The script will log all the events to log.json as a json format.

You should use this config for the logrotate inside /etc/logrotate.d/okta
```
/path/to/file/log.json {
    su <user> <group>
    rotate 5
    size 1G
    copytruncate
}
```
