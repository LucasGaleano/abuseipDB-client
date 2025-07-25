from datetime import datetime
import json
import configparser

class loggerHelper:

    def __init__(self, enable=True):
        self.enable = enable
        

    def log_to_json(self, data):
        if self.enable:
            with open('log.json','a') as logfile:
                data['app'] = "abuseipDB"
                data['timestamp'] = datetime.isoformat(datetime.now())
                print(json.dumps(data))
                logfile.write(json.dumps(data))
                logfile.write('\n')

config = configparser.ConfigParser()
config.read('abuseipDB.conf')

enableJson = True
if config['logging']['log_json'] != 'yes':
    enableJson = False

logger = loggerHelper(enable=enableJson)
