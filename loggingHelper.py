from datetime import datetime
import json
import configparser

class loggerHelper:

    def __init__(self, enableJson=True, debug=False):
        self.enableJson = enableJson
        self.debug = debug
        

    def log_to_json(self, data):
        if self.enableJson:
            with open('log.json','a') as logfile:
                print(json.dumps(data))
                logfile.write(json.dumps(data))
                logfile.write('\n')

    def log_to_console(self, message):
        if self.debug:
            print(message)

config = configparser.ConfigParser()
config.read('abuseipDB.conf')

enableJson = True
if config['logging']['log_json'] != 'yes':
    enableJson = False

logger = loggerHelper(enableJson=enableJson, debug=True)
