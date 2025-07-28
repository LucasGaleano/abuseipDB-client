import requests
from dataclasses import dataclass
import json

@dataclass
class telegramClient:
    botToken : str
    chatID: str


    def sendMessage(self, message:str, jsonmessage=True, title=None) -> json:


        url = f'https://api.telegram.org/bot{self.botToken}/sendMessage'
        if jsonmessage:
            # message = json.dumps(message, indent=2),
            formatMessage = ''
            if title:
                formatMessage = f'<b>{title}</b>\n\n'
            
            for key, value in message.items():
                formatMessage += f'<b>{key}:</b> {value}\n'
            message = formatMessage
        payload = {
            'chat_id': self.chatID,
            'text': message,
            "parse_mode": "html"

                
        }
        response = requests.post(url, data=payload)
        return response.json()