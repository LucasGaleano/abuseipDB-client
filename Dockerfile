FROM python:3.13.0a4
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "-u","./abuseIpDb.py"]


#docker image rm -f testing; docker build --tag testing .