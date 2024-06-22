FROM python:3.13.0a4
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "-u","./abuseIpDb.py"]


#docker image rm -f abuseipdb; docker build --tag abuseipdb .
#docker run --rm abuseipdb | tee -a log.json
