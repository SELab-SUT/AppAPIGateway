FROM python:3

WORKDIR /app
COPY requirements.txt .
RUN pip3 install -r requirements.txt
COPY . .

ENV FLASK_APP=api_gateway.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=80

EXPOSE 80

ENTRYPOINT [ "flask" ]
CMD [ "run" ]