FROM python:3.6.4-alpine

WORKDIR /app

COPY ./requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8080

CMD python3 calendar_manager.py config.json