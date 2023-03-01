FROM python:3.8.12-slim-buster

RUN apt-get update

RUN yes | apt-get install python3-dev build-essential

RUN pip install --upgrade pip

# COPY requirements.txt /rasa_traind/ # Works
COPY . /rasa_traind/

RUN pip install -r requirements.txt

WORKDIR /rasa_traind/rasa_actions_server/

CMD ["rasa", "run"]
