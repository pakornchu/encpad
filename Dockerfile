FROM debian:latest
RUN apt-get update \
&& apt-get -y upgrade \
&& apt-get -y install python3-pip \
&& pip3 install Crypto Flask gunicorn flask-talisman
COPY ./code /code
ENV FLASK_APP=mainapp
WORKDIR /code
CMD gunicorn --bind 0.0.0.0:$PORT mainapp:app