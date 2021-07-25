FROM python:3.8-alpine3.11

RUN apk add --update --no-cache gcc alpine-sdk linux-headers

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

COPY ./app .
COPY app.ini .
RUN pip3 install -r requirements.txt
RUN pip3 install uwsgi

RUN echo -e "uwsgi\nuwsgi" | adduser uwsgi

EXPOSE 5000
CMD ["uwsgi", "--ini", "app.ini"]