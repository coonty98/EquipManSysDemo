# syntax=docker/dockerfile:1

FROM python:3.12-alpine3.21

WORKDIR /python-docker

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

# CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0", "--port=5050"]

RUN pip install gunicorn
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5050", "app:app"]