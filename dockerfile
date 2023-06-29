FROM python:3.8

WORKDIR /code

COPY requirements.txt requirements.txt

RUN pip install -r requirements.txt

EXPOSE 5000
COPY ./utils/ .
COPY ./models/ .
COPY ./main.py .
COPY ./handler.py .

CMD ["python", "main.py"]