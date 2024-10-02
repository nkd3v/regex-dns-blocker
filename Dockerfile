FROM python:3.12.6-alpine

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir dnspython

EXPOSE 853

CMD ["python", "main.py"]