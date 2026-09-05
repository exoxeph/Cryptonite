FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /data/encrypted_uploads

EXPOSE 5000

CMD ["flask", "--app", "app:create_app", "run", "--host=0.0.0.0", "--port=5000"]
