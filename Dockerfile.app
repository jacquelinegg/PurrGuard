FROM python:3.12-slim
WORKDIR /app
COPY app/ /app/app/
# The carrier app/assets/logo.png contains the encrypted secrets; it is a normal app asset.
EXPOSE 8080
CMD ["python", "app/server.py"]
