FROM python:3.12-slim
WORKDIR /app
COPY app/ /app/app/
# Носителят app/assets/logo.png съдържа криптираните тайни; той е нормален актив на приложението.
EXPOSE 8080
CMD ["python", "app/server.py"]
