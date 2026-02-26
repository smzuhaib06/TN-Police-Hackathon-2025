# Dockerfile for TOR Unveil Stem backend
FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV BACKEND_PORT=5000
ENV API_KEY=changeme
EXPOSE 5000
CMD ["python", "stem_service.py"]
