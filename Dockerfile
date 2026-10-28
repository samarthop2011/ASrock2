FROM python:3.12-slim
RUN useradd -m -u 10001 hunter
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p data && chown -R hunter:hunter /app
USER hunter
CMD ["python", "hunter.py", "-c", "config.yaml"]
