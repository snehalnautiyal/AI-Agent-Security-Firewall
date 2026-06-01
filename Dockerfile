FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (cached layer)
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

# Copy source
COPY guardlayer/ guardlayer/

EXPOSE 8080

# Default target is OpenAI; override with -e GUARDLAYER_TARGET=...
ENV GUARDLAYER_TARGET=https://api.openai.com

CMD ["guardlayer", "start", "--host", "0.0.0.0", "--port", "8080"]
