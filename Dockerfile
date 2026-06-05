FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .

RUN python -m pip install --upgrade pip \
    && python -m pip install -r requirements.txt

COPY app ./app
COPY scripts ./scripts

EXPOSE 48921

# 当前实现的验证码 Session/RSA 私钥仍在进程内存中，默认使用单 worker 保证
# precheck -> verify 链路命中同一进程。横向扩展前请先切换 Redis Session Store。
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "48921", "--workers", "1"]
