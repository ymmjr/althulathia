FROM python:3.12-slim
WORKDIR /app

COPY bundle /tmp/bundle

RUN python -c "from pathlib import Path; import base64,zipfile; d=''.join(p.read_text().strip() for p in sorted(Path('/tmp/bundle').glob('part*.txt'))); Path('/tmp/app.zip').write_bytes(base64.b64decode(d)); zipfile.ZipFile('/tmp/app.zip').extractall('/app')" \
    && pip install --no-cache-dir -r /app/requirements.txt \
    && rm -rf /tmp/bundle /tmp/app.zip

ENV PYTHONUNBUFFERED=1

CMD ["python","server.py"]
