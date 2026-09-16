# case 5: python:3.12-slim with cryptography installed, its Rust extension
# loaded, and a plain HTTP server kept listening. Build context is
# cases/images/5-cryptography (see cases/run.sh). The image is scanned by
# the same ImageID it is run with (no registry round-trip in between).
FROM python:3.12-slim
RUN pip install --no-cache-dir cryptography
COPY server.py /server.py
CMD ["python", "-u", "/server.py"]
