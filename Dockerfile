FROM registry.cn-shanghai.aliyuncs.com/ale10bb/python:3.12-web-flask

# requirements for wxwork
RUN pip install --no-cache-dir pycryptodome

# directory structure for wxwork
WORKDIR /wxwork
COPY weworkapi_callback weworkapi_callback
COPY app.py .

ENTRYPOINT ["gunicorn", "app:app"]
CMD [ "--worker-class", "gevent", "--capture-output", "--bind", ":9080" ]