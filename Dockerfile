FROM python:3.11-slim

# set TZ to Asia/Shanghai by default
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# environments for RM
WORKDIR /wxwork
ENTRYPOINT ["gunicorn", "app:app"]
CMD [ "--worker-class", "gevent", "--capture-output", "--bind", ":9080" ]

# requirements for RM
RUN pip install --no-cache-dir Flask requests pycryptodome gunicorn[gevent]
COPY app.py app.py
COPY weworkapi_callback weworkapi_callback
