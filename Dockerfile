FROM python:3.8-slim
MAINTAINER frank@csie.io
RUN pip install poetry
ADD . /app
WORKDIR /app
RUN poetry install --no-dev
EXPOSE 8080/tcp
ENTRYPOINT ["python", "-m", "easysocks5.server"]
CMD ["-H", "0.0.0.0", "-P", "8080"]
