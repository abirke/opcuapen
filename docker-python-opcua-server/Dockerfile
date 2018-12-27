FROM ubuntu:16.04

RUN apt-get update
# install required software
RUN apt-get install -y git python3-pip libssl-dev
# install optional but useful tools
RUN apt-get install -y less vim

RUN pip3 install --upgrade pip
RUN pip3 install cryptography opcua

RUN git clone https://github.com/freeopcua/python-opcua.git /opt/python-opcua/

WORKDIR /opt/python-opcua/examples/
ENTRYPOINT ["python3", "server-with-encryption.py"]
