FROM python:3.10.4-bullseye
RUN apt update
RUN apt-get install build-essential libssl-dev git -y
RUN apt-get install yasm libgmp-dev libpcap-dev libnss3-dev libkrb5-dev pkg-config libbz2-dev zlib1g-dev -y
RUN git clone --depth 10 https://github.com/openwall/john.git
RUN cd john/src && ./configure && make -s clean && make -sj4