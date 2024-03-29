FROM mitrecnd/d20:latest

COPY ./ /data/d20-extras

RUN  \
apt-get update && \
apt-get -y install yara exiftool libarchive13 libarchive-dev p7zip-full && \
pip install setuptools --upgrade && \
cd /data/d20-extras/malchive && \
pip install . && \
cd /data/d20-extras && \
pip install -r requirements.txt && \
apt-get clean && \
rm -rf /var/lib/apt/lists/* /tmp/ /var/tmp/*

WORKDIR /data
