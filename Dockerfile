# docker build -t web-PEanalysis .

# ベースイメージ:CentOS7
FROM centos:7

# 作業ディレクトリ:/root
WORKDIR /root
RUN mkdir ./web-PEanalysis

# ローカルのweb-PEanalysisリソースの配置
COPY . ./web-PEanalysis

RUN yum -y update
RUN yum groups mark convert
RUN yum install -y python36 git unzip
RUN yum groupinstall -y "Development Tools"
RUN yum install -y epel-release

# mongodb、ssdeepインストール準備
RUN cp ./web-PEanalysis/mongodb-org-4.0.repo /etc/yum.repos.d
RUN yum install -y libffi-devel python36-devel python36-pip automake autoconf libtool ssdeep-devel

WORKDIR /root/web-PEanalysis
# pythonモジュールインストール
RUN pip3 install -r requirements.txt

# pehashセットアップ
RUN git clone https://github.com/knowmalware/pehash
RUN cd ./pehash && python3 setup.py install

RUN mkdir ./{PEiD,trid}
# PEiDセットアップ
RUN ln -s /lib64/libcrypto.so.1.0.2k /lib64/libcrypto.so.1.0.0
RUN cd ./PEiD && \
    curl -L https://github.com/K-atc/PEiD/releases/download/v0.1.1/PEiD > PEiD && \
    chmod 755 PEiD && \
    ./PEiD --prepare

# tridセットアップ
RUN cd ./trid && \
    curl https://mark0.net/download/trid_linux_64.zip > trid_linux_64.zip && \
    unzip trid_linux_64.zip && \
    chmod 755 trid
RUN cd ./trid && \
    curl https://mark0.net/download/tridupdate.zip > tridupdate.zip && \
    unzip tridupdate.zip && \
    python3 tridupdate.py


CMD ["python3", "/root/web-PEanalysis/app.py"]