SH_PWD=$(pwd)

# Update apt-get
sudo apt-get update -y

# Setup tools
sudo apt-get install git wget unzip
sudo apt-get install build-essential libffi-dev python3 python3-dev python3-pip libfuzzy-dev -y

# Setup pehash
git clone https://github.com/knowmalware/pehash && cd pehash
sudo python3 setup.py install
cd ${SH_PWD}

# Setup mongodb
sudo apt-get install mongodb -y

# Setup PEiD
mkdir PEiD && cd PEiD
wget https://github.com/K-atc/PEiD/releases/download/v0.1.1/PEiD \
    && chmod 755 PEiD \
    && ./PEiD --prepare
cd ${SH_PWD}

# Setup trid
mkdir trid && cd trid
wget http://mark0.net/download/trid_linux_64.zip \
    && unzip trid_linux_64.zip \
    && chmod 755 trid
wget http://mark0.net/download/tridupdate.zip \
    && unzip tridupdate.zip \
    && python3 tridupdate.py
cd ${SH_PWD}

# Setup winchecksec
mkdir winchecksec && cd winchecksec
wget https://github.com/trailofbits/winchecksec/releases/download/v2.0.0/ubuntu-latest.Release.zip \
    && unzip ubuntu-latest.Release.zip \
    && chmod 755 build/winchecksec
cd ${SH_PWD}

# Install pip package
pip3 install --no-cache-dir ssdeep pyimpfuzzy pefile Flask pymongo virustotal-api 
