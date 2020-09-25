# web-PEanalysis(CentOS7)

- [Ubuntu18.04用](https://github.com/JinkaiINT2020/web-PEanalysis/blob/develop/README_ubuntu.md)

![upload-page](https://raw.githubusercontent.com/JinkaiINT2020/web-PEanalysis/readmeImage/web-PEanalysis-upload.png)

![search-page](https://raw.githubusercontent.com/JinkaiINT2020/web-PEanalysis/readmeImage/web-PEanalysis-search.png)

PEファイルの表層解析、および動的解析を行い、解析結果を閲覧するプログラムです。動的解析に際しては、Cuckoo Sandboxにリクエストを送信することで解析を行います。また解析結果の項目を利用して、これまで解析したPEファイルの解析結果の検索や、統計情報の表示ができます。

注意: 現在、動的解析はUbuntu18.04のみ対応しています。詳しくは[Ubuntu18.04のREADME](https://github.com/JinkaiINT2020/web-PEanalysis/blob/develop/README_ubuntu.md)をご覧ください。

## インストール

Docker Composeを用いてweb-PEanalysisを起動する場合は、実行方法まで進めてください。

### 使用環境

インストールにおいて、以下の環境を想定しています。

- CentOS7
- Python3.6

### 必要となるPythonモジュール

web-PEanalysisを動かすにあたり、必要となるPythonのモジュールは以下の通りです。

- [ssdeep](https://pypi.org/project/ssdeep/)

```
# ssdeepを動かすために必要となるパッケージのインストール
$ sudo yum groupinstall "Development Tools"
$ sudo yum install epel-release
$ sudo yum install libffi-devel python-devel python-pip ssdeep-devel ssdeep-libs
# Pythonモジュールであるssdeepのインストール
$ pip install ssdeep
```

- [pyimpfuzzy](https://pypi.org/project/pyimpfuzzy/)

```
$ pip install pyimpfuzzy
```

- [pehash](https://github.com/knowmalware/pehash)

```
$ git clone https://github.com/knowmalware/pehash
$ cd pehash
$ python setup.py install
```

- [pefile](https://pypi.org/project/pefile/)

```
$ pip install pefile
```

- [flask](https://pypi.org/project/Flask/)

```
$ pip install Flask
```

- [pymongo](https://pypi.org/project/pymongo/)

```
# mongodb4.0のインストール
$ cat /etc/yum.repos.d/mongodb-org-4.0.repo
[mongodb-org-4.0]
name=MongoDB Repository
baseurl=https://repo.mongodb.org/yum/redhat/$releasever/mongodb-org/4.0/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://www.mongodb.org/static/pgp/server-4.0.asc
$ sudo yum install -y mongodb-org

# pymongoのインストール
$ pip install pymongo
```

- [virustotal-api](https://pypi.org/project/virustotal-api/)

```
$ pip install virustotal-api
```

### 必要となるソフトウェア

web-PEanalysisを動かすにあたり、必要となるソフトウェアは以下の通りです。どちらも、下のようにweb-PEanalysisディレクトリ直下に配置してください。

```
web-PEanalysis/
    templates/
    static/
    PEanalysis.py
    PEiD/
        PEiD
    trid/
        trid
    app.py
    config.py

```

- [PEiD](https://github.com/K-atc/PEiD)

PEiDではlibcrypto.so.1.0.0を使用するため、libcrypto.so.1.0.0が存在しない場合は `ln -s /lib64/libcrypto.so.1.0.2k /lib64/libcrypto.so.1.0.0` のようにコマンド等を使用して、libcrypto.so.1.0.0を用意しておいてください。

※ `/lib64/libcrypto.so.1.0.2k` はご自身の使用しているlibcrypto.soのバージョンに合わせて変更してください。

```
$ mkdir PEiD
$ cd PEiD
$ curl -L https://github.com/K-atc/PEiD/releases/download/v0.1.1/PEiD > PEiD
$ chmod 755 PEiD
$ ./PEiD --prepare
```

- [TrID](http://mark0.net/soft-trid-e.html)

```
$ mkdir trid
$ cd trid
$ curl http://mark0.net/download/trid_linux_64.zip > trid_linux_64.zip
$ unzip trid_linux_64.zip
$ chmod 755 trid
$ curl http://mark0.net/download/tridupdate.zip > tridupdate.zip
$ unzip tridupdate.zip
$ python tridupdate.py
```

## 実行方法

### APIキーの設定

VirusTotal APIを使用する場合、Cuckoo Sandboxを使用する場合は、それぞれinstance/instance\_config.cfgファイルを作成し、以下の内容を記述してください。

- VirusTotal API: `VT_API_KEY`
- Cuckoo Sandbox: `CUCKOO_API_KEY`

```
# 例
VT_API_KEY = 'your virus total api key'
CUCKOO_API_KEY = 'your ~/.cuckoo/conf/cuckoo.conf api_token value'
```

### Docker Composeを用いた起動方法

注意: Docker Composeを用いて起動する場合、動的解析を行うことができなくなります。

1. web-PEanalysisディレクトリへ移動します。
3. 以下のコマンドを実行します。
    - `$ docker-compose up -d`
4. `http://localhost:5000/` へアクセスします。

### Docker Composeを用いない起動方法

1. web-PEanalysisディレクトリへ移動します。
2. 以下のコマンドを実行します。
    - `$ python3 app.py`
3. `http://localhost:5000/` へアクセスします。

## 主な機能

- `http://localhost:5000/search` : これまで解析を行ったPEファイルを検索することができます。
    - 表示されているテーブルの行をクリックすると、`http://localhost:5000/file/<sha256>` へ遷移します。
- `http://localhost:5000/upload` : PEファイルをアップロードし、表層解析を行います。
    - この時、VirusTotalの使用の可否を選択します。
- `http://localhost:5000/statistics` : これまでのPEファイルの解析結果をもとに、統計情報を表示します。
- `http://localhost:5000/file/<sha256>` : sha256に対応したPEファイルの表層解析結果を表示します。
    - `strings` をクリックすることで、 `http://localhost:5000/strings/<sha256>` に遷移します。
    - `import table` をクリックすることで、 `http://localhost:5000/imports/<sha256>` に遷移します。
    - `export table` をクリックすることで、 `http://localhost:5000/exports/<sha256>` に遷移します。
    - `pefile dump_info()` をクリックすることで、 `http://localhost:5000/pefile/<sha256>` に遷移します。
- `http://localhost:5000/pefile/<sha256>` : sha256に対応したPEファイルのダンプ結果を表示します。
