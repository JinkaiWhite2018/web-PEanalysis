import sys
import os
import subprocess
import getpass
import zipfile

path = os.getcwd()

cwdset = set(os.listdir(path))
appset = set(["app.py", "config.py", "PEanalysis.py", "requirements.txt"])
if not appset.issubset(cwdset):
	print("This tool must be used in PEanalysis directory.")
	sys.exit(1)

"""
print('This tool will use sudo.')
password = (getpass.getpass('UNIX password:')+'\n').encode()
"""

#mongodb
if not os.path.exists('/etc/yum.repos.d/mongodb-org-4.0.repo'):
	with open('/etc/yum.repos.d/mongodb-org-4.0.repo', 'w')as f:
		f.write('[mongo-db-org-4.0]\nname=MongoDB Repository\nbaseurl=https://repo.mongodb.org/yum/redhat/$releasever/mongodb-org/4.0/x86_64\ngpgcheck=1\nenabled=1\ngpgkey=https://www.mongodb.org/static/pgp/server-4.0.asc\n')

#yum
print('yum groups -y mark convert')
cp = subprocess.run(['yum', 'groups', '-y', 'mark', 'convert'])
print('yum groupinstall -y "Development Tools"')
cp = subprocess.run(['yum', 'groupinstall', '-y', '"Development Tools"'])

cp = subprocess.run(['yum', 'install', '-y', 'epel-release'])
cp = subprocess.run(['yum', 'install', '-y', 'libffi-devel', 'python36-devel', 'python36-pip', 'ssdeep-devel', 'mongodb-org', 'automake', 'autoconf', 'libtool'])

#python module
print('pip inatall -r requirements.txt')
cp = subprocess.run(['python3', '-m', 'pip', 'install', '-r', 'requirements.txt'])
if cp.returncode != 0:
	print('pip failed.', file=sys.stderr)
	sys.exit(1)
else:
	print('done.')

import requests

#pehash
print('installing pehash...')
cp = subprocess.run(['git', 'clone', 'https://github.com/knowmalware/pehash'])
os.chdir('./pehash')
print('python3 setup.py install')
cp = subprocess.run(['python3', 'setup.py', 'install'])
os.chdir('../')

#PEiD
print('installing PEiD...')
if not os.path.exists('PEiD'):
	os.mkdir('PEiD')
	os.chdir('./PEiD')
	url = 'https://github.com/K-atc/PEiD/releases/download/v0.1.1/PEiD'
	res = requests.get(url, stream=True)
	with open('PEiD', 'wb')as f:
		for chunk in res.iter_content(chunk_size=1024):
			if chunk:
				f.write(chunk)
				f.flush()
	cp = subprocess.run(['ln', '-s', '/lib64/libcrypto.so.1.0.2k', '/lib64/libcrypto.so.1.0.0'])
	cp = subprocess.run(['chmod', '755', 'PEiD'])
	cp = subprocess.run(['./PEiD', '--prepare'])
	os.chdir('../')

#trid
print('installing trid...')
if not os.path.exists('trid'):
	os.mkdir('trid')
	os.chdir('./trid')
	url = 'https://mark0.net/download/trid_linux_64.zip'
	res = requests.get(url, stream=True)
	with open('trid_linux_64.zip', 'wb')as f:
		for chunk in res.iter_content(chunk_size=1024):
			if chunk:
				f.write(chunk)
				f.flush()

	cp = subprocess.run(['unzip', 'trid_linux_64.zip'])
	cp = subprocess.run(['chmod', '755', 'trid'])
	url = 'https://mark0.net/download/tridupdate.zip'
	res = requests.get(url, stream=True)
	with open('tridupdate.zip', 'wb')as f:
		for chunk in res.iter_content(chunk_size=1024):
			if chunk:
				f.write(chunk)
				f.flush()
	cp = subprocess.run(['unzip', 'tridupdate.zip'])
	cp = subprocess.run(['python3', 'tridupdate.py'])


