# coding: utf-8

import subprocess
import datetime
import hashlib
import os
import pefile
import pehash
import pyimpfuzzy
import re
import ssdeep
import sys
import json
from virus_total_apis import PublicApi as VirusTotalPublicApi

HEADER = ['date', 'md5', 'sha1', 'sha256', 'ssdeep', 'imphash', 'impfuzzy',
          'Totalhash', 'AnyMaster', 'AnyMaster_v1_0_1', 'EndGame', 'Crits',
          'peHashNG', 'Platform', 'GUI Program', 'Console Program', 'DLL',
          'Packed', 'Anti-Debug', 'mutex', 'contains base64',
          'AntiDebugMethod', 'PEiD', 'TrID', 'nearest sha256', 'nearest value',
          'VTismalware', 'VirusTotalLink']
IMPHEAD = ['date', 'sha256']


def prepare(pefiles_dir):
    if not os.path.isdir(pefiles_dir):
        os.mkdir(pefiles_dir)
        print(pefiles_dir, ' create.', file=sys.stderr)
    else:
        print(pefiles_dir, ' already exists.', file=sys.stderr)


def file_check(filepath, pefiles_dir):
    if not os.path.isdir(pefiles_dir):
        print(pefiles_dir, ' is not found.', file=sys.stderr)
        print('please try --prepare option.')
        return pefiles_dir + 'が存在しません。'

    if not os.path.isfile(filepath):
        print(filepath, ' is not found.', file=sys.stderr)
        return os.path.basename(filepath) + ' is not found.'
    try:
        pe = pefile.PE(filepath)
    except:
        print(filepath, ' is not PE file.', file=sys.stderr)
        return os.path.basename(filepath) + 'はPEファイルではありません。'

    return pe


def analyse(filepath, pefiles_dir, pe, collection, useVT, api_key):
    ret_list = []

    # 'date', 'md5', 'sha1', 'sha256',
    m5 = hashlib.md5()
    s1 = hashlib.sha1()
    s256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            c = f.read(8192 * s256.block_size)
            if len(c) == 0:
                break
            m5.update(c)
            s1.update(c)
            s256.update(c)
    s256path = pefiles_dir + '/' + s256.hexdigest() + '.txt'
    if os.path.isfile(s256path):
        print(filepath, ' already run this program.', file=sys.stderr)
        return os.path.basename(filepath) + 'はすでに解析を完了しています。', s256.hexdigest()

    ret_list.append(datetime.datetime.now().strftime('%Y%m%d'))
    ret_list.append(m5.hexdigest())
    ret_list.append(s1.hexdigest())
    ret_list.append(s256.hexdigest())

    # 'ssdeep', 'imphash', 'impfuzzy'
    ret_list.append(ssdeep.hash_from_file(filepath))
    ret_list.append(pe.get_imphash())
    ret_list.append(pyimpfuzzy.get_impfuzzy(filepath))

    # 'Totalhash', 'AnyMaster', 'AnyMaster_v1_0_1', 'EndGame', 'Crits', 'peHashNG'
    ret_list.append(pehash.totalhash_hex(filepath))
    ret_list.append(pehash.anymaster_hex(filepath))
    ret_list.append(pehash.anymaster_v1_0_1_hex(filepath))
    ret_list.append(pehash.endgame_hex(filepath))
    ret_list.append(pehash.crits_hex(filepath))
    ret_list.append(pehash.pehashng_hex(filepath))

    # 'Platform', 'GUI Program', 'Console Program', 'DLL', 'Packed', 'Anti-Debug'
    # 'mutex', 'contains base64', 'AntiDebugMethod', 'PEiD'
    cwd = os.getcwd()
    os.chdir(cwd + '/PEiD')
    res = subprocess.check_output(['./PEiD', filepath])
    res = res.decode('utf-8').split('\n')
    r = re.compile('^\s+([^:]+)\s:\s(.+)$')
    res_dict = {}
    for s in res:
        m = r.match(s)
        if m:
            res_dict[m.group(1)] = m.group(2)
    res_contains = [s for s in res if s.startswith('  contains base64')]

    ret_list.append(res_dict['PE'])
    ret_list.append(res_dict['GUI Program'])
    ret_list.append(res_dict['Console Program'])
    ret_list.append(res_dict['DLL'])
    ret_list.append(res_dict['Packed'])
    ret_list.append(res_dict['Anti-Debug'])
    ret_list.append('yes' if 'mutex' in list(res_dict.keys()) else 'no')
    ret_list.append('yes' if res_contains else '')
    if 'AntiDebug' in list(res_dict.keys()):
        res_antidebug = re.sub(
            '[\[\]"]', '', res_dict['AntiDebug']).replace(' ', '|')
        ret_list.append(res_antidebug)
    else:
        ret_list.append('')
    if 'PEiD' in list(res_dict.keys()):
        res_peid = re.sub('[\[\]"]', '', res_dict['PEiD']).replace(' ', '|')
        ret_list.append(res_peid)
    else:
        ret_list.append('')

    # 'TrID'
    os.chdir(cwd + '/trid')
    res = subprocess.check_output(['./trid', filepath])
    res = res.decode('utf-8').split('\n')
    res = [s for s in res if re.match('^\s*[0-9]+\.[0-9]%', s)]
    res_trid = '\\n'.join(res)
    ret_list.append(res_trid)

    os.chdir(cwd)

    # nearest sha256, nearest value
    newfuzzy = ret_list[HEADER.index('impfuzzy')]
    nearest_sha256 = ''
    nearest_value = -1

    result = collection.find()
    if result.count() > 0:
        overwrites = []
        for r in result:
            cmpval = pyimpfuzzy.hash_compare(newfuzzy, r['impfuzzy'])
            if cmpval > nearest_value:
                nearest_sha256 = r['sha256']
                nearest_value = cmpval
            if cmpval > r['nearest value']:
                overwrites.append([{'sha256': r['sha256']},
                    {'$set': {
                            'nearest sha256': s256.hexdigest(),
                            'nearest value': cmpval
                            }}])
        for r in overwrites:
            collection.update(r[0], r[1])
    ret_list.append(nearest_sha256)
    ret_list.append(nearest_value)
        

    # ismalware, VirusTotalLink
    print(useVT)
    flag = False
    if useVT == 'on':
        vt = VirusTotalPublicApi(api_key)
        res = vt.get_file_report(m5.hexdigest())
        print(json.dumps(res, sort_keys=False, indent=4))
        if 'results' in res:
            if 'positives' in res['results']:
                if res['results']['positives'] > 0:
                    ret_list.append('True')
                else:
                    ret_list.append('False')
            else:
                ret_list.append('False')
            if 'permalink' in res['results']:
                ret_list.append(str(res['results']['permalink']))
            else:
                print('Server error occured.', file=sys.stderr)
                return 'VirusTotalでエラーが発生しました。', s256.hexdigest()
        else:
            print('Server error occured.', file=sys.stderr)
            return 'VirusTotalでエラーが発生しました。', s256.hexdigest()
    else:
        ret_list.append('')
        ret_list.append('')
    
    ret_dict = {}
    print(ret_list)
    print(len(HEADER), len(ret_list))
    for i in range(0, len(HEADER)):
        ret_dict[HEADER[i]] = ret_list[i]

    return ret_dict, s256path


def write_data(pe, collection, ret_dict, s256path):
    with open(s256path, 'w') as f:
        f.write(pe.dump_info())

    collection.insert_one(ret_dict)
