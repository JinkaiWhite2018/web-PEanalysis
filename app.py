# coding: utf-8

from flask import Flask, render_template, request, send_from_directory, Response
from werkzeug.utils import secure_filename
import os
import math
from pymongo import MongoClient
import PEanalysis
import subprocess

app = Flask(__name__, instance_relative_config=True)
app.config.from_object('config.Product')
if not app.config.from_pyfile('instance_config.cfg', silent=True):
    app.config['VT_API_KEY'] = ''

client = MongoClient(app.config['HOST_DB'], app.config['PORT_DB'])
db = client[app.config['USE_DB']]
collection = db[app.config['USE_COLLECTION']]


@app.route('/analyse/<filename>/<useVT>', methods=['GET'])
def analyse_file(filename, useVT):
    def analyse():
        yield 'data:<p>解析の準備をしています。</p>\n\n'
        filepath = os.path.join(os.getcwd(), app.config['UPLOAD_DIR'], filename)
        PEanalysis.prepare(app.config['PEFILES_DIR'])
        pe = PEanalysis.file_check(filepath, app.config['PEFILES_DIR'])
        if isinstance(pe, str):
                #pe=error_message
                yield 'data:<p>\n'
                yield 'data:' + pe + '<br>\n'
                yield 'data:<a href=\"upload\"">戻る</a>\n'
        else:
            yield 'data:<p>解析中...</p>\n\n'
            res_dict, s256path = PEanalysis.analyse(filepath, app.config['PEFILES_DIR'], pe, collection, useVT, app.config['VT_API_KEY'])
            os.remove(filepath)
            if isinstance(res_dict, str):
                #res_dict=error_message, s256path=s256
                yield 'data:<p>' + res_dict + '</p>\n'
                if res_dict.find('VirusTotal') == -1:
                    yield 'data:<p><a href=\"/file/' + s256path + '\">こちらから解析結果を確認することができます。</a></p>\n'
                else:
                    yield 'data:<p>instance/instance_config.cfgにVT_API_KEYを追加されているか確認してください。</p>\n'
                yield 'data:<p><a href=\"upload\"">戻る</a>\n'
            else:
                yield 'data:<p>解析結果を書き込んでいます...</p>\n\n'
                PEanalysis.write_data(pe, collection, res_dict, s256path)
                yield 'data:<p>\n'
                yield 'data:解析が完了しました。<br>\n'
                yield 'data:<a href=\"/file/' + os.path.basename(s256path).replace('.txt', '') + '\">こちらから解析結果を確認することができます。</a>\n'
        yield 'data:</p>\n\n'
    return Response(analyse(), mimetype='text/event-stream')


@app.route('/send', methods=['GET', 'POST'])
def send_file():
    if request.method == 'POST':
        if 'upfile' not in request.files:
            return '解析するファイルを選択してください。'
        useVT = request.form['useVT']
        upfile = request.files['upfile']
        filename = secure_filename(upfile.filename)
        updir = app.config['UPLOAD_DIR']
        if not os.path.isdir(updir):
            os.mkdir(updir)
        upfile.save(os.path.join(app.config['UPLOAD_DIR'], filename))
        return render_template('send.html', title='PEFile Surface Analyser - Send', filename=filename, useVT=useVT)


@app.route('/upload')
@app.route('/upload.html')
def render_upload():
    return render_template('upload.html', title='PEFile Surface Analyser - Upload')


@app.route('/pefile/<s256>')
def render_pefile(s256):
    topath = 'pefiles/' + s256 + '.txt'
    if os.path.isfile(topath):
        with open(topath, 'r') as f:
            textdata = f.read()
            return render_template('pefile.html', title='PEFile Surface Analyser - pefile', textdata=textdata)
    else:
        return '不正なリクエストです。'


@app.route('/file/<s256>')
def render_file(s256):
    result = collection.find_one({'sha256': s256})
    if result:
        if 'TrID' in result:
            result['TrID'] = result['TrID'].replace('\\n', '\n')
        return render_template('file.html', title='PEFile Surface Analyser - file', file_dict=result)
    else:
        return '不正なリクエストです。'


@app.route('/search')
@app.route('/search.html')
def render_search():
    onepage = app.config['ONE_PAGE']
    pagenum = app.config['PAGE_NUM']
    page = request.args.get('page', default=1, type=int)
    key_item = request.args.get('item', default='*', type=str)
    keywords = request.args.get('keyword', default='', type=str)
    get_params = ''
    if key_item == '*' or keywords == '':
        find_data = collection.find()
    else:
        find_data = collection.find({key_item: {'$regex': keywords}})
        get_params = '&item=' + key_item + '&keyword=' + keywords
    count = find_data.count()
    result = list(find_data.skip(onepage * (page - 1)).limit(onepage))
    all_page_num = math.ceil(count / onepage)
    start_page = page - pagenum + 1 if page - pagenum + 1 >= 1 else 1
    end_page = page + pagenum - 1 if page + pagenum - 1 <= all_page_num else all_page_num
    return render_template(
            'search.html', title='PEFile Surface Analyser - Search', page=page,
            start_page=start_page, end_page=end_page, all_page_num=all_page_num,
            headlist=PEanalysis.HEADER, impheadlist=PEanalysis.IMPHEAD,
            mongolist=result, get_params=get_params)


@app.route('/')
@app.route('/index')
@app.route('/index.html')
def render_index():
    return render_template('index.html', title='PEFile Surface Analyser')

    
# @app.route('/start_cuckoo')
# @app.route('/start_cuckoo.html')
# def start_cuckoo():
#     msg=subprocess.call(['cuckoo','web'])
#     return render_template('start_cuckoo.html', title='start cuckoo', msg=msg)


if __name__ == '__main__':
    subprocess.Popen(['cuckoo','web'])
    app.run(host='0.0.0.0', port=5000)
