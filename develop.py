#!/usr/bin/python3

import os
import sys
import time
import socket
import argparse
import datetime
import logging
import urllib.parse

BASE = os.getcwd()
DOCUMENT_ROOT = '/'


#print(os.path.basename(DOCUMENT_ROOT))
#print(os.path.abspath(DOCUMENT_ROOT))
#print(os.path.commonprefix([DOCUMENT_ROOT, BASE]))
#print(os.path.commonprefix(['/root/OServer', '/root']))
print(os.path.relpath(DOCUMENT_ROOT))

#full_path = os.path.normpath(self.root_dir + '/' + self.path)
full_path = os.path.normpath(BASE + DOCUMENT_ROOT)
print(full_path)

#print(os.path.commonprefix([full_path, BASE])) # != self.root_dir:

print(os.path.exists(full_path))


#url = '/root/7777'
url = 'httptest/dir1'
url = 'httptest/dir1/dir12/dir123/deep.txt'
url = 'httptest/dir2/'
url = '/httptest/dir4/'
url =  'httptest/../../../../../../../../../../../../../etc/passwd' #"""document root escaping forbidden"""
#url = '/httptest/dir2/%70%61%67%65%2e%68%74%6d%6c'
#url = 'httptest/dir2/page.html?arg1=value&arg2=value'
url = ''

#print(urllib.parse.unquote(url))
#print(os.path.join(DOCUMENT_ROOT, url))
#if not os.path.exists(os.path.join(DOCUMENT_ROOT, url)):
#    print('false')
#else:
#    print('exists')
#print(url.split('/')[1:])

#print( '\r\n'.join( '<p>' + repr(e).replace("'", '') + '</p>' for e in os.listdir(DOCUMENT_ROOT)))

#Thu, 19 Dec 2019 07:48:55 GMT\r\n
#print(datetime.datetime.now()) #2019-12-19 11:53:19.336632

now = datetime.datetime.now()
httpdate = time.mktime(now.timetuple())
#print(httpdate)


DATE = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
SERVER = sys.version
#print('python ' + SERVER.split('[')[0].strip() + ' ' +  SERVER.split('[')[1].strip().replace(']', ''))
CONTENT_LENGTH = 'Content-Length: 1234'
CONNECTION = 'Connection: close'
CONTENT_TYPE = 'Content-Type: text/html;charset=UTF-8\r\n'


#print(DOCUMENT_ROOT)
#print(path) #/root/OServer
#print(os.path.join(path, url))
#print(os.path.exists(path + url ))
#print(os.path.exists(os.path.join(path, url)))
#print(os.path.join(DOCUMENT_ROOT, BASE))
#print(os.path.join(path, url))
#print(os.path.exists(os.path.join(DOCUMENT_ROOT, url)))
#print(os.path.exists(os.path.join('/root/OServer', url)))
#print(os.path.exists(os.path.join('/', url)))
#print(os.path.exists(os.path.join(path, url)))
#print(os.path.exists(path + DOCUMENT_ROOT + url))
#print(os.path.exists(DOCUMENT_ROOT + url))
#print(os.path.exists(path + url))
#print(os.path.exists(os.path.join(path, DOCUMENT_ROOT, url)))
#print(os.path.abspath(DOCUMENT_ROOT))
#print(os.path.exists(os.path.join(os.path.abspath(DOCUMENT_ROOT), url)))
#print(os.path.exists(os.path.join('/root/OServer/', '/httptest/dir1/dir12/dir123/deep.txt')))
#print(os.path.exists(os.path.join('/root/OServer', 'httptest/dir1/dir12/dir123/deep.txt')))
#print(os.path.exists(os.path.join('./', '/httptest/dir1/dir12/dir123/deep.txt')))
#print(os.path.exists(url))
#print(os.path.exists('/root/OServer/httptest/dir1/dir12/dir123/deep.txt'))
#print(os.path.exists('/root/OServer/httptest/dir2/'))
#print(os.path.relpath('/root/OServer', '/root/OServer/httptest/../../../../../../../../../../../../../etc/passwd'))
#print(os.path.relpath('/root/OServer', '/etc/passwd'))
#print(os.path.relpath('/etc/passwd', '/root/OServer'))
#print(os.path.exists(os.path.join(full_path, url)))
#print(os.path.abspath(os.path.join(full_path, url)).startswith(BASE))

def generate_code(method, url):
    if method not in ['GET', 'HEAD']:
        return ('HTTP/1.1 405 Methd not allowed\r\n', 405)
    logging.info(f'url is: {url}, type is: {type(url)}, len is:  {len(url)}, bytelen is: {sys.getsizeof(url)}')
    if not os.path.exists(os.path.join(full_path, url)) or not os.path.abspath(os.path.join(full_path, url)).startswith(BASE):
        print('firs check not passsed')
        return ('HTTP/1.1 404 not found\r\n', 404)
    if os.path.isdir(os.path.join(full_path, url)) and '/' + url != DOCUMENT_ROOT:
        if not os.path.exists(os.path.join(full_path, url, 'index.html')):
            return ('HTTP/1.1 404 not found\r\n', 404)
    return ('HTTP/1.1 200 OK\r\n', 200)


print(generate_code('GET', url))




