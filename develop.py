#!/usr/bin/python3

import os
import sys
import time
import socket
import argparse
import datetime

DOCUMENT_ROOT = 'httptest'


url = '/root/7777'
#url = 'dir1'
url = '/httptest/dir1/dir12/dir123/deep.txt'

#print(url)
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

print(os.getcwd())
path = os.getcwd()
#print(os.path.join(p, url))
print(os.path.exists(path + url ))

def generate_code(url):
    p = os.getcwd()
    if not os.path.exists(path + url) and not os.path.exists(os.path.join(DOCUMENT_ROOT, url)):
        return ('HTTP/1.1 404 not found\n\n', 404)
    return ('HTTP/1.1 200 OK\r\n', 200)

print(generate_code(url))
