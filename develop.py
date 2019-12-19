#!/usr/bin/python3

import os
import time
import socket
import locale
import argparse
import datetime

DOCUMENT_ROOT = './document_root'

url = '2'
print(url)
print(os.path.join(DOCUMENT_ROOT, url))

if not os.path.exists(os.path.join(DOCUMENT_ROOT, url)):
    print('false')
else:
    print('exists')


#Thu, 19 Dec 2019 07:48:55 GMT\r\n
#print(datetime.datetime.now()) #2019-12-19 11:53:19.336632

now = datetime.datetime.now()
httpdate = time.mktime(now.timetuple())
#print(httpdate)


DATE = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

SERVER = sys.version


CONTENT_LENGTH = 'Content-Length: 1234'

CONNECTION = 'Connection: close'

CONTENT_TYPE = 'Content-Type: text/html;charset=UTF-8\r\n'