#!/usr/bin/python3

import os
import socket
import argparse

DOCUMENT_ROOT = './document_root'

url = '3'
print(url)
print(os.path.join(DOCUMENT_ROOT, url))

if not os.path.exists(os.path.join(DOCUMENT_ROOT, url)):
    print('false')
else:
    print('exists')
