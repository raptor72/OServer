#!/usr/bin/python3

import os


def get_len(url):
    print(os.listdir(url))
    le = 0
    for i in os.listdir(url):
        le += os.path.getsize(os.path.join(url, i))
    print(le)

#get_len('.')
#get_len('./httptest/dir2/')
url = './httptest/dir2/'

s = sum( [os.path.getsize(os.path.join(url, r)) for r in os.listdir(url)])

print(s)

#    if os.path.isfile(self.full_path + url) and os.path.abspath(self.full_path + url).startswith(self.base):
#        content_length = 'Content-Length: ' + str(os.path.getsize(self.full_path + url)) + '\r\n'
#    elif os.path.exists(self.full_path + url + 'index.html'):
#        content_length = 'Content-Length: ' + str(os.path.getsize(self.full_path + url + 'index.html')) + '\r\n'
#    else:
#        content_length = 'Content-Length: ' + str(len(response_prase)) + '\r\n'
#    connection = 'Connection: close\r\n\r\n'
#    headers = ''.join([response_prase, server, date, content_type, content_length, connection])
