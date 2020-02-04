#!/usr/bin/python3

import os
import sys
import datetime
import urllib.parse


CONTENT_TYPES = {
    'html': 'text/html',
    'css': 'text/css',
    'js': 'application/javascript',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'png': 'image/png',
    'gif': 'image/gif',
    'swf': 'application/x-shockwave-flash',
}


class Handler:
    def __init__(self, request, root_dir):
        self.request = request
        self.root_dir = root_dir
        self.base = os.getcwd()
        self.full_path = os.path.normpath(self.base + self.root_dir)

    def parse_request(self, request):
#        print('request:', request)
        parsed = request.split('\r\n\r\n')[0].split(' ')
#        parsed = request.split(' ')
#        print(parsed)
        method = parsed[0]
        try:
            url = parsed[1].split('?')[0]
            return (method, urllib.parse.unquote(url.replace('%20', ' ')))
        except:
            return method, ''

    def parse_content_type(self, url):
        if os.path.isfile(self.full_path + url):
            try:
                extension =  url.split('.')[-1]
                if extension in CONTENT_TYPES.keys():
                    return CONTENT_TYPES[extension]
            except:
                return 'text/html;charset=UTF-8'
        return 'text/html;charset=UTF-8'

    def generate_code(self, method, url):
        if method not in ['GET', 'HEAD']:
            return ('HTTP/1.1 405 Method not allowed\r\n', 405)
        path = self.full_path + url
        if not os.path.exists(path) or not os.path.abspath(path).startswith(self.base):
            return ('HTTP/1.1 404 Not found\r\n', 404)
        if os.path.isdir(path) and path != self.full_path + '/':
            if not os.path.exists(os.path.join(path, 'index.html')):
                return ('HTTP/1.1 404 Not found\r\n', 404)
        return ('HTTP/1.1 200 OK\r\n', 200)

    def render_html(self, html_file):
        with open(html_file, 'rb') as html:
            data = html.read()
        return data

    def generate_body(self, code, url):
        print(url)
        if code == 404:
            return b'<h1>404</h1><p>Not found</p>'
        if code == 405:
            return b'<h1>405</h1><p>Method not allowed</p>'
        path = self.full_path + url
        if path == self.full_path + '/':
             return bytes('\r\n'.join( '<p>' + repr(e).replace("'", '') + '</p>' for e in os.listdir(path)).encode())
        if os.path.isfile(path) and os.path.abspath(path).startswith(self.base):
            return self.render_html(path)
        if os.path.isdir(path):
            if os.path.exists(os.path.join(path, 'index.html')):
                return self.render_html(os.path.join(path, 'index.html'))
        return b'<p>No such file or directory</p>'


    def generate_headers(self, url, body, response_prase):
        server = 'Server: python ' + sys.version.split('[')[0].strip() + ' ' +  sys.version.split('[')[1].strip().replace(']', '') + '\r\n'
        date = 'Date: ' + datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT') + '\r\n'
        content_type = 'Content-Type: ' + self.parse_content_type(url) + '\r\n'
        content_length = 'Content-Length: ' + str(len(body)) + '\r\n'
        connection = 'Connection: close\r\n\r\n'
        headers = ''.join([response_prase, server, date, content_type, content_length, connection])
        print(headers)
        return headers


    def generate_headers2(self, method, url):
#        print(url)
        response_prase, code = self.generate_code(method, url)
        server = 'Server: python ' + sys.version.split('[')[0].strip() + ' ' +  sys.version.split('[')[1].strip().replace(']', '') + '\r\n'
        date = 'Date: ' + datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT') + '\r\n'
        content_type = 'Content-Type: ' + self.parse_content_type(url) + '\r\n'
#       os.path.exists(self.full_path + url) and
        if os.path.isfile(self.full_path + url) and os.path.abspath(self.full_path + url).startswith(self.base):
            content_length = 'Content-Length: ' + str(os.path.getsize(self.full_path + url)) + '\r\n'
        elif os.path.isdir(self.full_path + url) and os.path.exists(self.full_path + url + 'index.html'):
            content_length = 'Content-Length: ' + str(os.path.getsize(self.full_path + url + 'index.html')) + '\r\n'
        elif url == self.root_dir:
#            content_length = 'Content-Length: ' + str(len(response_prase)) + '\r\n'
            content_length = 'Content-Length: ' + str(sum( [os.path.getsize(os.path.join(self.full_path + url, r)) for r in os.listdir(self.full_path + url)])) + '\r\n'
        else:
            content_length = 'Content-Length: ' + str(len(response_prase)) + '\r\n'
        connection = 'Connection: close\r\n\r\n'

        headers = ''.join([response_prase, server, date, content_type, content_length, connection])
        print(headers)
        return headers, code, response_prase


#    def generate_response(self, request):
#        method, url = self.parse_request(request)
#        response_prase, code = self.generate_code(method, url)
#        body = self.generate_body(code, url)
#        headers = self.generate_headers(url, body, response_prase)
#        if method == 'HEAD':
#             return headers.encode()
#        return headers.encode() + body


    def generate_response(self, request):
        method, url = self.parse_request(request)
        headers, code, response_prase = self.generate_headers2(method, url)
        if method not in ['GET', 'HEAD']:
            return response_prase.encode()
        if method == 'HEAD':
            return headers.encode()
        body = self.generate_body(code, url)
        return headers.encode() + body



