#!/usr/bin/python3

import os
import sys
import socket
import logging
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
        parsed = request.split(' ')
        method = parsed[0]
        try:
            url = parsed[1].split('?')[0]
            if url.startswith('/'):
                url = urllib.parse.unquote(url[1:])
            return (method, urllib.parse.unquote(url.replace('%20', ' ')))
        except:
            return method, ''

    def parse_content_type(self, url):
        if os.path.isfile(os.path.join(self.full_path, url)):
            try:
                extension =  url.split('.')[-1]
                if extension in CONTENT_TYPES.keys():
                    return CONTENT_TYPES[extension]
            except:
                return 'text/html;charset=UTF-8'
        return 'text/html;charset=UTF-8'

    def generate_code(self, method, url):
        if method not in ['GET', 'HEAD']:
            return ('HTTP/1.1 405 Methd not allowed\r\n', 405)
        if not os.path.exists(os.path.join(self.full_path, url)) or not os.path.abspath(os.path.join(self.full_path, url)).startswith(self.base):
            return ('HTTP/1.1 404 not found\r\n', 404)
        if os.path.isdir(os.path.join(self.full_path, url)) and '/' + url != self.root_dir:
            if not os.path.exists(os.path.join(self.full_path, url, 'index.html')):
                return ('HTTP/1.1 404 not found\r\n', 404)
        return ('HTTP/1.1 200 OK\r\n', 200)

    def render_html(self, html_file):
        with open(html_file, 'rb') as html:
            data = html.read()
        return data

    def generate_body(self, code, url):
        if code == 404:
            return b'<h1>404</h1><p>Not found</p>'
        if code == 405:
            return b'<h1>405</h1><p>Method not allowed</p>'
        if '/' + url == self.root_dir:
             return bytes( '\r\n'.join( '<p>' + repr(e).replace("'", '') + '</p>' for e in os.listdir(os.path.join(self.full_path, url))).encode())
        if not '/' in url:
            if os.path.isfile(os.path.join(self.full_path, url)):
                return self.render_html(os.path.join(self.full_path, url))
        if os.path.isfile(os.path.join(self.full_path, url)):
            return self.render_html(os.path.join(self.full_path, url))
        if os.path.isdir(os.path.join(self.full_path, url)):
            if os.path.exists(os.path.join(self.full_path, url, 'index.html')):
                return self.render_html(os.path.join(self.full_path, url, 'index.html'))
        return b'<p>No such file or directory</p>'

    def generate_headers(self, url, body, response_prase):
        server = 'Server: python ' + sys.version.split('[')[0].strip() + ' ' +  sys.version.split('[')[1].strip().replace(']', '') + '\r\n'
        date = 'Date: ' + datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT') + '\r\n'
        content_type = 'Content-Type: ' + self.parse_content_type(url) + '\r\n'
        content_length = 'Content-Length: ' + str(len(body)) + '\r\n'
        connection = 'Connection: close\r\n\r\n'
        headers = response_prase + server + date + content_type + content_length + connection
        return headers

    def generate_response(self, request):
        method, url = self.parse_request(request)
        response_prase, code = self.generate_code(method, url)
        body = self.generate_body(code, url)
        headers = self.generate_headers(url, body, response_prase)
        if method == 'HEAD':
             return headers.encode()
        return headers.encode() + body








