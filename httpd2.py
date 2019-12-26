#!/usr/bin/python3

import os
import sys
import socket
import logging
import datetime
import urllib.parse

from optparse import OptionParser


def parse_document_root(r):
#    return r if r else '/'
    return r if r else os.getcwd()

#urllib.parse.unquote(url)

def parse_request(request):
    parsed = request.split(' ')
    method = parsed[0]
    try:
        url = parsed[1].split('?')[0]
        if url.startswith('/'):
            url = urllib.parse.unquote(url[1:])
        return (method, urllib.parse.unquote( url.replace('%20', ' '))  )
    except:
        return method, ''



def parse_content_type(url):
    if os.path.isfile(os.path.join(DOCUMENT_ROOT, url)) or os.path.isfile(url):
        try:
            extension =  url.split('.')[1]
            if extension in ['html', 'css', 'js', 'jpg', 'jpeg', 'png', 'gif', 'swf']:
                return extension
        except:
            return 'text/html;charset=UTF-8'
    return 'text/html;charset=UTF-8'


def generate_code(method, url):
#    path = os.getcwd()
    if method not in ['GET', 'HEAD']:
        return ('HTTP/1.1 405 Methd not allowed\r\n', 405)
    logging.info(f'url is: {url}, type is: {type(url)}, len is:  {len(url)}, bytelen is: {sys.getsizeof(url)}')
#    if not os.path.exists(path + url) and not os.path.exists(os.path.join(DOCUMENT_ROOT, url)):
#    if not os.path.exists(path + url) and not os.path.exists(os.path.join(DOCUMENT_ROOT, url)) and not os.path.exists(os.path.join(path, url)): #uncorrect document root escaping forbidden
#    if not os.path.exists(os.path.join(DOCUMENT_ROOT, url)) and not os.path.exists(os.path.join(path, DOCUMENT_ROOT, url)):
#    if not os.path.exists(os.path.join(DOCUMENT_ROOT, url)) and not os.path.exists(os.path.join(DOCUMENT_ROOT, url, 'index.html')):
    if not os.path.exists(os.path.join(DOCUMENT_ROOT, url)) or not os.path.abspath(os.path.join(DOCUMENT_ROOT, url)).startswith(DOCUMENT_ROOT):
        return ('HTTP/1.1 404 not found\r\n', 404)

    if os.path.isdir(os.path.join(DOCUMENT_ROOT, url)):
        if not os.path.exists(os.path.join(DOCUMENT_ROOT, url, 'index.html')):
            return ('HTTP/1.1 404 not found\r\n', 404)

    return ('HTTP/1.1 200 OK\r\n', 200)


def render_html(html_file):
    with open(html_file, 'rb') as html:
#    with open(html_file, 'r', encoding='utf8') as html:
        data = html.read()
    try:
        data = data.decode('utf8')
    except UnicodeDecodeError:
        data = str(data)
    return data

def generate_result(code, url):
    logging.info(f'code is: {code}, url is: {url}')
    if code == 404:
        return '<h1>404</h1><p>Not found</p>'
    if code == 405:
        return '<h1>405</h1><p>Method not allowed</p>'
    if url == DOCUMENT_ROOT:
        return '\r\n'.join( '<p>' + repr(e).replace("'", '') + '</p>' for e in os.listdir(url))
    if not '/' in url:
        if os.path.isfile(os.path.join(DOCUMENT_ROOT, url)):
#            content_type = parse_content_type(url)
#            if content_type == 'html':
            return render_html(os.path.join(DOCUMENT_ROOT, url))
#            return '<p>Content type of file is: ' + content_type + '</p>'
    if os.path.isfile(url):
#        content_type = parse_content_type(url)
#        if content_type == 'html':
        return render_html(url)
#        return '<p>Content type of file is: ' + content_type + '</p>'
    if os.path.isdir(url):
        if os.path.exists(os.path.join(url, 'index.html')):
            return render_html(os.path.join(url, 'index.html'))
    return '<p>No such file or directory</p>'

def generate_headers(url, body, response_prase):
    server = 'Server: python ' + sys.version.split('[')[0].strip() + ' ' +  sys.version.split('[')[1].strip().replace(']', '') + '\r\n'
    date = 'Date: ' + datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT') + '\r\n'
    content_type = 'Content-Type: ' + parse_content_type(url) + '\r\n'
    content_length = 'Content-Length: ' + str(len(body)) + '\r\n'
    connection = 'Connection: close\r\n\r\n'
    headers = response_prase + server + date + content_type + content_length + connection
    return headers

def generate_response(request):
    method, url = parse_request(request)
    response_prase, code = generate_code(method, url)
    logging.info('response_prase is %s' % response_prase)
    logging.info('code is %s' % code)
#    headers, code = generate_headers(method, url)
    body = generate_result(code, url)
#    print(type(body))
    headers = generate_headers(url, body, response_prase)
    logging.info('Headers is %s' % headers)

#    body = generate_content(code, url)
    return (headers + body).encode()
#    return headers + body

def run(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('127.0.0.1', port))
#    server_socket.bind(('172.17.0.2', port))
    server_socket.listen()

    while True:
        client_socket, addr = server_socket.accept()
        request = client_socket.recv(1024)
        logging.info('request is: %s', request)
        logging.info('addres is: %s', addr)
        if request:
            response = generate_response(request.decode('utf-8'))
            client_socket.sendall(response)
        client_socket.close()


if __name__ == '__main__':
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=5123)
    op.add_option("-r", "--root", action="store", type=str)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    DOCUMENT_ROOT = parse_document_root(opts.root)
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    logging.info('Starting server at %s' % opts.port)
    logging.info('DOCUMENT_ROOT is %s' % DOCUMENT_ROOT)
    run(opts.port)



