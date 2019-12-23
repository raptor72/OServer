#!/usr/bin/python3

import os
import sys
import socket
import logging
import datetime

from optparse import OptionParser


DOCUMENT_ROOT = 'root'

def parse_request(request):
    parsed = request.split(' ')
    method = parsed[0]
    url = parsed[1]
    if url.startswith('/'):
        url = url[1:]
    return (method, url.replace('%20', ' '))


def parse_content_type(url):
    if os.path.isfile(os.path.join(DOCUMENT_ROOT, url)) or os.path.isfile(url):
        try:
            extension =  url.split('.')[1]
            if extension in ['html', 'css', 'js', 'jpg', 'jpeg', 'png', 'gif', 'swf']:
                return extension
        except:
            return 'text/html;charset=UTF-8'
    return 'text/html;charset=UTF-8'

def generate_headers(method, url):
    server = 'Server: python ' + sys.version.split('[')[0].strip() + ' ' +  sys.version.split('[')[1].strip().replace(']', '')
    date = 'Date: ' + datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_type = 'Content-Type: ' + parse_content_type(url)
    connection = 'Connection: close'
    content_length = 'Content-Length: ' + str(sys.getsizeof(url))

    if method not in ['GET', 'HEAD']:
        return ('HTTP/1.1 405 Methd not allowed\n\n', 405)
    logging.info(f'url is: {url}, type is: {type(url)}, len is:  {len(url)}, bytelen is: {sys.getsizeof(url)}')
    if not os.path.exists(url) and not os.path.exists(os.path.join(DOCUMENT_ROOT, url)):
        return ('HTTP/1.1 404 not found\n\n', 404)
    return (('HTTP/1.1 200 OK\n' + server + '\n' + date + '\n' + content_type + '\n' + connection + content_length + '\n\n' , 200))

def render_html(html_file):
    with open(html_file, 'r') as html:
        data = html.read()
    return data


def generate_content(code, url):
    if code == 404:
        return '<h1>404</h1><p>Not found</p>'
    if code == 405:
        return '<h1>405</h1><p>Method not allowed</p>'

    if url == DOCUMENT_ROOT:
        return '\r\n'.join( '<p>' + repr(e).replace("'", '') + '</p>' for e in os.listdir(url))

    if not '/' in url:
        if os.path.isfile(os.path.join(DOCUMENT_ROOT, url)):
            content_type = parse_content_type(url)
            if content_type == 'html':
                return render_html(os.path.join(DOCUMENT_ROOT, url))
            return '<p>Content type of file is: ' + content_type + '</p>'
    if os.path.isfile(url):
        content_type = parse_content_type(url)
        if content_type == 'html':
            return render_html(url)
        return '<p>Content type of file is: ' + content_type + '</p>'

    if os.path.isdir(url):
        if os.path.exists(os.path.join(url, 'index.html')):
            return render_html(os.path.join(url, 'index.html'))
    return '<p>No such file or directory</p>'

def generate_response(request):
    method, url = parse_request(request)
    headers, code = generate_headers(method, url)
    logging.info('Headers is %s' % headers)
    body = generate_content(code, url)
    return (headers + body).encode()

def run(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#    server_socket.bind(('127.0.0.1', port))
    server_socket.bind(('172.17.0.2', port))
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
    op.add_option("-r", "--root", action="store", type=str, default="root")
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    logging.info('Starting server at %s' % opts.port)
    run(opts.port)


