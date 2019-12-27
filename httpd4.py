#!/usr/bin/python3

import os
import sys
import socket
import logging
import datetime
import urllib.parse

from optparse import OptionParser
from handler import Handler

def run(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('127.0.0.1', port))
#    server_socket.bind(('172.17.0.2', port))
    server_socket.listen()

    while True:
        client_socket, addr = server_socket.accept()
        request = client_socket.recv(1024)
        handler = Handler(request, DOCUMENT_ROOT)
        logging.info('request is: %s', request)
        logging.info('addres is: %s', addr)
        if request:
#            response = generate_response(request.decode('utf-8'))
            response = handler.generate_response(request.decode())
            client_socket.sendall(response)
        client_socket.close()


if __name__ == '__main__':
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=5123)
    op.add_option("-r", "--root", action="store", type=str, default='/')
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    DOCUMENT_ROOT = opts.root
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    logging.info('Starting server at %s' % opts.port)
    logging.info('DOCUMENT_ROOT is %s' % DOCUMENT_ROOT)
    run(opts.port)



