#!/usr/bin/python3

import os
import sys
import socket
import logging
import datetime
import urllib.parse

from handler import Handler
from optparse import OptionParser

class Server:

    def __init__(self, addr, port, root_dir, workers=1):
        self.addr = addr
        self.port = port
        self.root_dir = root_dir
        self.workers = workers
        self.handler = Handler
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def run(self):
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.addr, self.port))
        self.server_socket.listen()

        while True:
            client_socket, addr = self.server_socket.accept()
            request = client_socket.recv(1024)
#            handler = Handler(request, DOCUMENT_ROOT)
            handler = self.handler(request, self.root_dir)
#            logging.info('request is: %s', request)
#            logging.info('addres is: %s', addr)
            if request:
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
    server = Server('127.0.0.1', opts.port, DOCUMENT_ROOT)
    server.run()
