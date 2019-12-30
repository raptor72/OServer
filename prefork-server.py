#!/usr/bin/python3

import os
import sys
import errno
import socket
import logging
from handler import Handler
from optparse import OptionParser


class Server:
    def __init__(self, addr, port, root_dir, worker=1):
        self.addr = addr
        self.port = port
        self.root_dir = root_dir
        self.worker = worker
        self.handler = Handler
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def run(self):
        workers = []
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.addr, self.port))
        self.server_socket.listen()

        for i in range(self.worker):
            pid = os.fork()
            if pid != 0:
                workers.append(pid)
            else:
                while True:
                    try:
                         client_socket, addr = self.server_socket.accept()
                    except IOError as e:
                        if e.errno == errno.EINTR:
                            continue
                        raise
                    request = client_socket.recv(1024)
                    if len(request.strip()) == 0:
                        client_socket.close()
                        continue
                    handler = self.handler(request, self.root_dir)
                    if request:
                        response = handler.generate_response(request.decode())
                        client_socket.sendall(response)
                    client_socket.close()
        self.server_socket.close()

        for pid in workers:
            os.waitpid(pid, 0)

if __name__ == '__main__':
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=5123)
    op.add_option("-r", "--root", action="store", type=str, default='/')
    op.add_option("-l", "--log", action="store", default=None)
    op.add_option("-w", "--worker", type=int, default=1)
    (opts, args) = op.parse_args()
    if opts.root.startswith('/'):
        DOCUMENT_ROOT = opts.root
    else:
        DOCUMENT_ROOT = '/' + opts.root
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    logging.info('Starting server at %s' % opts.port)
    logging.info('DOCUMENT_ROOT is %s' % DOCUMENT_ROOT)

    server = Server('127.0.0.1', opts.port, DOCUMENT_ROOT, opts.worker)
#    server = Server('172.17.0.2', opts.port, DOCUMENT_ROOT, opts.worker)
    server.run()


