#!/usr/bin/python3

import os
import errno
import socket
import logging
from handler import Handler
from optparse import OptionParser


def read_all(sock, maxbuff, TIMEOUT=5):
    data = b''
    sock.settimeout(TIMEOUT)
    while True:
        buf = sock.recv(maxbuff)
        data += buf
        if not buf or b'\r\n\r\n' in data:
            break
    return data

def run(addr, port, root_dir, worker, maxbuff):
    workers = []
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((addr, port))
    server_socket.listen()

    for i in range(worker):
        pid = os.fork()
        if pid != 0:
            workers.append(pid)
        else:
            while True:
                try:
                    client_socket, addr = server_socket.accept()
                except IOError as e:
                    if e.errno == errno.EINTR:
                        continue
                    raise
                request = read_all(client_socket, maxbuff)
                if len(request.strip()) == 0:
                    client_socket.close()
                    continue
                handler = Handler(request, root_dir)
                if request:
                    response = handler.generate_response(request.decode())
                    client_socket.sendall(response)
                client_socket.close()
    server_socket.close()

    for pid in workers:
        os.waitpid(pid, 0)


if __name__ == '__main__':
    op = OptionParser()
    op.add_option("-p", "--port", type=int, default=80)
    op.add_option("-r", "--root", type=str, default='/')
    op.add_option("-w", "--worker", type=int, default=1)
    op.add_option("-b", "--buffer", type=int, default=1024)
    (opts, args) = op.parse_args()
    DOCUMENT_ROOT = opts.root if opts.root.startswith('/') else '/' + opts.root
    logging.basicConfig(level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    logging.info('Starting server at %s' % opts.port)
    logging.info('DOCUMENT_ROOT is %s' % DOCUMENT_ROOT)
    run('127.0.0.1', opts.port, DOCUMENT_ROOT, opts.worker, opts.buffer)
#    run('172.17.0.2', opts.port, DOCUMENT_ROOT, opts.worker, opts.buffer)


