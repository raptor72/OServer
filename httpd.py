#!/usr/bin/python3


import socket


URLS = {
    '/authors': 'Author_A: 1, Author_B: 2, Author_C: 3',
    '/author/1': 'Book 1: 1, Book 2: 1, Book 3: 1',
    '/author/2': 'Book 1: 2, Book 2: 2',
    '/author/3': 'Book 1: 3, Book 2: 3, Book 3: 3, Book 4: 3'
}

def parse_request(request):
    parsed = request.split(' ')
    method = parsed[0]
    url = parsed[1]
    return (method, url)


def generate_headers(method, url):
    if method != 'GET':
        return ('HTTP/1.1 405 Methd not allowed\n\n', 405)
    if url not in URLS:
        return ('HTTP/1.1 404 not found\n\n', 404)
    return (('HTTP/1.1 200 OK\n\n', 200))


def generate_content(code, url):
    if code == 404:
        return '<h1>404</h1><p>Not found</p>'
    if code == 405:
        return '<h1>405</h1><p>Method not allowed</p>'
    return '{}'.format(URLS[url])


def generate_response(request):
    method, url = parse_request(request)
    headers, code = generate_headers(method, url)
    body = generate_content(code, url)

    return (headers + body).encode()


def run():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('127.0.0.1', 5123))
    server_socket.listen()

    while True:
        client_socket, addr = server_socket.accept()
        request = client_socket.recv(1024)
        print(request)
        print()
        print(addr)

        response = generate_response(request.decode('utf-8'))

        client_socket.sendall(response)
        client_socket.close()


if __name__ == '__main__':
    run()

