# OServer

./prefork_httpd2.py -r httptest -w 3

curl -X GET http://127.0.0.1:5123/wikipedia_russia.html

ab -n 10000 -c 4 -r http://172.17.0.2:5123/wikipedia_russia.html
