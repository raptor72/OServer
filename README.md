# OServer

Веб-сервер написанный на "ванильном" python.
Для работы с HTTP не используются сторонние библиотеки.
Архитектура приложения: prefork-server.


Сервер может масштабироваться на несколько воркеров. Для задания их количества используется аргумент `-w`.
Прослушаваемый порт задается аргументом `-p`.
Путь `DOCUMENT_ROOT` по которому будут возвращаться файлы задается аргументом `-r`.

#### Пример запуска:
    ./httpd.py -r / -p 8080 -w 2


#### Пример тестов:
    ./httptest.py

#### результаты нагрузочного тестирования ApacheBenchmark с одним воркером:

    ab -n 50000 -c 100 -r http://localhost:8080/httptest/wikipedia_russia.html


    Server Software:        python
    Server Hostname:        localhost
    Server Port:            8080

    Document Path:          /httptest/wikipedia_russia.html
    Document Length:        954824 bytes

    Concurrency Level:      100
    Time taken for tests:   23.096 seconds
    Complete requests:      50000
    Failed requests:        0
    Write errors:           0
    Total transferred:      47752250000 bytes
    HTML transferred:       47741200000 bytes
    Requests per second:    2164.89 [#/sec] (mean)
    Time per request:       46.192 [ms] (mean)
    Time per request:       0.462 [ms] (mean, across all concurrent requests)
    Transfer rate:          2019107.77 [Kbytes/sec] received

    Connection Times (ms)
                  min  mean[+/-sd] median   max
    Connect:        0    0   0.1      0       2
    Processing:     2   46   2.1     46      79
    Waiting:        1   46   1.8     46      66
    Total:          4   46   2.0     46      80

#### с двумя воркерами:

    ab -n 50000 -c 100 -r http://localhost:8080/httptest/wikipedia_russia.html


    Server Software:        python
    Server Hostname:        localhost
    Server Port:            8080

    Document Path:          /httptest/wikipedia_russia.html
    Document Length:        954824 bytes

    Concurrency Level:      100
    Time taken for tests:   12.459 seconds
    Complete requests:      50000
    Failed requests:        0
    Write errors:           0
    Total transferred:      47752250000 bytes
    HTML transferred:       47741200000 bytes
    Requests per second:    4013.30 [#/sec] (mean)
    Time per request:       24.917 [ms] (mean)
    Time per request:       0.249 [ms] (mean, across all concurrent requests)
    Transfer rate:          3743047.49 [Kbytes/sec] received

    Connection Times (ms)
                  min  mean[+/-sd] median   max
    Connect:        0    0   0.1      0       2
    Processing:     2   25   0.7     25      29
    Waiting:        1   24   0.7     24      28
    Total:          4   25   0.7     25      30

