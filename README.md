# atyx-notify-client

Python-клиент для Atyx Notify API. Отправляет JSON-запросы с подписью
HMAC-SHA512 и предоставляет функции для проверки подписи на стороне сервера.

## Установка

Требуется Python 3.8 или новее. Зависимость `requests` устанавливается автоматически.

Из каталога проекта:

```bash
python -m pip install .
```

Для разработки:

```bash
python -m pip install -e '.[dev]'
```

## Быстрый старт

Для отправки нужны API-ключ и соответствующий секрет из Atyx Notify.
Каналы доставки настраиваются на стороне сервиса для этого ключа.

Задайте переменные окружения `NOTIFY_APIKEY` и `NOTIFY_APISECRET`, затем выполните:

```python
import os

from atyx_notify_client import NotifyApi

api = NotifyApi(
    apikey=os.environ["NOTIFY_APIKEY"],
    apisecret=os.environ["NOTIFY_APISECRET"],
)

try:
    response = api.send_message("Привет из Python!")
    response.raise_for_status()
    result = response.json()
    if result.get("status") != "ok":
        raise RuntimeError(f"Ошибка Notify API: {result.get('errors', result)}")
    print("Сообщение отправлено")
finally:
    api.session.close()
```

В этом примере ключ и секрет читаются из окружения пользовательским кодом:
сам клиент принимает их через параметры конструктора.

`send_message(message)` отправляет `{"message": message}` и возвращает
`requests.Response`. Клиент не вызывает `raise_for_status()` и не проверяет
JSON-ответ автоматически. Сетевые ошибки передаются вызывающему коду как
исключения `requests`.

Ответ сервиса при успехе — `{"status": "ok"}`, при ошибке —
`{"status": "error", "errors": [...]}`. Проверяйте поле `status`, поскольку
ошибка API может сопровождаться HTTP-кодом 200.

## Адрес API

Адрес выбирается в следующем порядке:

1. Непустой параметр `baseurl` конструктора.
2. Переменная окружения `NOTIFY_BASEURL`.
3. Адрес по умолчанию: `https://notify.atyx.ru/notify/`.

Пример для локального сервера:

```python
api = NotifyApi(
    apikey="your-api-key",
    apisecret="your-api-secret",
    baseurl="http://localhost:8000/notify/",
)
```

Или задайте адрес через окружение:

```bash
export NOTIFY_BASEURL='http://localhost:8000/notify/'
```

## Отправка произвольных данных

`post(url, data)` отправляет подписанный POST-запрос с JSON-телом:

```python
response = api.post("", {"message": "Сообщение без форматирования", "plain": True})
response.raise_for_status()
result = response.json()
```

`url` — суффикс, который напрямую добавляется к `baseurl`. Клиент не нормализует
разделяющие слеши: при `baseurl="http://localhost:8000/notify/"` суффикс
`"endpoint/"` даст `/notify/endpoint/`, а `"/endpoint/"` — `/notify//endpoint/`.
Пустая строка отправляет запрос на сам `baseurl`, как и `send_message()`.
Допустимые поля и пути определяются серверным API.

## Подпись запросов

Клиент автоматически добавляет заголовки:

| Заголовок | Значение |
| --- | --- |
| `X-ATYX-APIKEY` | API-ключ |
| `X-ATYX-TIMESTAMP` | Unix timestamp в миллисекундах |
| `X-ATYX-CONTENTHASH` | SHA-512 от `json.dumps(data).encode("utf-8")` |
| `X-ATYX-SIGNATURE` | HMAC-SHA512 с API-секретом |

Строка для подписи имеет вид `timestamp|uri|method|contenthash`.
Для исходящих запросов метод — `post`. При вычислении подписи URI содержит
схему, имя хоста и путь; порт и query string исключаются. Сам HTTP-запрос
отправляется на исходный адрес, включая указанный порт.

Для серверной проверки используйте `check_signature()` с подписью и данными
входящего запроса:

```python
valid = api.check_signature(
    signature=signature_from_header,
    timestamp=int(timestamp_from_header),
    uri="https://notify.atyx.ru/notify/",
    method="post",
    data=parsed_json_body,
)
```

Переменные `signature_from_header`, `timestamp_from_header` и `parsed_json_body`
в примере берутся из входящего запроса. API-секрет должен соответствовать его
API-ключу. Метод передавайте в нижнем регистре, как при отправке клиентом.

Проверка возвращает `False`, если timestamp неположительный, отличается от
текущего времени более чем на 5000 мс или подпись не совпадает. Для успешной
проверки часы клиента и сервера должны быть синхронизированы. Порядок ключей
и параметры JSON-сериализации влияют на хеш.

Также доступны функции `get_timestamp()` и `get_contenthash(data)` как на уровне
модуля `atyx_notify_client`, так и статические методы `NotifyApi`.

## Тесты

После установки зависимостей разработки запустите из корня проекта:

```bash
python -m pytest
```
