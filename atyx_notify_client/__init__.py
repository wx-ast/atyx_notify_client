import hashlib
import hmac
import json
import os
import time
from urllib.parse import urlparse

import requests


def get_contenthash(data: dict) -> str:
    """Вычисляет SHA-512 хеш JSON-представления данных."""
    hash_object = hashlib.sha512(json.dumps(data).encode('utf-8'))
    return hash_object.hexdigest()


def get_timestamp() -> int:
    """Возвращает текущий timestamp в миллисекундах."""
    return int(time.time() * 1000)


class NotifyApi:
    """Универсальный клиент и хелпер для Notify API.

    Поддерживает:
    - отправку запросов (клиентская часть)
    - проверку сигнатур (серверная часть)
    """

    DEFAULT_BASEURL = 'https://notify.atyx.ru:8443/notify/'
    TIMESTAMP_TOLERANCE_MS = 5000  # 5 секунд

    def __init__(self, apikey: str, apisecret: str, baseurl: str = None):
        self.apikey = apikey
        self.apisecret = apisecret
        self.baseurl = baseurl or os.environ.get('NOTIFY_BASEURL', self.DEFAULT_BASEURL)

        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json;charset=utf-8',
            'X-ATYX-APIKEY': self.apikey,
        })

    @staticmethod
    def get_timestamp() -> int:
        """Возвращает текущий timestamp в миллисекундах."""
        return int(time.time() * 1000)

    @staticmethod
    def get_contenthash(data: dict) -> str:
        """Вычисляет SHA-512 хеш JSON-представления данных."""
        return get_contenthash(data)

    def check_signature(
        self,
        signature: str,
        timestamp: int,
        uri: str,
        method: str,
        data: dict,
    ) -> bool:
        """Проверяет сигнатуру запроса.

        Проверяет:
        - timestamp не равен нулю
        - разница timestamp'ов в пределах TIMESTAMP_TOLERANCE_MS
        - хеш сигнатуры
        """
        if timestamp <= 0:
            return False
        if abs(self.get_timestamp() - timestamp) > self.TIMESTAMP_TOLERANCE_MS:
            return False
        contenthash = get_contenthash(data)
        signature2 = self._get_signature(timestamp, uri, method, contenthash)
        return signature == signature2

    def post(self, url: str, data: dict) -> requests.Response:
        """Отправляет POST-запрос с подписью."""
        timestamp = get_timestamp()
        method = 'post'
        uri = ''.join((self.baseurl, url))
        original_uri = uri

        # Strip port from URI for consistent signing (nginx strips it from Host header)
        parsed = urlparse(uri)
        netloc = parsed.hostname
        signed_uri = f'{parsed.scheme}://{netloc}{parsed.path}'

        contenthash = get_contenthash(data)
        signature = self._get_signature(timestamp, signed_uri, method, contenthash)

        self.session.headers.update({
            'X-ATYX-TIMESTAMP': str(timestamp),
            'X-ATYX-CONTENTHASH': contenthash,
            'X-ATYX-SIGNATURE': signature,
        })

        response = self.session.post(original_uri, json=data)
        return response

    def send_message(self, message):
        return self.post('', {'message': message})

    def _get_signature(self, timestamp: int, uri: str, method: str, contenthash: str) -> str:
        """Генерирует HMAC-SHA512 сигнатуру."""
        parsed = urlparse(uri)
        netloc = parsed.hostname
        clean_uri = f'{parsed.scheme}://{netloc}{parsed.path}'

        presign = '|'.join((str(timestamp), clean_uri, method, contenthash))
        hash_object = hmac.new(
            self.apisecret.encode('utf-8'),
            presign.encode('utf-8'),
            hashlib.sha512,
        )
        return hash_object.hexdigest()


# Alias for backward compatibility (typo in original name)
NotifyApi._get_sugnature = NotifyApi._get_signature
