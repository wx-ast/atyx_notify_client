import hashlib
import hmac
import json
import os
import time
from unittest.mock import MagicMock, patch

import pytest
import requests
from freezegun import freeze_time

from atyx_notify_client import get_contenthash, get_timestamp, NotifyApi


# ---------------------------------------------------------------------------
# Module-level functions
# ---------------------------------------------------------------------------

class TestGetContenthash:
    def test_returns_hex_string(self):
        result = get_contenthash({"key": "value"})
        assert isinstance(result, str)
        assert len(result) == 128  # SHA-512 hex digest length

    def test_consistent_for_same_input(self):
        data = {"a": 1, "b": [2, 3]}
        assert get_contenthash(data) == get_contenthash(data)

    def test_different_for_different_input(self):
        h1 = get_contenthash({"a": 1})
        h2 = get_contenthash({"a": 2})
        assert h1 != h2

    def test_empty_dict(self):
        result = get_contenthash({})
        expected = hashlib.sha512(json.dumps({}).encode("utf-8")).hexdigest()
        assert result == expected

    def test_unicode_data(self):
        data = {"msg": "привет \u00e9"}
        result = get_contenthash(data)
        expected = hashlib.sha512(json.dumps(data).encode("utf-8")).hexdigest()
        assert result == expected

    def test_nested_dict(self):
        data = {"outer": {"inner": [1, "a", True]}}
        result = get_contenthash(data)
        expected = hashlib.sha512(json.dumps(data).encode("utf-8")).hexdigest()
        assert result == expected

    def test_numeric_values(self):
        data = {"int": 42, "float": 3.14, "neg": -1, "zero": 0}
        result = get_contenthash(data)
        expected = hashlib.sha512(json.dumps(data).encode("utf-8")).hexdigest()
        assert result == expected

    def test_none_value(self):
        data = {"val": None}
        result = get_contenthash(data)
        expected = hashlib.sha512(json.dumps(data).encode("utf-8")).hexdigest()
        assert result == expected


class TestGetTimestamp:
    def test_returns_int(self):
        result = get_timestamp()
        assert isinstance(result, int)

    def test_returns_current_time_in_ms(self):
        with freeze_time("2024-01-15 12:00:00"):
            result = get_timestamp()
            expected = 1705320000000
            assert result == expected


# ---------------------------------------------------------------------------
# NotifyApi.__init__
# ---------------------------------------------------------------------------

class TestNotifyApiInit:
    def test_stores_apikey(self):
        client = NotifyApi("mykey", "mysecret")
        assert client.apikey == "mykey"

    def test_stores_apisecret(self):
        client = NotifyApi("mykey", "mysecret")
        assert client.apisecret == "mysecret"

    def test_uses_default_baseurl_when_not_provided(self):
        client = NotifyApi("mykey", "mysecret")
        assert client.baseurl == NotifyApi.DEFAULT_BASEURL

    def test_uses_provided_baseurl(self):
        client = NotifyApi("mykey", "mysecret", baseurl="http://localhost:9999/notify/")
        assert client.baseurl == "http://localhost:9999/notify/"

    def test_falls_back_to_env_variable(self, monkeypatch):
        monkeypatch.setenv("NOTIFY_BASEURL", "http://env.host/notify/")
        client = NotifyApi("mykey", "mysecret")
        assert client.baseurl == "http://env.host/notify/"

    def test_explicit_baseurl_overrides_env(self, monkeypatch):
        monkeypatch.setenv("NOTIFY_BASEURL", "http://env.host/notify/")
        client = NotifyApi("mykey", "mysecret", baseurl="http://custom/notify/")
        assert client.baseurl == "http://custom/notify/"

    def test_creates_session(self):
        client = NotifyApi("mykey", "mysecret")
        assert isinstance(client.session, requests.Session)

    def test_session_has_correct_headers(self):
        client = NotifyApi("mykey", "mysecret")
        assert client.session.headers["Content-Type"] == "application/json;charset=utf-8"
        assert client.session.headers["X-ATYX-APIKEY"] == "mykey"


# ---------------------------------------------------------------------------
# NotifyApi.get_timestamp (class static method)
# ---------------------------------------------------------------------------

class TestNotifyApiGetTimestamp:
    def test_returns_int(self):
        result = NotifyApi.get_timestamp()
        assert isinstance(result, int)

    def test_returns_current_time_in_ms(self):
        from datetime import datetime, timezone
        frozen = datetime(2024, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
        expected = int(frozen.timestamp() * 1000)
        with freeze_time(frozen):
            result = NotifyApi.get_timestamp()
            assert result == expected


# ---------------------------------------------------------------------------
# NotifyApi.get_contenthash (class static method)
# ---------------------------------------------------------------------------

class TestNotifyApiGetContenthash:
    def test_returns_same_as_module_function(self):
        data = {"test": "data"}
        assert NotifyApi.get_contenthash(data) == get_contenthash(data)

    def test_consistent(self):
        data = {"nested": {"key": "val"}}
        assert NotifyApi.get_contenthash(data) == NotifyApi.get_contenthash(data)


# ---------------------------------------------------------------------------
# NotifyApi._get_signature
# ---------------------------------------------------------------------------

class TestGetSignature:
    def _make_client(self):
        return NotifyApi("testkey", "testsecret")

    def test_returns_hex_string(self):
        client = self._make_client()
        result = client._get_signature(1000, "http://host/path", "post", "chash")
        assert isinstance(result, str)
        assert len(result) == 128  # SHA-512 hex digest

    def test_signature_is_deterministic(self):
        client = self._make_client()
        sig1 = client._get_signature(1000, "http://host/path", "post", "chash")
        sig2 = client._get_signature(1000, "http://host/path", "post", "chash")
        assert sig1 == sig2

    def test_different_timestamp_produces_different_signature(self):
        client = self._make_client()
        sig1 = client._get_signature(1000, "http://host/path", "post", "chash")
        sig2 = client._get_signature(2000, "http://host/path", "post", "chash")
        assert sig1 != sig2

    def test_different_data_produces_different_signature(self):
        client = self._make_client()
        sig1 = client._get_signature(1000, "http://host/path", "post", "hash1")
        sig2 = client._get_signature(1000, "http://host/path", "post", "hash2")
        assert sig1 != sig2

    def test_strips_port_from_uri(self):
        client = self._make_client()
        sig_with_port = client._get_signature(1000, "http://host:8443/notify/", "post", "chash")
        sig_without_port = client._get_signature(1000, "http://host/notify/", "post", "chash")
        assert sig_with_port == sig_without_port

    def test_uses_correct_signing_string_format(self):
        """The signing input should be 'timestamp|uri|method|contenthash'."""
        client = self._make_client()
        timestamp = 1000
        uri = "http://host/path"
        method = "post"
        contenthash = "myhash"
        expected_presign = f"{timestamp}|{uri}|{method}|{contenthash}"

        with patch("hmac.new") as mock_new:
            mock_new.return_value = MagicMock(hexdigest=MagicMock(return_value="abc123"))
            client._get_signature(timestamp, uri, method, contenthash)
            mock_new.assert_called_once()
            call_args = mock_new.call_args
            assert call_args[0][1] == expected_presign.encode("utf-8")


# ---------------------------------------------------------------------------
# NotifyApi._get_sugnature backward-compat alias
# ---------------------------------------------------------------------------

class TestGetSugnatureAlias:
    def test_alias_exists(self):
        assert hasattr(NotifyApi, "_get_sugnature")

    def test_alias_points_to_same_function(self):
        assert NotifyApi._get_sugnature is NotifyApi._get_signature

    def test_alias_produces_same_result(self):
        client = NotifyApi("k", "s")
        sig1 = client._get_signature(1, "http://h/p", "post", "ch")
        sig2 = client._get_sugnature(1, "http://h/p", "post", "ch")
        assert sig1 == sig2


# ---------------------------------------------------------------------------
# NotifyApi.check_signature
# ---------------------------------------------------------------------------

class TestCheckSignature:
    def _make_client(self, secret="testsecret"):
        return NotifyApi("testkey", secret)

    def test_valid_signature_returns_true(self):
        client = self._make_client()
        data = {"msg": "hello"}

        with freeze_time("2024-01-01 00:00:00"):
            contenthash = client.get_contenthash(data)
            now_ms = int(time.time() * 1000)
            sig = client._get_signature(now_ms, "http://host/notify/test", "post", contenthash)
            result = client.check_signature(sig, now_ms, "http://host/notify/test", "post", data)

        assert result is True

    def test_wrong_signature_returns_false(self):
        client = self._make_client()
        data = {"msg": "hello"}
        contenthash = client.get_contenthash(data)
        sig = client._get_signature(1000, "http://host/notify/test", "post", contenthash)

        with freeze_time("2024-01-01 00:00:00"):
            now_ms = int(time.time() * 1000)
            result = client.check_signature("wrong_signature", now_ms, "http://host/notify/test", "post", data)

        assert result is False

    def test_zero_timestamp_returns_false(self):
        client = self._make_client()
        data = {"msg": "hello"}
        sig = client._get_signature(1000, "http://host/notify/test", "post", get_contenthash(data))
        result = client.check_signature(sig, 0, "http://host/notify/test", "post", data)
        assert result is False

    def test_negative_timestamp_returns_false(self):
        client = self._make_client()
        data = {"msg": "hello"}
        sig = client._get_signature(1000, "http://host/notify/test", "post", get_contenthash(data))
        result = client.check_signature(sig, -100, "http://host/notify/test", "post", data)
        assert result is False

    def test_expired_timestamp_returns_false(self):
        client = self._make_client()
        data = {"msg": "hello"}
        contenthash = client.get_contenthash(data)
        sig = client._get_signature(1000, "http://host/notify/test", "post", contenthash)

        with freeze_time("2024-01-01 00:00:00"):
            far_past = 1000  # Very old timestamp, well beyond 5s tolerance
            result = client.check_signature(sig, far_past, "http://host/notify/test", "post", data)

        assert result is False

    def test_fresh_timestamp_within_tolerance(self):
        client = self._make_client()
        data = {"msg": "hello"}

        with freeze_time("2024-01-01 00:00:00"):
            contenthash = client.get_contenthash(data)
            now = int(time.time() * 1000)
            sig = client._get_signature(now, "http://host/notify/test", "post", contenthash)
            result = client.check_signature(sig, now, "http://host/notify/test", "post", data)
            assert result is True

    def test_different_secret_produces_different_signature(self):
        client1 = self._make_client("secret1")
        client2 = self._make_client("secret2")
        data = {"msg": "hello"}
        contenthash = client1.get_contenthash(data)
        sig = client1._get_signature(1000, "http://host/notify/test", "post", contenthash)

        with freeze_time("2024-01-01 00:00:00"):
            now_ms = int(time.time() * 1000)
            result = client2.check_signature(sig, now_ms, "http://host/notify/test", "post", data)

        assert result is False

    def test_different_uri_produces_different_signature(self):
        client = self._make_client()
        data = {"msg": "hello"}
        contenthash = client.get_contenthash(data)
        sig = client._get_signature(1000, "http://host/notify/path1", "post", contenthash)

        with freeze_time("2024-01-01 00:00:00"):
            now_ms = int(time.time() * 1000)
            result = client.check_signature(
                sig, now_ms, "http://host/notify/path2", "post", data
            )

        assert result is False


# ---------------------------------------------------------------------------
# NotifyApi.post
# ---------------------------------------------------------------------------

class TestPost:
    def _make_client(self):
        return NotifyApi("testkey", "testsecret", baseurl="https://notify.atyx.ru:8443/notify/")

    def test_posts_to_correct_url(self):
        client = self._make_client()
        data = {"msg": "hello"}

        with freeze_time("2024-01-01 00:00:00"):
            with patch.object(client.session, "post") as mock_post:
                mock_post.return_value = MagicMock(status_code=200)
                client.post("/endpoint", data)
                mock_post.assert_called_once_with(
                    "https://notify.atyx.ru/notify//endpoint",
                    json=data,
                )

    def test_strips_port_from_url(self):
        client = self._make_client()
        data = {}

        with freeze_time("2024-01-01 00:00:00"):
            with patch.object(client.session, "post") as mock_post:
                mock_post.return_value = MagicMock(status_code=200)
                client.post("/test", data)
                called_url = mock_post.call_args[0][0]
                assert ":8443" not in called_url

    def test_sets_signature_headers(self):
        client = self._make_client()
        data = {"msg": "hello"}

        with freeze_time("2024-01-01 00:00:00"):
            with patch.object(client.session, "post") as mock_post:
                mock_post.return_value = MagicMock(status_code=200)
                client.post("/endpoint", data)

                # Verify headers were set on the session
                assert "X-ATYX-TIMESTAMP" in client.session.headers
                assert "X-ATYX-CONTENTHASH" in client.session.headers
                assert "X-ATYX-SIGNATURE" in client.session.headers

    def test_timestamp_header_is_int_string(self):
        client = self._make_client()
        data = {"msg": "hello"}

        with freeze_time("2024-01-01 00:00:00"):
            with patch.object(client.session, "post") as mock_post:
                mock_post.return_value = MagicMock(status_code=200)
                client.post("/endpoint", data)
                ts = client.session.headers["X-ATYX-TIMESTAMP"]
                assert ts.isdigit()

    def test_contenthash_header_is_correct(self):
        client = self._make_client()
        data = {"key": "value"}
        expected_hash = get_contenthash(data)

        with freeze_time("2024-01-01 00:00:00"):
            with patch.object(client.session, "post") as mock_post:
                mock_post.return_value = MagicMock(status_code=200)
                client.post("/endpoint", data)
                assert client.session.headers["X-ATYX-CONTENTHASH"] == expected_hash

    def test_signature_header_is_correct(self):
        client = self._make_client()
        data = {"key": "value"}

        with freeze_time("2024-01-01 00:00:00"):
            with patch.object(client.session, "post") as mock_post:
                mock_post.return_value = MagicMock(status_code=200)
                client.post("/endpoint", data)

                ts = int(client.session.headers["X-ATYX-TIMESTAMP"])
                contenthash = client.session.headers["X-ATYX-CONTENTHASH"]
                expected_sig = client._get_signature(ts, "https://notify.atyx.ru/notify//endpoint", "post", contenthash)
                assert client.session.headers["X-ATYX-SIGNATURE"] == expected_sig

    def test_returns_response(self):
        client = self._make_client()
        data = {"msg": "hello"}
        mock_response = MagicMock(status_code=200)

        with freeze_time("2024-01-01 00:00:00"):
            with patch.object(client.session, "post", return_value=mock_response) as mock_post:
                response = client.post("/endpoint", data)
                assert response is mock_response

    def test_sends_json_data(self):
        client = self._make_client()
        data = {"msg": "hello", "num": 42}

        with freeze_time("2024-01-01 00:00:00"):
            with patch.object(client.session, "post") as mock_post:
                mock_post.return_value = MagicMock(status_code=200)
                client.post("/endpoint", data)
                mock_post.assert_called_once()
                assert mock_post.call_args[1]["json"] == data

    def test_custom_baseurl(self):
        client = NotifyApi("k", "s", baseurl="http://custom.host:3000/notify/")
        data = {}

        with freeze_time("2024-01-01 00:00:00"):
            with patch.object(client.session, "post") as mock_post:
                mock_post.return_value = MagicMock(status_code=200)
                client.post("/test", data)
                called_url = mock_post.call_args[0][0]
                assert called_url == "http://custom.host/notify//test"

    def test_empty_url_path(self):
        client = self._make_client()
        data = {}

        with freeze_time("2024-01-01 00:00:00"):
            with patch.object(client.session, "post") as mock_post:
                mock_post.return_value = MagicMock(status_code=200)
                client.post("", data)
                called_url = mock_post.call_args[0][0]
                assert called_url == "https://notify.atyx.ru/notify/"
