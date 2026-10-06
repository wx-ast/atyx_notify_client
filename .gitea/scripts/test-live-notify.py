"""Check the deployed Notify API using a dedicated test key."""

import os
import sys
import time

import requests
from atyx_notify_client import NotifyApi


URL = 'https://notify.atyx.ru/notify/'
KNOWN_ERRORS = {
    'invalid auth token', 'invalid timestamp', 'apikey not available',
    'timestamp not available', 'apisignature not available', 'timestamp is too old',
    'account or apikey deactivated', 'apikey not found', 'signature not valid',
    'invalid message_ucs2', 'invalid plain', 'message not available', 'message not sent',
}


class TestFailure(Exception):
    pass


class TimedSession(requests.Session):
    def request(self, method, url, **kwargs):
        kwargs.setdefault('timeout', (5, 20))
        kwargs.setdefault('allow_redirects', False)
        return super().request(method, url, **kwargs)


def describe_result(result):
    """Report fixed API error messages without logging arbitrary response data."""
    if not isinstance(result, dict):
        return 'response is not an object'
    status = result.get('status')
    summary = f'status={status}' if status in ('ok', 'error') else 'status=unknown'
    errors = result.get('errors')
    if isinstance(errors, list):
        safe_errors = [error if isinstance(error, str) and error in KNOWN_ERRORS
                       else '<unrecognized error>' for error in errors[:20]]
        if safe_errors:
            summary += '; errors=' + ', '.join(safe_errors)
    return summary


def check_response(response, label, expected_status, expected_error=None):
    if response.status_code != 200:
        raise TestFailure(f'{label}: unexpected HTTP status {response.status_code}')
    try:
        result = response.json()
    except ValueError:
        raise TestFailure(f'{label}: response is not JSON') from None
    if not isinstance(result, dict) or result.get('status') != expected_status:
        raise TestFailure(f'{label}: unexpected API status ({describe_result(result)})')
    if expected_error is not None and expected_error not in result.get('errors', []):
        raise TestFailure(f'{label}: expected rejection reason missing ({describe_result(result)})')
    print(f'PASS: {label}', flush=True)


def main():
    apikey = os.environ.get('NOTIFY_TEST_APIKEY', '')
    secret = os.environ.get('NOTIFY_TEST_APISECRET', '')
    if not apikey or not secret:
        raise TestFailure('Set NOTIFY_TEST_APIKEY and NOTIFY_TEST_APISECRET in Gitea Secrets')

    api = NotifyApi(apikey, secret, baseurl=URL)
    api.session.close()
    api.session = TimedSession()
    with api.session:
        # Deployment restarts the service; wait without retrying message delivery.
        for attempt in range(30):
            try:
                response = api.session.get(URL)
                if response.status_code == 200 and response.json() == {'status': 'ok'}:
                    break
            except (requests.RequestException, ValueError):
                pass
            if attempt == 29:
                raise TestFailure('Notify API did not become ready')
            time.sleep(2)

        run_id = os.environ.get('NOTIFY_TEST_RUN_ID', 'local')
        data = {'message': f'Notify CI integration test: {run_id}', 'plain': True}
        check_response(api.post('', data), 'three-part token delivery', 'ok')
        auth_headers = {name for name in api.session.headers if name.upper().startswith('X-ATYX-')}
        if auth_headers != {'X-ATYX-TOKEN'}:
            raise TestFailure('Client must send only X-ATYX-TOKEN for authentication')

        def send_rejected(label, timestamp, signed_data, sent_data, bad_signature=False, error='signature not valid'):
            signature = api._get_signature(timestamp, URL, 'post', api.get_contenthash(signed_data))
            if bad_signature:
                signature = ('0' if signature[0] != '0' else '1') + signature[1:]
            response = api.session.post(
                URL, json=sent_data,
                headers={'X-ATYX-TOKEN': f'{apikey}:{timestamp}:{signature}'},
            )
            check_response(response, label, 'error', error)

        send_rejected('invalid signature rejected', api.get_timestamp(), data, data, bad_signature=True)
        send_rejected('modified body rejected', api.get_timestamp(), data, {**data, 'message': 'tampered'})
        send_rejected('expired timestamp rejected', api.get_timestamp() - 60000, data, data, error='timestamp is too old')
        send_rejected('future timestamp rejected', api.get_timestamp() + 60000, data, data, error='timestamp is too old')


if __name__ == '__main__':
    try:
        main()
    except TestFailure as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        sys.exit(1)
    except requests.RequestException:
        # Do not print request details or authentication headers.
        print('FAIL: request to Notify API failed', file=sys.stderr)
        sys.exit(1)
