import json
from pathlib import Path
import tempfile

from dashboard import Dashboard


def make_dashboard(tmp_path):
    config_path = tmp_path / 'config.json'
    db_path = tmp_path / 'honeypot_test.db'
    config = {
        'db_path': str(db_path)
    }
    config_path.write_text(json.dumps(config))
    dashboard = Dashboard(config_file=str(config_path), port=5001)
    return dashboard


def test_subscribe_and_list(tmp_path):
    dashboard = make_dashboard(tmp_path)
    client = dashboard.app.test_client()

    response = client.post('/api/subscribe-email', json={'email': 'user@example.com'})
    assert response.status_code == 200
    body = response.get_json()
    assert body['status'] == 'subscribed'
    assert body['email'] == 'user@example.com'

    response = client.get('/api/subscriptions')
    assert response.status_code == 200
    body = response.get_json()
    assert 'subscriptions' in body
    assert len(body['subscriptions']) == 1
    assert body['subscriptions'][0]['email'] == 'user@example.com'


def test_unsubscribe(tmp_path):
    dashboard = make_dashboard(tmp_path)
    client = dashboard.app.test_client()

    client.post('/api/subscribe-email', json={'email': 'user2@example.com'})
    response = client.post('/api/unsubscribe', json={'email': 'user2@example.com'})

    assert response.status_code == 200
    body = response.get_json()
    assert body['status'] == 'unsubscribed'
    assert body['email'] == 'user2@example.com'

    response = client.get('/api/subscriptions')
    assert response.status_code == 200
    body = response.get_json()
    assert body['subscriptions'] == []
