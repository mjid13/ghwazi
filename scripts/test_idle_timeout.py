import sys, os, time
# Ensure project root is on sys.path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from ghwazi.app import create_app

app = create_app()
client = app.test_client()

# Simulate an authenticated session that has been idle past the timeout
with client.session_transaction() as sess:
    sess['user_id'] = 1
    sess['username'] = 'testuser'
    sess['last_activity'] = time.time() - (app.config.get('SESSION_IDLE_TIMEOUT', 1800) + 10)

# Call an API endpoint to trigger before_request idle-timeout enforcement
resp = client.get('/api/get_chart_data', headers={'Accept': 'application/json'})
print('status_code=', resp.status_code)
try:
    print('json=', resp.get_json())
except Exception as e:
    print('json parsing error:', e)
