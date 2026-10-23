import secrets
print('ADMIN_PASSWORD=' + secrets.token_urlsafe(24))
print('SESSION_SECRET=' + secrets.token_urlsafe(48))
print('INGEST_API_KEY=' + secrets.token_urlsafe(40))
