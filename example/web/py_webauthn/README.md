# Example for py\_webauthn

- [py\_webauthn](https://github.com/duo-labs/py_webauthn)
- [flask](https://flask.palletsprojects.com/en/stable/installation/)

```
python3 -m venv .venv
source .venv/bin/activate
pip install webauthn Flask duckdb uuid7
```

Initialize the database:
```
flask --app server init-db
```

Run server:
```
flask --app server run --debug
```

Begin registration:
```
curl --header "Content-Type: application/json" --request GET --data '{"username": "bob@zigtoberfest.de"}' http://localhost:5000/auth/register
```

Reset `register` table:
```
curl --request GET http://localhost:5000/auth/reset/register
```

## Zig Client

Register a new user
```
./zig-out/bin/py_webauthn_client --cmd register --url http://127.0.0.1:5000/auth/register/begin --username franzi
```
