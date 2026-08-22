"""
vulnerable_app.py

A tiny, INTENTIONALLY vulnerable local web app for testing sqli_scanner.py
against a guaranteed target. Uses only the Python standard library (no
extra installs needed).

It builds a SQL query by directly pasting user input into the query string
(the classic mistake) - so your scanner should find both an error-based
and a boolean-based SQL injection against it.

Run it:
    python3 vulnerable_app.py

Then in another terminal, scan it:
    python sqli_scanner.py "http://127.0.0.1:5000/user?username=admin"

WARNING: deliberately vulnerable. Only run this locally for testing your
own scanner - never expose it to a network beyond 127.0.0.1.
"""

import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

conn = sqlite3.connect(":memory:", check_same_thread=False)
cur = conn.cursor()
cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, secret TEXT)")
cur.execute("INSERT INTO users (username, secret) VALUES ('admin', 'TopSecretFlag123')")
conn.commit()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/user":
            self._respond(404, "Not found. Try /user?username=admin")
            return

        username = parse_qs(parsed.query).get("username", [""])[0]

        # VULNERABLE ON PURPOSE: raw string interpolation into SQL.
        query = f"SELECT id, username, secret FROM users WHERE username = '{username}'"

        try:
            cur.execute(query)
            rows = cur.fetchall()
        except sqlite3.OperationalError as exc:
            # Leaks the DB error back to the client - classic error-based hole.
            body = f"Database error: sqlite3.OperationalError: {exc}\nQuery: {query}"
            self._respond(500, body)
            return

        if rows:
            lines = [f"Found user: id={r[0]} username={r[1]} secret={r[2]}" for r in rows]
            body = "Results:\n" + "\n".join(lines)
        else:
            body = "No results found."

        self._respond(200, body)

    def _respond(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, format, *args):
        pass  # keep console output quiet


if __name__ == "__main__":
    port = 5000
    print(f"Vulnerable test app running at http://127.0.0.1:{port}/user?username=admin")
    print("Only accessible on localhost. Press Ctrl+C to stop.")
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
