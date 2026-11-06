"""Run the candidate against a disposable loopback-only PostgreSQL container."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import time


def docker(*args):
    result = subprocess.run(["docker", *args], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError("Cannot manage the disposable PostgreSQL fixture")
    return result.stdout.strip()


name = "hanko-go-session-test-" + secrets.token_hex(8)
started = False
try:
    url = os.environ.get("HANKO_TEST_DATABASE_URL")
    if not url:
        password = secrets.token_hex(32)
        docker("run", "-d", "--rm", "--name", name, "-p", "127.0.0.1::5432", "-e", "POSTGRES_DB=hanko_sessions", "-e", "POSTGRES_PASSWORD=" + password, "postgres:17-alpine")
        started = True
        ports = json.loads(docker("inspect", name, "--format", "{{json .NetworkSettings.Ports}}"))
        port = ports["5432/tcp"][0]["HostPort"]
        url = f"postgres://postgres:{password}@127.0.0.1:{port}/hanko_sessions"
        deadline = time.monotonic() + 30
        # Ignore the entrypoint's temporary Unix-socket-only initialization server.
        while subprocess.run(["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            if time.monotonic() >= deadline:
                raise RuntimeError("Disposable PostgreSQL did not become ready")
            time.sleep(0.1)
    result = subprocess.run(["go", "run", "."], cwd=Path(__file__).parent, env={**os.environ, "HANKO_TEST_DATABASE_URL": url})
    if result.returncode:
        raise SystemExit(result.returncode)
finally:
    if started:
        docker("rm", "-f", name)
