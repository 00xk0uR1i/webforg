"""Hollywood hacking theme for WebForge CLI — animated splash, ASCII art, progress bars."""

from __future__ import annotations

import os
import sys
import time
import random
import threading
from typing import Optional

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.text import Text
from rich.progress import (
    Progress, BarColumn, TextColumn, SpinnerColumn,
    TimeElapsedColumn, MofNCompleteColumn,
)
from rich.live import Live
from rich.table import Table
from rich.columns import Columns
from rich.align import Align
from rich import box

console = Console()

# ── Color palette ──────────────────────────────────────────────────────
MATRIX_GREEN  = "bold green"
CYBER_CYAN    = "bold cyan"
NEON_RED      = "bold red"
WARN_YELLOW   = "bold yellow"
DIM_GREEN     = "dim green"
DIM_WHITE     = "dim white"
BOLD_WHITE    = "bold white"
BOLD_MAGENTA  = "bold magenta"


# ── ASCII Art Logo ─────────────────────────────────────────────────────
SKULL_LOGO = r"""__________________________________________________________________________
Skull cross section
  __________________________________________________________________________
            ___           _,.---,---.,_
            |         ,;~'             '~;,
            |       ,;                     ;,
   Frontal  |      ;                         ; ,--- Supraorbital Foramen
    Bone    |     ,'                         /'
            |    ,;                        /' ;,
            |    ; ;      .           . <-'  ; |
            |__  | ;   ______       ______   ;<----- Coronal Suture
           ___   |  '/~"     ~" . "~     "~\'  |
           |     |  ~  ,-~~~^~, | ,~^~~~-,  ~  |
 Maxilla,  |      |   |        }:{        | <------ Orbit
Nasal and  |      |   l       / | \       !   |
Zygomatic  |      .~  (__,.--" .^. "--.,__)  ~.
  Bones    |      |    ----;' / | \ `;-<--------- Infraorbital Foramen
           |__     \__.       \/^\/       .__/
              ___   V| \                 / |V <--- Mastoid Process
              |      | |T~\___!___!___/~T| |
              |      | |`IIII_I_I_I_IIII'| |
     Mandible |      |  \,III I I I III,/  |
              |       \   `~~~~~~~~~~'    /
              |         \   .       . <-x---- Mental Foramen
              |__         \.    ^    ./
                            ^~~~^~~~^
  __________________________________________________________________________
Skull Punk
  __________________________________________________________________________"""

SKULL_LOGO_SMALL = SKULL_LOGO

WEBFORG_LOGO = SKULL_LOGO

WEBFORG_LOGO_SMALL = SKULL_LOGO_SMALL

CREATOR_BANNER = r"""
    +-------------------------------------------+
    |                                           |
    |     ##   ##  ######  ####   ##   ##  ##   |
    |     ###  ##  ##      ## ##  ##   ##  ##   |
    |     ## # ##  ####    ## ##  ##   ##  ##   |
    |     ##  ###  ##      ## ##  ##   ##       |
    |     ##   ##  ######  ####    #####   ##   |
    |                                           |
    |            Created by K0uR1i             |
    |            github.com/K0uR1i             |
    +-------------------------------------------+
"""


# ── Matrix rain characters ─────────────────────────────────────────────
MATRIX_CHARS = "01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン"


# ── Animation helpers ──────────────────────────────────────────────────
def _sleep(seconds: float):
    """Sleep that respects NO_COLOR / CI."""
    if os.environ.get("NO_COLOR") or os.environ.get("CI"):
        return
    time.sleep(seconds)


def typewrite(text: str, delay: float = 0.03, color: str = MATRIX_GREEN):
    """Typewriter effect -- prints one character at a time using Rich Live for clean overwrites."""
    if os.environ.get("NO_COLOR") or os.environ.get("CI"):
        console.print(f"[{color}]{text}[/]")
        return
    displayed = ""
    with Live(console=console, refresh_per_second=30, transient=True) as live:
        for ch in text:
            displayed += ch
            live.update(Text.from_markup(f"[{color}]{displayed}[/]"))
            time.sleep(delay)
    console.print(f"[{color}]{text}[/]")


def glitch_text(text: str, iterations: int = 3, delay: float = 0.05):
    """Glitch animation using Rich Live for proper line overwriting."""
    if os.environ.get("NO_COLOR") or os.environ.get("CI"):
        console.print(f"[bold cyan]{text}[/]")
        return
    glitch_chars = "█▓▒░@#$%&*!?<>{}[]"
    original = text
    with Live(console=console, refresh_per_second=30, transient=True) as live:
        for _ in range(iterations):
            glitched = ""
            for ch in original:
                if ch == " ":
                    glitched += ch
                elif random.random() < 0.3:
                    glitched += random.choice(glitch_chars)
                else:
                    glitched += ch
            live.update(Text.from_markup(f"[bold cyan]{escape(glitched)}[/]"))
            time.sleep(delay)
    console.print(f"[bold cyan]{original}[/]")


def scanline_effect(width: int = 60, lines: int = 5):
    """Fake scanline effect."""
    if os.environ.get("NO_COLOR") or os.environ.get("CI"):
        return
    for _ in range(lines):
        console.print(f"[dim green]{'─' * width}[/]")
        time.sleep(0.02)


def random_hex(length: int = 16) -> str:
    """Generate random hex string for dramatic effect."""
    return "".join(random.choices("0123456789abcdef", k=length))


def fake_shell_output(lines: int = 8, delay: float = 0.04):
    """Print fake shell output for atmosphere."""
    if os.environ.get("NO_COLOR") or os.environ.get("CI"):
        return
    fake_lines = [
        "[dim green]$ nmap -sV -sC target.com[/]",
        "[dim green]$ nikto -h target.com[/]",
        "[dim green]$ sqlmap -u 'http://target.com/?id=1' --dbs[/]",
        "[dim green]$ nuclei -t cves/ -u target.com[/]",
        "[dim green]$ curl -s http://target.com/robots.txt[/]",
        "[dim green]$ whatweb http://target.com[/]",
        "[dim green]$ ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target.com/FUZZ[/]",
        "[dim green]$ hydra -l admin -P wordlist.txt target.com ssh[/]",
    ]
    for line in fake_lines[:lines]:
        console.print(line)
        time.sleep(delay)


def matrix_rain(lines: int = 6, width: int = 50, delay: float = 0.03):
    """Brief Matrix-style rain effect."""
    if os.environ.get("NO_COLOR") or os.environ.get("CI"):
        return
    with Live(console=console, refresh_per_second=20, transient=True) as live:
        grid = [[" " for _ in range(width)] for _ in range(lines)]
        for frame in range(lines * 3):
            # Shift down
            for row in range(lines - 1, 0, -1):
                grid[row] = grid[row - 1][:]
            # New top row
            grid[0] = [random.choice(MATRIX_CHARS + " ") for _ in range(width)]
            # Randomly brighten one column
            col = random.randint(0, width - 1)
            display = ""
            for row in range(lines):
                line = ""
                for c in range(width):
                    ch = grid[row][c]
                    if c == col and row < lines - 1:
                        line += f"[bold white]{ch}[/]"
                    else:
                        line += f"[dim green]{ch}[/]"
                display += line + "\n"
            live.update(Text.from_markup(display))
            time.sleep(delay)


def animated_skull_reveal():
    """Animated skull logo with scanline sweep, glitch interference, and pulse."""
    logo_lines = SKULL_LOGO.strip().split("\n")
    total = len(logo_lines)

    glitch_chars = "█▓▒░@#$%&*!?<>{}[]|/\\~`"
    green = "\033[1;32m"
    dim = "\033[2;32m"
    cyan = "\033[1;36m"
    white = "\033[1;37m"
    reset = "\033[0m"

    def render_frame(reveal_up_to: int, scanline_at: int = -1, glitch_rows: set = None):
        """Build a single frame of the skull animation."""
        glitch_rows = glitch_rows or set()
        output = []
        for i, line in enumerate(logo_lines):
            if i > reveal_up_to:
                output.append("")
                continue
            if i in glitch_rows:
                # Glitch this line: randomly replace chars
                glitched = ""
                for ch in line:
                    if ch == " ":
                        glitched += ch
                    elif random.random() < 0.4:
                        glitched += random.choice(glitch_chars)
                    else:
                        glitched += ch
                output.append(f"{cyan}{glitched}{reset}")
            elif i == scanline_at:
                # Scanline: highlight this row
                output.append(f"{white}{line}{reset}")
            elif i < scanline_at or scanline_at == -1:
                output.append(f"{green}{line}{reset}")
            else:
                output.append(f"{dim}{line}{reset}")
        return "\n".join(output)

    # ── Phase A: Rapid line-by-line reveal with scanline ──
    with Live(console=console, refresh_per_second=60, transient=True) as live:
        for reveal in range(total):
            # Scanline at current reveal position
            live.update(Text.from_markup(render_frame(reveal, scanline_at=reveal)))
            time.sleep(0.025)

        # ── Phase B: Glitch interference passes ──
        for _ in range(3):
            num_glitch = random.randint(3, 6)
            glitch_rows = set(random.sample(range(total), min(num_glitch, total)))
            live.update(Text.from_markup(render_frame(total - 1, glitch_rows=glitch_rows)))
            time.sleep(0.06)

        # ── Phase C: Full glitch burst ──
        for _ in range(2):
            glitch_rows = set(range(total))
            live.update(Text.from_markup(render_frame(total - 1, glitch_rows=glitch_rows)))
            time.sleep(0.05)

        # ── Phase D: Clean resolve ──
        live.update(Text.from_markup(render_frame(total - 1)))
        time.sleep(0.15)

    # ── Final static render via Rich ──
    for line in logo_lines:
        console.print(f"[bold green]{line}[/]")


# ── Progress bar helpers ───────────────────────────────────────────────
def make_progress(**kwargs) -> Progress:
    """Create a themed progress bar."""
    return Progress(
        SpinnerColumn(style=MATRIX_GREEN),
        TextColumn("[bold green]{task.description}[/]", justify="right"),
        BarColumn(bar_width=40, style=MATRIX_GREEN, complete_style="bold cyan"),
        MofNCompleteColumn(),
        TextColumn("•"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    )


def themed_progress_bar(description: str, total: int = 100, duration: float = 2.0):
    """Animated progress bar with Hollywood feel."""
    with make_progress() as progress:
        task = progress.add_task(description, total=total)
        step = total / (duration / 0.03)
        while not progress.finished:
            progress.advance(task, advance=min(step, total - progress.tasks[task].completed))
            time.sleep(0.03)
    return True


# ── Boot Sequence ──────────────────────────────────────────────────────
def boot_sequence():
    """Full Hollywood-style boot animation with skull logo."""
    if os.environ.get("NO_COLOR") or os.environ.get("CI"):
        console.print(f"[{MATRIX_GREEN}]WebForge v0.1.0 -- Created by K0uR1i[/]")
        return

    os.system("clear" if os.name != "nt" else "cls")

    # Phase 1: Matrix rain before logo
    matrix_rain(lines=4, width=60, delay=0.02)
    console.print()

    # Phase 2: Animated skull reveal (scanline + glitch + pulse)
    animated_skull_reveal()
    console.print()

    # Phase 3: Title with glitch
    glitch_text("  >> WEBFORG v0.1.0 <<", iterations=5, delay=0.04)
    console.print()

    # Phase 4: Creator banner
    glitch_text("  Created by K0uR1i", iterations=4, delay=0.04)
    console.print()

    # Phase 5: Matrix rain transition
    matrix_rain(lines=3, width=60, delay=0.02)
    console.print()

    # Phase 6: Boot messages with typing effect
    boot_messages = [
        (f"  [dim green]>[/] Initializing exploit framework core...", 0.25),
        (f"  [dim green]>[/] Loading {random.randint(30, 40)} modules...", 0.3),
        (f"  [dim green]>[/] Syncing CVE database [dim](NVD + CISA KEV + Sploitus)[/]...", 0.4),
        (f"  [dim green]>[/] Calibrating payload generators...", 0.15),
        (f"  [dim green]>[/] Establishing encrypted command channels...", 0.2),
        (f"  [dim green]>[/] Bypassing IDS/IPS signatures...", 0.15),
        (f"  [dim green]>[/] Loading OWASP Top 10 exploitation guides...", 0.15),
        (f"  [dim green]>[/] Weaponizing attack vectors...", 0.1),
        (f"  [dim green]>[/] Initializing session persistence engine...", 0.15),
    ]

    for msg, delay in boot_messages:
        console.print(msg)
        time.sleep(delay)

    console.print()
    scanline_effect(width=70, lines=3)
    console.print()

    # Phase 7: Animated progress bar -- "Establishing secure connection"
    with make_progress() as progress:
        task = progress.add_task("[bold green]Establishing secure channel", total=100)
        while not progress.finished:
            remaining = 100 - progress.tasks[task].completed
            progress.advance(task, advance=min(random.randint(2, 8), remaining))
            time.sleep(0.04)

    console.print()

    # Phase 8: SYSTEM READY with glitch
    glitch_text("  >> SYSTEM READY <<", iterations=3, delay=0.04)
    console.print()

    # Phase 9: Status panel
    status_table = Table(show_header=False, box=box.ROUNDED, border_style=MATRIX_GREEN, padding=(0, 2))
    status_table.add_column("Key", style="bold cyan", width=20)
    status_table.add_column("Value", style="green")
    status_table.add_row("Framework", f"WebForge v0.1.0")
    status_table.add_row("Author", "K0uR1i")
    status_table.add_row("Modules", f"{random.randint(30, 40)} loaded")
    status_table.add_row("CVE DB", f"{random.randint(5000, 8000)} entries")
    status_table.add_row("Sploitus", "Connected")
    status_table.add_row("OWASP Top 10", "Full exploitation guides loaded")
    status_table.add_row("Status", "[bold green]OPERATIONAL[/]")
    status_table.add_row("Session ID", f"[dim]{random_hex(8)}[/]")

    console.print(Panel(
        Align.center(status_table),
        title=f"[bold green]=== SYSTEM STATUS ===[/]",
        subtitle=f"[dim green]=== {random_hex(16).upper()} ===[/]",
        border_style=MATRIX_GREEN,
        padding=(1, 2),
    ))

    console.print()
    typewrite("  Type 'help' for commands. Type 'show modules' to begin.", delay=0.02, color=DIM_GREEN)
    console.print()
    scanline_effect(width=70, lines=2)
    console.print()


# ── Themed module actions ──────────────────────────────────────────────
def themed_check(url: str):
    """Animated check with progress bar."""
    console.print(f"  [bold cyan]>[/] Probing target [bold]{url}[/]...")
    with make_progress() as progress:
        task = progress.add_task("[bold green]Running vulnerability checks", total=100)
        while not progress.finished:
            remaining = 100 - progress.tasks[task].completed
            progress.advance(task, advance=min(random.randint(3, 12), remaining))
            time.sleep(0.03)
    console.print(f"  [dim green]>[/] Scan complete. Analyzing response signatures...")
    console.print()


def themed_exploit(url: str):
    """Animated exploit execution with dramatic output."""
    console.print(f"  [bold red]>[/] Targeting [bold]{url}[/]")
    console.print()

    phases = [
        ("  [bold green]>[/] Phase 1: Reconnaissance & target profiling", 0.3),
        ("  [bold green]>[/] Phase 2: Crafting exploit payload", 0.2),
        ("  [bold green]>[/] Phase 3: Encoding payloads [dim](bypass WAF/IDS)[/]", 0.2),
        ("  [bold green]>[/] Phase 4: Sending exploit...", 0.3),
    ]

    for msg, delay in phases:
        console.print(msg)
        time.sleep(delay)

    console.print()
    with make_progress() as progress:
        task = progress.add_task("[bold red]Exploiting", total=100)
        while not progress.finished:
            remaining = 100 - progress.tasks[task].completed
            progress.advance(task, advance=min(random.randint(2, 10), remaining))
            time.sleep(0.03)

    console.print()


def themed_fingerprint(url: str):
    """Animated fingerprint scan."""
    console.print(f"  [bold cyan]>[/] Fingerprinting [bold]{url}[/]...")
    console.print()
    with make_progress() as progress:
        task = progress.add_task("[bold cyan]Enumerating technologies", total=100)
        while not progress.finished:
            remaining = 100 - progress.tasks[task].completed
            progress.advance(task, advance=min(random.randint(3, 15), remaining))
            time.sleep(0.03)
    console.print(f"  [dim green]>[/] Signature database: 1,200+ technologies loaded")
    console.print()


def themed_update_header(source: str):
    """Animated update header."""
    console.print()
    glitch_text(f"  >> DATABASE UPDATE: {source}", iterations=4, delay=0.03)
    console.print()
    with make_progress() as progress:
        task = progress.add_task(f"[bold green]Fetching {source}", total=100)
        while not progress.finished:
            remaining = 100 - progress.tasks[task].completed
            progress.advance(task, advance=min(random.randint(1, 6), remaining))
            time.sleep(0.03)
    console.print()


def themed_search_results(query: str, count: int):
    """Animated search results header."""
    console.print()
    console.print(f"  [bold cyan]>[/] Searching exploit database for '[bold]{query}[/]'...")
    with make_progress() as progress:
        task = progress.add_task("[bold green]Querying", total=30)
        while not progress.finished:
            remaining = 30 - progress.tasks[task].completed
            progress.advance(task, advance=min(random.randint(1, 5), remaining))
            time.sleep(0.02)
    console.print(f"  [dim green]>[/] Found [bold]{count}[/] matching exploits")
    console.print()


# ── Themed message helpers ─────────────────────────────────────────────
def success_msg(msg: str):
    console.print(f"  [bold green][OK] {msg}[/]")

def error_msg(msg: str):
    console.print(f"  [bold red][FAIL] {msg}[/]")

def warning_msg(msg: str):
    console.print(f"  [bold yellow][!] {msg}[/]")

def info_msg(msg: str):
    console.print(f"  [bold cyan][*] {msg}[/]")

def loading_msg(msg: str):
    console.print(f"  [dim green]>{msg}[/]")

def divider(color: str = MATRIX_GREEN, width: int = 60):
    console.print(f"  [{color}]{'=' * width}[/]")
