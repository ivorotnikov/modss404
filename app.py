# Окно: найти адрес Modss, до которого доходит роутер, и прописать его в DNS,
# чтобы телевизор не получал неоткрываемый адрес Cloudflare от AdGuard или 8.8.8.8.
# Вход: веб-панель Keenetic, Telnet или SSH. Пароль только в полях окна.

import hashlib
import http.cookiejar
import json
import queue
import random
import re
import socket
import subprocess
import threading
import time
import tkinter as tk
import urllib.error
import urllib.request
from tkinter import messagebox, ttk

try:
    import paramiko
except ImportError:
    paramiko = None


DEFAULT_NAMES = "modss.tv\napi.modss.tv\nlampa.stream"
PING_POLLS = 25
PING_PAUSE_SEC = 0.4
PROTOCOLS = (
    ("Telnet", "23"),
    ("SSH", "22"),
    ("Keenetic, веб-панель", "80"),
)
# Эти сети Cloudflare пингуются, но с части сетей на порты 80 и 443 не отвечают.
BLACKHOLE_PREFIXES = ("188.114.96.", "188.114.97.")
SHELL_PROMPT = r"(\(config\)>\s*$|\[[^\]\n]+\]\s*>\s*$|[#\$]\s*$)"
HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)


class FixError(Exception):
    pass


class PingResult:
    def __init__(self, host, ip, loss, text):
        self.host = host
        self.ip = ip
        self.loss = loss
        self.text = text

    @property
    def ok(self):
        return bool(self.ip) and self.loss == 0 and usable_pin(self.ip)


def usable_pin(ip):
    if not valid_ip(ip):
        return False
    if ip.startswith(("0.", "127.")):
        return False
    return not ip.startswith(BLACKHOLE_PREFIXES)


def valid_ip(ip):
    parts = str(ip).split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 and str(int(part)) == part for part in parts)
    except ValueError:
        return False


def valid_host(host):
    return bool(HOST_RE.match(host or ""))


def normalize_host(line):
    line = line.strip()
    line = re.sub(r"^https?://", "", line, flags=re.IGNORECASE)
    return line.split("/")[0].strip().strip(".")


def checked_host(host):
    host = normalize_host(host)
    if not valid_host(host):
        raise FixError(f"Имя «{host}» не похоже на адрес сайта. В строке не должно быть пробелов и команд.")
    return host


def parse_ping(host, lines):
    text = "\n".join(lines) if isinstance(lines, (list, tuple)) else str(lines)
    lowered = text.lower()
    ip_match = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)", text)
    loss_match = re.search(r"(\d+)% packet loss", text)
    ip = ip_match.group(1) if ip_match else None
    loss = int(loss_match.group(1)) if loss_match else None
    if any(phrase in lowered for phrase in (
        "failed to resolve",
        "network unreachable",
        "bad address",
        "unknown host",
        "not known",
        "does not exist",
        "no address",
    )):
        ip = None
        loss = 100
    if ip and not valid_ip(ip):
        ip = None
    return PingResult(host, ip, loss, text)


def parse_static_a(text):
    found = {}
    for match in re.finditer(r"static_a = (\S+) (\d{1,3}(?:\.\d{1,3}){3})", text):
        if valid_host(match.group(1)) and valid_ip(match.group(2)):
            found[match.group(1)] = match.group(2)
    return found


def parse_dnsmasq_addresses(text):
    found = {}
    for match in re.finditer(r"address=/([A-Za-z0-9.-]+)/(\d{1,3}(?:\.\d{1,3}){3})", text):
        if valid_host(match.group(1)) and valid_ip(match.group(2)):
            found[match.group(1)] = match.group(2)
    return found


def rewrite_dnsmasq_lines(text, updates, removals):
    kept = []
    for line in text.splitlines():
        match = re.match(r"\s*address=/([A-Za-z0-9.-]+)/", line.strip())
        if match and (match.group(1) in updates or match.group(1) in removals):
            continue
        if line.strip():
            kept.append(line.strip())
    for name, ip in updates.items():
        kept.append(f"address=/{name}/{ip}")
    return "\n".join(kept).strip()


def parse_uci_addresses(text):
    found = {}
    for match in re.finditer(
        r"(dhcp\.[^=\s]+)\.address=(.+)$",
        text,
        re.MULTILINE,
    ):
        key = match.group(1)
        for piece in re.findall(r"/([A-Za-z0-9.-]+)/(\d{1,3}(?:\.\d{1,3}){3})", match.group(2)):
            if valid_host(piece[0]) and valid_ip(piece[1]):
                found[piece[0]] = (key, piece[1])
    return found


def parse_mikrotik_static(text):
    found = {}
    for line in text.splitlines():
        name = re.search(r"name=\"?([A-Za-z0-9.-]+)\"?", line)
        ip = re.search(r"address=(\d{1,3}(?:\.\d{1,3}){3})", line)
        if name and ip and valid_host(name.group(1)) and valid_ip(ip.group(1)):
            found[name.group(1)] = ip.group(1)
    return found


def parse_resolve(text):
    if re.search(r"(?i)failure:|does not exist|no address|not found", text):
        return None
    for match in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3})", text):
        if valid_ip(match.group(1)) and not match.group(1).startswith("127."):
            return match.group(1)
    return None


def strip_ansi(text):
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)
    text = re.sub(r"\x1b\][^\x07]*\x07", "", text)
    return text.replace("\x00", "")


def lan_gateways():
    try:
        raw = subprocess.check_output(["route", "print", "-4"], encoding="oem", errors="replace")
    except (OSError, subprocess.CalledProcessError):
        return []
    found = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            gateway = parts[2]
            if gateway in ("On-link", "0.0.0.0") or gateway in found:
                continue
            found.append(gateway)
    return found


def split_target(host, port_text):
    host = re.sub(r"^https?://", "", host.strip(), flags=re.IGNORECASE).strip("/")
    if not host:
        raise FixError("Укажите адрес роутера.")
    if "/" in host or " " in host:
        raise FixError("В адресе роутера укажите только IP или имя, без пути.")
    if not port_text.strip():
        raise FixError("Укажите порт.")
    try:
        port = int(port_text.strip())
    except ValueError as exc:
        raise FixError("Порт должен быть числом.") from exc
    if port < 1 or port > 65535:
        raise FixError("Порт должен быть от 1 до 65535.")
    if ":" in host:
        raise FixError("Порт пишите в отдельном поле, не в адресе.")
    return host, port


def credential(value, title):
    if "\r" in value or "\n" in value:
        raise FixError(f"{title} не должен содержать перевод строки.")
    return value


class KeeneticWeb:
    def __init__(self, host, port, login, password, timeout=20):
        self.base = f"http://{host}" if port in (80, 0) else f"http://{host}:{port}"
        self.login_name = login.strip() or "admin"
        self.password = password
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def connect(self):
        try:
            status, headers, raw = self._open("GET", "/auth")
        except FixError:
            raise
        except Exception as exc:
            raise FixError("Нет связи с веб-панелью. Проверьте адрес и порт 80.") from exc
        if status != 401 and not headers.get("X-NDM-Challenge"):
            raise FixError("Это не веб-панель Keenetic. Для другого роутера выберите Telnet или SSH.")
        challenge = headers.get("X-NDM-Challenge") or ""
        realm = headers.get("X-NDM-Realm") or ""
        if not challenge or not realm:
            raise FixError("Роутер не выдал данные для входа.")
        digest = hashlib.md5(f"{self.login_name}:{realm}:{self.password}".encode("utf-8")).hexdigest()
        token = hashlib.sha256((challenge + digest).encode("utf-8")).hexdigest()
        status, headers, raw = self._open("POST", "/auth", {"login": self.login_name, "password": token})
        if status == 401:
            raise FixError("Неверный логин или пароль.")
        if status != 200:
            raise FixError(f"Роутер не пустил в панель, ответ {status}.")
        version = self._json("POST", "/rci/show/version", {})
        title = version.get("description") or version.get("model") or "Keenetic"
        release = version.get("title") or version.get("release") or ""
        return f"{title}, веб-панель, версия {release}".strip().rstrip(",")

    def ping(self, host):
        payload = self._tool("/rci/tools/ping", {"host": host, "count": 1})
        return parse_ping(host, payload)

    def static_map(self):
        data = self._json("POST", "/rci/show/dns-proxy", {})
        return parse_static_a(json.dumps(data))

    def set_host(self, domain, address):
        return self._status("/rci/ip/host", {"domain": domain, "address": address})

    def clear_host(self, domain):
        return self._status("/rci/ip/host", {"domain": domain, "no": True}, missing_ok=True)

    def flush(self):
        return ""

    def close(self):
        return None

    def _tool(self, path, data):
        body = self._json("POST", path, data)
        lines = list(body.get("message") or [])
        continued = bool(body.get("continued"))
        for _ in range(PING_POLLS):
            if not continued:
                break
            try:
                body = self._json("GET", path)
            except FixError:
                break
            lines.extend(body.get("message") or [])
            continued = bool(body.get("continued"))
            if continued:
                time.sleep(PING_PAUSE_SEC)
        return lines

    def _status(self, path, data, missing_ok=False):
        payload = self._json("POST", path, data)
        items = payload.get("status") or []
        messages = [item.get("message") or "" for item in items]
        text = "; ".join(message for message in messages if message)
        for item in items:
            if item.get("status") != "error":
                continue
            message = (item.get("message") or "").lower()
            if missing_ok and "no such record" in message:
                continue
            raise FixError(text or "Роутер отклонил команду.")
        return text

    def _json(self, method, path, data=None):
        status, headers, raw = self._open(method, path, data)
        if status == 401:
            raise FixError("Сессия роутера закончилась. Нажмите кнопку ещё раз.")
        if not raw.strip():
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise FixError("Роутер ответил не тем форматом, который ждёт программа.") from exc

    def _open(self, method, path, data=None):
        body = None
        headers = {}
        if data is not None:
            body = json.dumps(data).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=body, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                return response.status, dict(response.headers), response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            return exc.code, dict(exc.headers), raw
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            raise FixError("Роутер не отвечает. Проверьте адрес и что компьютер в его сети.") from exc


def consume_telnet(data, send):
    out = bytearray()
    index = 0
    while index < len(data):
        if data[index] != 255:
            out.append(data[index])
            index += 1
            continue
        if index + 1 >= len(data):
            return bytes(out), data[index:]
        command = data[index + 1]
        if command == 255:
            out.append(255)
            index += 2
            continue
        if command in (251, 252, 253, 254):
            if index + 2 >= len(data):
                return bytes(out), data[index:]
            option = data[index + 2]
            if command == 251 and option in (1, 3):
                send(bytes([255, 253, option]))
            elif command == 253 and option in (1, 3):
                send(bytes([255, 251, option]))
            elif command in (251, 252):
                send(bytes([255, 254, option]))
            else:
                send(bytes([255, 252, option]))
            index += 3
            continue
        if command == 250:
            end = data.find(bytes([255, 240]), index + 2)
            if end < 0:
                return bytes(out), data[index:]
            index = end + 2
            continue
        index += 2
    return bytes(out), b""


class ByteStream:
    def __init__(self, newline):
        self.newline = newline
        self.buf = ""
        self.closed = False

    def write(self, text):
        raise NotImplementedError

    def pump(self):
        raise NotImplementedError

    def close(self):
        raise NotImplementedError

    def _pull(self, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            chunk = self.pump()
            if chunk:
                self.buf = strip_ansi(self.buf + chunk).replace("\r", "")
                return True
            time.sleep(0.05)
        return False

    def read_until(self, pattern, timeout):
        deadline = time.time() + timeout
        compiled = re.compile(pattern)
        while time.time() < deadline:
            match = compiled.search(self.buf)
            if match:
                text = self.buf[:match.end()]
                self.buf = self.buf[match.end():]
                return text
            left = deadline - time.time()
            if left <= 0 or not self._pull(min(0.4, left)):
                continue
        raise FixError("Роутер не прислал ответ вовремя. Проверьте порт и тип входа.")

    def read_idle(self, timeout, idle=0.8, until=None):
        deadline = time.time() + timeout
        last = time.time()
        seen = False
        compiled = re.compile(until) if until else None
        while time.time() < deadline:
            if self._pull(min(0.3, max(0.05, deadline - time.time()))):
                seen = True
                last = time.time()
                continue
            if not seen or time.time() - last < idle:
                continue
            if compiled is None or compiled.search(self.buf):
                break
        text = self.buf
        self.buf = ""
        return text

    def write_line(self, line):
        self.write(line + self.newline)

    def sh(self, command, timeout=25):
        marker = f"MODSSEND{random.randint(100000, 999999)}"
        self.write_line(command)
        self.write_line(f"echo {marker}:$?")
        raw = self.read_until(re.escape(marker) + r":\d+", timeout)
        code_match = re.search(re.escape(marker) + r":(\d+)", raw)
        code = int(code_match.group(1)) if code_match else 1
        body = raw[:code_match.start()] if code_match else raw
        return body, code


class TelnetStream(ByteStream):
    def __init__(self, host, port, timeout=20):
        super().__init__("\r\n")
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.raw = b""

    def open(self):
        try:
            self.sock = socket.create_connection((self.host, self.port), self.timeout)
        except (OSError, TimeoutError) as exc:
            raise FixError(
                "Нет связи по Telnet. Проверьте адрес, порт и что служба Telnet на роутере включена."
            ) from exc
        self.sock.settimeout(0.4)
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

    def write(self, text):
        try:
            self.sock.sendall(text.encode("utf-8", "replace"))
        except OSError as exc:
            raise FixError("Связь с роутером оборвалась.") from exc

    def pump(self):
        try:
            data = self.sock.recv(4096)
        except socket.timeout:
            return ""
        except OSError as exc:
            raise FixError("Связь с роутером оборвалась.") from exc
        if not data:
            raise FixError("Роутер закрыл соединение.")
        self.raw += data
        text, self.raw = consume_telnet(self.raw, self.sock.sendall)
        return text.decode("utf-8", "replace")

    def close(self):
        if self.sock and not self.closed:
            self.closed = True
            try:
                self.sock.close()
            except OSError:
                pass


class SshStream(ByteStream):
    def __init__(self, host, port, login, password, timeout=20):
        super().__init__("\n")
        self.host = host
        self.port = port
        self.login = login
        self.password = password
        self.timeout = timeout
        self.client = None
        self.channel = None

    def open(self):
        if paramiko is None:
            raise FixError("Для SSH не хватает библиотеки paramiko. Возьмите готовый exe или установите её в Python.")
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.client.connect(
                self.host,
                port=self.port,
                username=self.login.strip() or "admin",
                password=self.password,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
            )
        except paramiko.AuthenticationException as exc:
            self.close()
            raise FixError("Неверный логин или пароль.") from exc
        except (paramiko.SSHException, OSError, TimeoutError) as exc:
            self.close()
            raise FixError("Нет связи по SSH. Проверьте адрес, порт 22 и что служба SSH включена.") from exc
        self.channel = self.client.invoke_shell(term="vt100", width=200, height=60)
        self.channel.settimeout(0.4)

    def write(self, text):
        try:
            self.channel.send(text)
        except OSError as exc:
            raise FixError("Связь с роутером оборвалась.") from exc

    def pump(self):
        chunks = []
        try:
            if self.channel.recv_ready():
                chunks.append(self.channel.recv(4096))
            if self.channel.recv_stderr_ready():
                chunks.append(self.channel.recv_stderr(4096))
        except socket.timeout:
            return ""
        except OSError as exc:
            raise FixError("Связь с роутером оборвалась.") from exc
        if not chunks:
            if self.channel.closed:
                raise FixError("Роутер закрыл SSH.")
            return ""
        return b"".join(chunks).decode("utf-8", "replace")

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            if self.channel:
                self.channel.close()
        except OSError:
            pass
        try:
            if self.client:
                self.client.close()
        except OSError:
            pass


class PromptDriver:
    prompt = r"\(config\)>"

    def __init__(self, stream):
        self.stream = stream

    def cmd(self, line, timeout=25):
        self.stream.write_line(line)
        text = self.stream.read_until(self.prompt, timeout)
        lowered = text.lower()
        if "no such command" in lowered or "argument parse error" in lowered or "syntax error" in lowered:
            raise FixError("Роутер не принял команду. Запись не изменена.")
        return text

    def close(self):
        self.stream.close()

    def flush(self):
        return ""


class KeeneticCli(PromptDriver):
    def label_from(self, banner):
        match = re.search(r"KeeneticOS version\s+(\S+)", banner)
        version = match.group(1).rstrip(",") if match else ""
        return f"Keenetic, командная строка, версия {version}".strip().rstrip(",")

    def ping(self, host):
        return parse_ping(host, self.cmd(f"tools ping {host} count 1", timeout=35))

    def static_map(self):
        return parse_static_a(self.cmd("show dns-proxy", timeout=25))

    def set_host(self, domain, address):
        if not valid_ip(address):
            raise FixError("Роутер вернул некорректный IP, запись не прописана.")
        return self.cmd(f"ip host {domain} {address}")

    def clear_host(self, domain):
        self.stream.write_line(f"no ip host {domain}")
        text = self.stream.read_until(self.prompt, 20)
        if "no such record" in text.lower():
            return ""
        if "error" in text.lower() and "cleared" not in text.lower():
            raise FixError("Роутер не снял DNS-запись.")
        return text


class MikroTikDriver(PromptDriver):
    prompt = r"\[[^\]\n]+\]\s*>"

    def label_from(self, banner):
        return "MikroTik, командная строка"

    def ping(self, host):
        text = self.cmd(f"/resolve {host}", timeout=25)
        ip = parse_resolve(text)
        return PingResult(host, ip, 0 if ip else 100, text)

    def static_map(self):
        return parse_mikrotik_static(self.cmd("/ip dns static print terse", timeout=25))

    def set_host(self, domain, address):
        if not valid_ip(address):
            raise FixError("Роутер вернул некорректный IP, запись не прописана.")
        self.clear_host(domain)
        return self.cmd(f'/ip dns static add name="{domain}" address={address}')

    def clear_host(self, domain):
        text = self.cmd(f'/ip dns static remove [find where name="{domain}"]')
        if re.search(r"(?i)no such item|nothing to remove|no matching", text):
            return ""
        return text


class UnixDriver:
    def __init__(self, stream, banner):
        self.stream = stream
        self.banner = banner
        self.pending = False

    def sh(self, command, timeout=25):
        body, code = self.stream.sh(command, timeout)
        return body, code

    def close(self):
        self.stream.close()

    def flush(self):
        return ""

    def ping(self, host):
        body, code = self.sh(f"ping -c 1 -W 3 {host}", timeout=20)
        result = parse_ping(host, body)
        if code != 0 and result.loss is None:
            result.loss = 100
        return result


class OpenWrtDriver(UnixDriver):
    def label_from(self):
        match = re.search(r"DISTRIB_DESCRIPTION=['\"]?([^'\"\n]+)", self.banner)
        if not match:
            match = re.search(r"DISTRIB_ID=['\"]?(\S+)", self.banner)
        title = match.group(1).strip() if match else "OpenWrt"
        return f"{title}, SSH/Telnet"

    def static_map(self):
        body, code = self.sh("uci show dhcp", timeout=20)
        if code != 0 and "dnsmasq" not in body:
            raise FixError("Не удалось прочитать DNS OpenWrt. Нужен вход под root.")
        if not re.search(r"dhcp\.@dnsmasq\[0\]=dnsmasq|dhcp\.\w+=dnsmasq", body):
            raise FixError("На OpenWrt нет dnsmasq в настройках DHCP. Записи не менял.")
        return {name: ip for name, (key, ip) in parse_uci_addresses(body).items()}

    def clear_host(self, domain):
        body, code = self.sh("uci show dhcp", timeout=20)
        if code != 0:
            raise FixError("Не удалось прочитать DNS OpenWrt.")
        commands = []
        for name, (key, ip) in parse_uci_addresses(body).items():
            if name == domain:
                commands.append(f"uci del_list '{key}.address=/{name}/{ip}'")
        if not commands:
            return ""
        script = " && ".join(commands)
        out, status = self.sh(script, timeout=20)
        if status != 0:
            raise FixError("OpenWrt не снял DNS-запись. Нужен вход под root.")
        self.pending = True
        return out

    def set_host(self, domain, address):
        if not valid_ip(address):
            raise FixError("Роутер вернул некорректный IP, запись не прописана.")
        self.clear_host(domain)
        out, status = self.sh(
            f"uci add_list 'dhcp.@dnsmasq[0].address=/{domain}/{address}'",
            timeout=20,
        )
        if status != 0:
            raise FixError("OpenWrt не принял DNS-запись.")
        self.pending = True
        return out

    def flush(self):
        if not self.pending:
            return ""
        out, status = self.sh("uci commit dhcp && /etc/init.d/dnsmasq reload", timeout=40)
        self.pending = False
        if status != 0:
            raise FixError("Запись сохранена, но OpenWrt не перечитал DNS. Повторите «Исправить».")
        return "OpenWrt перечитал DNS."


class DnsmasqFileDriver(UnixDriver):
    remote_path = ""
    reload_command = ""
    missing_message = "Роутер не дал записать DNS."

    def read_file(self):
        body, code = self.sh(f"cat {self.remote_path} 2>/dev/null || true")
        return body

    def static_map(self):
        return parse_dnsmasq_addresses(self.read_file())

    def write_file(self, updates, removals):
        current = self.read_file()
        # В выводе оболочки есть эхо команды. Берём только строки address= и чужие настройки.
        lines = []
        for line in current.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("cat ", "echo ", "printf ", "nvram ", "mkdir ")):
                continue
            if re.match(r"^(#|address=/|server=/|dhcp-option=|rebind-|bogus-|interface=|no-|cache-size=|local=/)", stripped):
                lines.append(stripped)
        rewritten = rewrite_dnsmasq_lines("\n".join(lines), updates, removals)
        if rewritten and "address=/" not in rewritten and not updates:
            rewritten = ""
        payload = rewritten.replace("'", "'\"'\"'")
        command = f"mkdir -p $(dirname {self.remote_path}) && printf '%s\\n' '{payload}' > {self.remote_path}"
        if not payload:
            command = f": > {self.remote_path}"
        out, status = self.sh(command, timeout=20)
        if status != 0:
            raise FixError(self.missing_message)
        self.pending = True
        return out

    def clear_host(self, domain):
        return self.write_file({}, {domain})

    def set_host(self, domain, address):
        if not valid_ip(address):
            raise FixError("Роутер вернул некорректный IP, запись не прописана.")
        return self.write_file({domain: address}, set())

    def flush(self):
        if not self.pending:
            return ""
        out, status = self.sh(self.reload_command, timeout=40)
        self.pending = False
        if status != 0:
            raise FixError("Файл DNS записан, но служба DNS не перечиталась.")
        return "Служба DNS перечитана."


class DdWrtDriver(UnixDriver):
    def label_from(self):
        return "DD-WRT, командная строка"

    def _options(self):
        body, code = self.sh("nvram get dnsmasq_options", timeout=15)
        if code != 0:
            raise FixError("DD-WRT не отдал настройки DNS. Нужен вход под root.")
        lines = []
        for line in body.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("nvram ") or stripped.startswith("echo "):
                continue
            lines.append(stripped)
        return "\n".join(lines)

    def static_map(self):
        return parse_dnsmasq_addresses(self._options())

    def _store(self, updates, removals):
        rewritten = rewrite_dnsmasq_lines(self._options(), updates, removals)
        payload = rewritten.replace("'", "'\"'\"'")
        out, status = self.sh(f"nvram set dnsmasq_options='{payload}'", timeout=20)
        if status != 0:
            raise FixError("DD-WRT не принял DNS-запись.")
        self.pending = True
        return out

    def clear_host(self, domain):
        return self._store({}, {domain})

    def set_host(self, domain, address):
        if not valid_ip(address):
            raise FixError("Роутер вернул некорректный IP, запись не прописана.")
        return self._store({domain: address}, set())

    def flush(self):
        if not self.pending:
            return ""
        out, status = self.sh("nvram commit && stopservice dnsmasq && startservice dnsmasq", timeout=40)
        self.pending = False
        if status != 0:
            raise FixError("Запись сохранена, но DD-WRT не перезапустил DNS.")
        return "DD-WRT перезапустил DNS."


class AsusDriver(DnsmasqFileDriver):
    remote_path = "/jffs/configs/dnsmasq.conf.add"
    reload_command = "service restart_dnsmasq"
    missing_message = "Asus не записал файл DNS. Нужны Asuswrt-Merlin, включённый JFFS и вход под admin."

    def label_from(self, product):
        return f"Asus {product}, командная строка".strip()

    def static_map(self):
        self._require_jffs()
        return super().static_map()

    def set_host(self, domain, address):
        self._require_jffs()
        return super().set_host(domain, address)

    def clear_host(self, domain):
        self._require_jffs()
        return super().clear_host(domain)

    def _require_jffs(self):
        body, code = self.sh("[ -d /jffs/configs ] || [ -d /jffs ] && echo JFFS_OK || echo JFFS_NO")
        if "JFFS_OK" not in body:
            raise FixError(
                "На Asus нет каталога /jffs. Нужна прошивка Asuswrt-Merlin с включённым JFFS. Записи не менял."
            )


class ShellClient:
    def __init__(self, stream, login, password, telnet_login):
        self.stream = stream
        self.login = login
        self.password = password
        self.telnet_login = telnet_login
        self.driver = None

    def connect(self):
        self.stream.open()
        try:
            banner = self._login()
            self.driver = self._identify(banner)
            if isinstance(self.driver, (OpenWrtDriver, DdWrtDriver)):
                return self.driver.label_from()
            if isinstance(self.driver, AsusDriver):
                return self.driver.label_from(getattr(self.driver, "product", ""))
            return self.driver.label_from(banner)
        except Exception:
            self.stream.close()
            raise

    def _login(self):
        if not self.telnet_login:
            return self.stream.read_idle(8, 0.6, SHELL_PROMPT)
        first = self.stream.read_until(r"(?i)(login|username)\s*:", 12)
        if first.lstrip().startswith("HTTP/"):
            raise FixError("На этом порту веб-страница, а не Telnet. Для Keenetic выберите веб-панель или укажите порт 23.")
        self.stream.write_line(self.login.strip() or "admin")
        self.stream.read_until(r"(?i)password\s*:", 8)
        self.stream.write_line(self.password)
        banner = first + "\n" + self.stream.read_idle(10, 0.6, SHELL_PROMPT)
        lowered = banner.lower()
        if any(phrase in lowered for phrase in ("login incorrect", "login failed", "authentication failed", "bad password", "access denied")):
            raise FixError("Неверный логин или пароль.")
        if re.search(r"(?i)(login|username)\s*:\s*$", banner):
            raise FixError("Неверный логин или пароль.")
        return banner

    def _identify(self, banner):
        if "KeeneticOS" in banner or "(config)>" in banner:
            return KeeneticCli(self.stream)
        if "MikroTik" in banner or re.search(r"\[[^\]\n]+@[^\]\n]+\]\s*>", banner):
            return MikroTikDriver(self.stream)
        try:
            probe, code = self.stream.sh(
                "printf '%s\\n' __A__; cat /etc/openwrt_release 2>/dev/null; printf '%s\\n' __B__; "
                "nvram get productid 2>/dev/null; printf '%s\\n' __C__; nvram get os_version 2>/dev/null; "
                "printf '%s\\n' __D__; nvram get buildinfo 2>/dev/null; printf '%s\\n' __E__",
                timeout=12,
            )
        except FixError:
            probe = ""
        blob = banner + "\n" + probe
        if "DISTRIB_ID" in blob or "OpenWrt" in blob:
            driver = OpenWrtDriver(self.stream, blob)
            return driver
        if "DD-WRT" in blob:
            return DdWrtDriver(self.stream, blob)
        product = ""
        parts = probe.split("__B__")
        if len(parts) > 1:
            product = parts[1].split("__C__")[0].strip().splitlines()
            product = next((line.strip() for line in product if line.strip() and not line.strip().startswith("nvram")), "")
        if re.match(r"^[A-Z]{2,4}-[A-Z0-9]+", product) or "merlin" in blob.lower() or "ASUSWRT" in blob:
            driver = AsusDriver(self.stream, blob)
            driver.product = product
            return driver
        sample = " ".join(banner.split())[:180]
        raise FixError(
            "Командная строка открылась, но роутер не опознан. Подходят Keenetic, OpenWrt, MikroTik, DD-WRT и Asus с Merlin. "
            "Записи не менял."
            + (f" Ответ роутера: {sample}" if sample else "")
        )

    def ping(self, host):
        return self.driver.ping(host)

    def static_map(self):
        return self.driver.static_map()

    def set_host(self, domain, address):
        return self.driver.set_host(domain, address)

    def clear_host(self, domain):
        return self.driver.clear_host(domain)

    def flush(self):
        return self.driver.flush()

    def close(self):
        self.stream.close()


def make_client(form):
    protocol = form["protocol"]
    login = credential(form["login"], "Логин")
    password = credential(form["password"], "Пароль")
    if protocol == "Keenetic, веб-панель":
        host, port = split_target(form["host"], form["port"] or "80")
        return KeeneticWeb(host, port, login, password)
    if protocol == "Telnet":
        host, port = split_target(form["host"], form["port"] or "23")
        return ShellClient(TelnetStream(host, port), login, password, True)
    if protocol == "SSH":
        host, port = split_target(form["host"], form["port"] or "22")
        return ShellClient(SshStream(host, port, login, password), login, password, False)
    raise FixError("Выберите способ входа: Telnet, SSH или веб-панель Keenetic.")


def names_from(text):
    hosts = []
    for line in text.splitlines():
        if not line.strip():
            continue
        host = checked_host(line)
        if host not in hosts:
            hosts.append(host)
    if not hosts:
        raise FixError("Впишите хотя бы одно имя, например modss.tv.")
    return hosts


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Modss на телевизоре")
        self.geometry("820x640")
        self.minsize(700, 520)
        self.queue = queue.Queue()
        self.worker = None
        self._build()
        self.after(150, self._drain)

    def _build(self):
        pad = {"padx": 10, "pady": 4}
        form = ttk.Frame(self)
        form.pack(fill="x", **pad)

        ttk.Label(form, text="Вход").grid(row=0, column=0, sticky="w")
        self.protocol = ttk.Combobox(form, values=[item[0] for item in PROTOCOLS], state="readonly", width=24)
        self.protocol.grid(row=1, column=0, sticky="we", padx=(0, 12))
        self.protocol.set(PROTOCOLS[0][0])
        self.protocol.bind("<<ComboboxSelected>>", self._on_protocol)

        ttk.Label(form, text="Адрес роутера").grid(row=0, column=1, sticky="w")
        self.host = ttk.Combobox(form, values=lan_gateways(), width=22)
        self.host.grid(row=1, column=1, sticky="we", padx=(0, 12))
        if self.host["values"]:
            self.host.set(self.host["values"][0])

        ttk.Label(form, text="Порт").grid(row=0, column=2, sticky="w")
        self.port = ttk.Entry(form, width=6)
        self.port.insert(0, PROTOCOLS[0][1])
        self.port.grid(row=1, column=2, sticky="w", padx=(0, 12))

        ttk.Label(form, text="Логин").grid(row=0, column=3, sticky="w")
        self.login = ttk.Entry(form, width=14)
        self.login.insert(0, "admin")
        self.login.grid(row=1, column=3, sticky="we", padx=(0, 12))

        ttk.Label(form, text="Пароль").grid(row=0, column=4, sticky="w")
        self.password = ttk.Entry(form, show="*", width=18)
        self.password.grid(row=1, column=4, sticky="we")

        form.columnconfigure(1, weight=1)
        form.columnconfigure(4, weight=1)

        ttk.Label(self, text="Имена, по одному в строке. Можно добавить своё. Для OpenWrt логин обычно root.").pack(anchor="w", padx=10, pady=(6, 0))
        self.names = tk.Text(self, height=5, wrap="none")
        self.names.pack(fill="x", padx=10, pady=4)
        self.names.insert("1.0", DEFAULT_NAMES)

        buttons = ttk.Frame(self)
        buttons.pack(fill="x", padx=10, pady=6)
        self.check_btn = ttk.Button(buttons, text="Проверить", command=lambda: self._start(self._check))
        self.fix_btn = ttk.Button(buttons, text="Исправить", command=lambda: self._start(
            self._fix,
            ("Исправить DNS", "Программа войдёт на роутер, снимет старые записи этих имён и пропишет адреса, которые найдёт сам роутер. Продолжить?"),
        ))
        self.clear_btn = ttk.Button(buttons, text="Удалить записи", command=lambda: self._start(
            self._clear,
            ("Удалить записи", "Удалить DNS-записи этих имён с роутера?"),
        ))
        self.check_btn.pack(side="left", padx=(0, 8))
        self.fix_btn.pack(side="left", padx=(0, 8))
        self.clear_btn.pack(side="left")

        hint = (
            "Программа сама смотрит, какой это роутер, и пишет DNS его командами. "
            "Пароль остаётся только в этом окне. После «Исправить» на телевизоре забудьте Wi-Fi, "
            "подключитесь снова и откройте http://modss.tv."
        )
        ttk.Label(self, text=hint, wraplength=780, justify="left").pack(anchor="w", padx=10, pady=(0, 6))

        self.log = tk.Text(self, height=16, state="disabled", wrap="word")
        self.log.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _on_protocol(self, _event):
        current = self.port.get().strip()
        if current in {item[1] for item in PROTOCOLS} or not current:
            for name, port in PROTOCOLS:
                if name == self.protocol.get():
                    self.port.delete(0, "end")
                    self.port.insert(0, port)

    def _snapshot(self):
        return {
            "protocol": self.protocol.get(),
            "host": self.host.get(),
            "port": self.port.get(),
            "login": self.login.get(),
            "password": self.password.get(),
            "names": self.names.get("1.0", "end"),
        }

    def _start(self, job, confirm=None):
        if self.worker and self.worker.is_alive():
            return
        if confirm and not messagebox.askyesno(confirm[0], confirm[1]):
            return
        form = self._snapshot()
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")
        self._set_busy(True)
        self.worker = threading.Thread(target=self._guard, args=(job, form), daemon=True)
        self.worker.start()

    def _guard(self, job, form):
        try:
            job(form)
        except FixError as exc:
            self.queue.put(("log", str(exc)))
        except Exception as exc:
            self.queue.put(("log", f"Сбой программы: {exc}"))
        finally:
            self.queue.put(("busy", False))

    def _run(self, form, job):
        client = make_client(form)
        where = form["protocol"]
        self.queue.put(("log", f"Подключаюсь, способ: {where}..."))
        try:
            self.queue.put(("log", client.connect()))
            job(client, names_from(form["names"]))
        finally:
            client.close()

    def _check(self, form):
        def job(client, hosts):
            current = client.static_map()
            for host in hosts:
                pinned = current.get(host)
                if pinned:
                    self.queue.put(("log", f"{host}: сейчас прописан адрес {pinned}"))
                self._report_ping(client.ping(host))
        self._run(form, job)

    def _fix(self, form):
        def job(client, hosts):
            current = client.static_map()
            previous = {}
            for host in hosts:
                previous[host] = current.get(host)
                if previous[host]:
                    self.queue.put(("log", f"{host}: снимаю прежнюю запись {previous[host]}"))
                    client.clear_host(host)
            flushed = client.flush()
            if flushed:
                self.queue.put(("log", flushed))
            fixed = []
            for host in hosts:
                self.queue.put(("log", f"{host}: ищу адрес через роутер..."))
                try:
                    result = client.ping(host)
                except FixError as exc:
                    self.queue.put(("log", str(exc)))
                    result = None
                if result:
                    self._report_ping(result)
                if result and result.ok:
                    message = client.set_host(host, result.ip)
                    if message:
                        self.queue.put(("log", " ".join(message.split())))
                    self.queue.put(("log", f"{host}: прописан {result.ip}"))
                    fixed.append(host)
                    continue
                if result and result.ip and result.ip.startswith(BLACKHOLE_PREFIXES):
                    self.queue.put((
                        "log",
                        f"{host}: адрес {result.ip} с телевизора обычно не открывается. Оставил как было.",
                    ))
                if previous[host]:
                    client.set_host(host, previous[host])
                    self.queue.put(("log", f"{host}: вернул прежнюю запись {previous[host]}"))
                else:
                    self.queue.put(("log", f"{host}: запись не прописана"))
            flushed = client.flush()
            if flushed:
                self.queue.put(("log", flushed))
            if fixed:
                self.queue.put((
                    "log",
                    "Готово. На телевизоре забудьте сеть Wi-Fi, подключитесь заново и откройте http://modss.tv",
                ))
        self._run(form, job)

    def _clear(self, form):
        def job(client, hosts):
            for host in hosts:
                message = client.clear_host(host)
                self.queue.put(("log", " ".join(message.split()) if message else f"{host}: записи нет"))
            flushed = client.flush()
            if flushed:
                self.queue.put(("log", flushed))
        self._run(form, job)

    def _report_ping(self, result):
        if result.ip and result.ip.startswith(BLACKHOLE_PREFIXES):
            self.queue.put(("log", f"{result.host}: роутер нашёл {result.ip}. Этот адрес телевизор обычно не открывает."))
            return
        if result.ok:
            self.queue.put(("log", f"{result.host}: роутер доходит до {result.ip}"))
            return
        if result.ip:
            self.queue.put(("log", f"{result.host}: адрес {result.ip}, потерь {result.loss}%"))
            return
        self.queue.put(("log", f"{result.host}: роутер не нашёл рабочий адрес"))

    def _set_busy(self, busy):
        state = "disabled" if busy else "normal"
        for button in (self.check_btn, self.fix_btn, self.clear_btn):
            button.configure(state=state)

    def _drain(self):
        while True:
            try:
                kind, payload = self.queue.get_nowait()
            except queue.Empty:
                break
            if kind == "log":
                self.log.configure(state="normal")
                self.log.insert("end", payload + "\n")
                self.log.see("end")
                self.log.configure(state="disabled")
            elif kind == "busy":
                self._set_busy(payload)
        self.after(150, self._drain)


def self_test():
    sample = """
PING ya.ru (5.255.255.242) 56 (84) bytes of data.
1 packets transmitted, 1 packets received, 0% packet loss,
"""
    result = parse_ping("ya.ru", sample)
    assert result.ok and result.ip == "5.255.255.242", result.ip
    blocked = parse_ping("modss.tv", "PING modss.tv (188.114.96.3) 56 bytes\n1 packets transmitted, 1 packets received, 0% packet loss")
    assert blocked.ip == "188.114.96.3" and not blocked.ok
    assert parse_static_a("static_a = modss.tv 104.21.71.62 0")["modss.tv"] == "104.21.71.62"
    uci = "dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].address='/modss.tv/104.21.71.62' '/api.modss.tv/172.67.169.254'\n"
    parsed = parse_uci_addresses(uci)
    assert parsed["modss.tv"][1] == "104.21.71.62", parsed
    assert parsed["api.modss.tv"][0] == "dhcp.@dnsmasq[0]"
    mikro = '0 name="modss.tv" address=104.21.71.62 ttl=5m\n1 address=172.67.169.254 name=api.modss.tv\n'
    assert parse_mikrotik_static(mikro)["api.modss.tv"] == "172.67.169.254"
    assert parse_resolve("failure: dns name does not exist") is None
    assert parse_resolve("address: 172.67.173.114") == "172.67.173.114"
    rewritten = rewrite_dnsmasq_lines("cache=100\naddress=/modss.tv/1.1.1.1\naddress=/ya.ru/5.5.5.5", {"modss.tv": "9.9.9.9"}, set())
    assert "address=/modss.tv/9.9.9.9" in rewritten and "address=/ya.ru/5.5.5.5" in rewritten
    assert "1.1.1.1" not in rewritten
    try:
        checked_host("modss.tv; reboot")
        raise AssertionError("command must be rejected")
    except FixError:
        pass
    assert strip_ansi("\x1b[K(config)> ") == "(config)> "
    text, left = consume_telnet(bytes([255, 251, 1, 65]), lambda data: None)
    assert text == b"A" and left == b""
    print("self_test ok")


if __name__ == "__main__":
    App().mainloop()
