import argparse
import asyncio
import os
import re
import sys
import time
import traceback
from dataclasses import dataclass

import requests
import telnetlib3

HOST = "192.168.1.1"
PORT = 23
USERNAME = "user"
CONFIG_PATH = "/config/workb/backup_lastgood.xml"
ENABLE_TELNET_URL = "http://192.168.1.1/boaform/set_telnet_enabled_url.cgi"

LOGIN_PROMPTS = (b"login: ", b"Login: ", b"Username: ", b"username: ")
PASSWORD_PROMPTS = (b"Password:", b"password:")
SHELL_PROMPTS = (b"$ ", b"# ", b"> ")
LOGIN_FAILURES = ("login incorrect", "登录失败")

SUPER_USER_RE = re.compile(r'aucTeleAccountName"\s+Value="([^"]+)"')
SUPER_PASS_RE = re.compile(r'aucTeleAccountPassword"\s+Value="([^"]+)"')
PPPOE_USER_RE = re.compile(r'aucUsername"\s+Value="([^"]+@[^"]+)"')

PPPOE_RE = re.compile(
    r'aucUsername"\s+Value="([^"]+@[^"]+)"[^\n]*\n[^\n]*'
    r'aucPassword"\s+Value="([^"]+)"'
)


class GetpwdError(Exception):
    """带有明确上下文的、可直接展示给用户的错误。"""


@dataclass
class Credentials:
    SuperUser: str = ""
    SuperPass: str = ""
    PPPoEUser: str = ""
    PPPoEPass: str = ""

    def found(self) -> bool:
        return bool(self.SuperUser or self.SuperPass or self.PPPoEUser or self.PPPoEPass)


def tail(text: str, n: int = 800) -> str:
    return text if len(text) <= n else text[-n:]


def read_password(prompt: str = "路由器密码: ") -> str:
    """逐字符读取密码，用 * 掩码；退格可删除，Ctrl+C 取消。"""
    if not sys.stdin.isatty():
        # 管道/重定向时无法关闭回显，退化为普通读取。
        line = sys.stdin.readline()
        if not line:
            raise EOFError
        return line.rstrip("\r\n")

    chars: list[str] = []

    def feed(ch: str) -> str | None:
        """返回 'done'/'cancel'，或 None 表示已处理。"""
        if ch in ("\r", "\n"):
            print()
            return "done"
        if ch == "\x03":
            print()
            raise KeyboardInterrupt
        if ch in ("\b", "\x7f"):
            if chars:
                chars.pop()
                sys.stdout.write("\b \b")
                sys.stdout.flush()
            return None
        chars.append(ch)
        sys.stdout.write("*")
        sys.stdout.flush()
        return None

    if os.name == "nt":
        import msvcrt

        print(prompt, end="", flush=True)
        while True:
            result = feed(msvcrt.getwch())
            if result == "done":
                return "".join(chars)
    else:
        import termios
        import tty

        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            print(prompt, end="", flush=True)
            while True:
                ch = sys.stdin.read(1)
                if not ch:
                    raise EOFError
                result = feed(ch)
                if result == "done":
                    return "".join(chars)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


def decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def enable_telnet() -> None:
    print("正在开启 telnet...")
    session = requests.Session()
    session.trust_env = False  # 忽略代理设置，光猫是本地地址
    try:
        response = session.post(
            ENABLE_TELNET_URL,
            data={
                "telnet_port": "23",
                "telnet_lan_enabled": "1",
                "telnet_wan_enabled": "0",
            },
            timeout=8,
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        raise GetpwdError(
            f"开启 telnet 失败: {e}\n"
            "请确认电脑已连接光猫的 WiFi 或网线，且能访问 http://192.168.1.1"
        ) from e


class TelnetSession:
    """对 telnetlib3 流的薄封装：按标记读取，支持超时与错误定位。"""

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.buffer = bytearray()

    async def send_line(self, line: str) -> None:
        self.writer.write(line.encode("utf-8") + b"\r\n")
        await self.writer.drain()

    async def read_until(
        self,
        markers: tuple[bytes, ...],
        timeout: float,
        stage: str,
        failures: tuple[str, ...] = (),
    ) -> str:
        """返回截至（含）最先出现的标记的文本；超时/断开时带上下文报错。"""
        try:
            return await asyncio.wait_for(
                self._read_until(markers, stage, failures), timeout
            )
        except asyncio.TimeoutError as e:
            raise GetpwdError(
                f"{stage}超时（{timeout} 秒）。已收到:\n{tail(decode(bytes(self.buffer)))}"
            ) from e
        except asyncio.IncompleteReadError as e:
            raise GetpwdError(
                f"{stage}失败：连接被对端关闭。已收到:\n{tail(decode(bytes(e.partial)))}"
            ) from e

    async def _read_until(
        self, markers: tuple[bytes, ...], stage: str, failures: tuple[str, ...]
    ) -> str:
        while True:
            text = decode(bytes(self.buffer))
            lower = text.lower()
            for failure in failures:
                if failure in lower:
                    raise GetpwdError(
                        "登录失败：密码错误（请确认输入的是光猫背面的 user 账号密码）"
                    )

            found = [(self.buffer.find(m), m) for m in markers]
            found = [(pos, m) for pos, m in found if pos != -1]
            if found:
                pos, marker = min(found, key=lambda item: item[0])
                end = pos + len(marker)
                data = bytes(self.buffer[:end])
                del self.buffer[:end]  # 多余数据留着给下一阶段用
                return decode(data)

            chunk = await self.reader.read(1024)
            if not chunk:
                raise asyncio.IncompleteReadError(bytes(self.buffer), len(self.buffer))
            self.buffer.extend(chunk)


def parse_credentials(output: str) -> Credentials:
    creds = Credentials()
    if match := SUPER_USER_RE.search(output):
        creds.SuperUser = match.group(1)
    if match := SUPER_PASS_RE.search(output):
        creds.SuperPass = match.group(1)
    if match := PPPOE_RE.search(output):
        creds.PPPoEUser, creds.PPPoEPass = match.group(1), match.group(2)
    elif match := PPPOE_USER_RE.search(output):
        # 只找到用户名时保留用户名，绝不猜一个可能属于别人的密码。
        creds.PPPoEUser = match.group(1)
    return creds


async def fetch_credentials(host: str, port: int, password: str) -> Credentials:
    print(f"正在连接 {host}:{port}...")
    try:
        reader, writer = await telnetlib3.open_connection(host, port, encoding=False)
    except OSError as e:
        raise GetpwdError(f"无法连接 {host}:{port}: {e}") from e

    session = TelnetSession(reader, writer)
    try:
        await session.read_until(LOGIN_PROMPTS, 8, "等待登录提示符", LOGIN_FAILURES)
        print("正在登录...")
        await session.send_line(USERNAME)

        await session.read_until(PASSWORD_PROMPTS, 8, "等待密码提示符", LOGIN_FAILURES)
        await session.send_line(password)

        await session.read_until(SHELL_PROMPTS, 10, "读取登录结果", LOGIN_FAILURES)

        marker = f"__GPWD_{time.time_ns()}__"
        # 把哨兵拆成两段，避免设备回显的命令本身触发 marker。
        mid = len(marker) // 2
        split = marker[:mid] + '"' + marker[mid:] + '"'
        await session.send_line(f"cat {CONFIG_PATH}; echo {split}")

        print(f"正在读取 {CONFIG_PATH}...")
        output = await session.read_until(
            (("\n" + marker).encode(),), 15, f"读取 {CONFIG_PATH}"
        )

        creds = parse_credentials(output)
        if not creds.found():
            raise GetpwdError(
                "未在配置文件中找到账号密码字段。\n"
                f"原始输出（末尾 800 字符）:\n{tail(output)}"
            )
        return creds
    finally:
        writer.close()


async def main() -> int:
    parser = argparse.ArgumentParser(description="获取 UNG453H 超级管理员与 PPPoE 账号密码")
    parser.add_argument("-p", "--password", help="光猫的 user 账号密码（不指定则交互输入）")
    args = parser.parse_args()

    try:
        password = args.password if args.password else read_password()
        enable_telnet()
        creds = await fetch_credentials(HOST, PORT, password)
    except GetpwdError as e:
        print(f"错误: {e}", file=sys.stderr)
        return 1
    except (EOFError, KeyboardInterrupt):
        print("\n已取消。", file=sys.stderr)
        return 1

    print(f"配置文件: {CONFIG_PATH}")
    for label, value in (
        ("账号", creds.SuperUser),
        ("密码", creds.SuperPass),
        ("pppoe 账号", creds.PPPoEUser),
        ("pppoe 密码", creds.PPPoEPass),
    ):
        if value:
            print(f"{label}: {value}")

    return 0


def cli() -> None:
    code = 1
    try:
        code = asyncio.run(main())
    except SystemExit as e:  # argparse 的 --help / 参数错误
        code = e.code if isinstance(e.code, int) else 1
    except KeyboardInterrupt:
        print("\n已取消。", file=sys.stderr)
    except BaseException:
        traceback.print_exc()
    finally:
        try:
            input("\n按回车键退出...")
        except (EOFError, KeyboardInterrupt):
            pass
    sys.exit(code)


if __name__ == "__main__":
    cli()
