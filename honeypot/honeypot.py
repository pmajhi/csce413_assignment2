#!/usr/bin/env python3

import socket
import threading
import time
import os
from datetime import datetime

import paramiko
from logger import (
    setup_logger,
    log_connection_start,
    log_connection_end,
    log_auth_attempt,
    log_command,
    log_data,
)

HOST = "0.0.0.0"
PORT = 22

logger = setup_logger()

HOST_KEY_PATH = "/app/ssh_host_key"
HOST_KEY = None


def load_host_key():
    global HOST_KEY
    if os.path.exists(HOST_KEY_PATH):
        HOST_KEY = paramiko.RSAKey(filename=HOST_KEY_PATH)
    else:
        HOST_KEY = paramiko.RSAKey.generate(2048)
        HOST_KEY.write_private_key_file(HOST_KEY_PATH)


class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, addr):
        super().__init__()
        self.addr = addr
        self.username = None

    def check_auth_password(self, username, password):
        self.username = username
        log_auth_attempt(logger, self.addr, username, password)
        # Always accept to keep attacker interacting
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True


def client_handler(client, addr):
    start = time.time()
    log_connection_start(logger, addr)

    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(HOST_KEY)
        server = HoneypotServer(addr)

        transport.start_server(server=server)

        # Wait for a session channel
        chan = transport.accept(20)
        if chan is None:
            return

        # Fake SSH banner, login already handled by Paramiko
        chan.send(
            "\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-84-generic x86_64)\r\n"
        )
        chan.send("Last login: " + datetime.utcnow().isoformat() + " from 10.0.0.5\r\n")
        prompt_user = server.username or "admin"

        chan.send(f"{prompt_user}@127.0.0.1:~$ ")

        # Command loop
        buffer = ""
        while True:
            data = chan.recv(1024)
            if not data:
                break

            text = data.decode("utf-8", errors="replace")

            for ch in text:
                # Handle Enter
                if ch in ("\r", "\n"):
                    chan.send("\r\n")
                    cmd = buffer.strip()
                    buffer = ""

                    if not cmd:
                        chan.send("\r\n")
                        chan.send(f"{prompt_user}@127.0.0.1:~$ ")
                        continue

                    log_command(logger, addr, cmd)

                    if cmd in ("exit", "quit", "logout"):
                        chan.send("logout\r\n")
                        return

                    resp = fake_response(cmd, prompt_user)
                    chan.send(resp)
                    chan.send(f"{prompt_user}@honeypot:~$ ")
                # Handle backspace
                elif ch in ("\b", "\x7f"):
                    if buffer:
                        buffer = buffer[:-1]
                        chan.send("\b \b")
                else:
                    buffer += ch
                    chan.send(ch)

    except Exception as e:
        extra = {"remote_ip": addr[0], "remote_port": addr[1]}
        logger.info(f"exception {e!r}", extra=extra)
    finally:
        try:
            client.close()
        except OSError:
            pass
        duration = time.time() - start
        log_connection_end(logger, addr, duration)


def fake_response(cmd: str, user: str) -> str:
    if not cmd:
        return "\r\n"
    lower = cmd.lower()

    if lower.startswith("whoami"):
        return user + "\r\n"
    if lower.startswith("uname"):
        return "Linux honeypot 5.15.0-84-generic x86_64\r\n"
    if lower.startswith("id"):
        return f"uid=1000({user}) gid=1000({user}) groups=1000({user})\r\n"
    if lower.startswith("ls"):
        return "README.md  secret.txt  logs\r\n"
    if "flag" in lower:
        return "bash: flag: command not found\r\n"
    if "sudo" in lower:
        return f"{user} is not in the sudoers file.  This incident will be reported.\r\n"
    if lower.startswith("cat secret.txt"):
        return "SIKE!\r\n"

    return f"bash: {cmd.split()[0]}: command not found\r\n"


def main():
    load_host_key()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(100)
    logger.info(
        "honeypot_listening",
        extra={"remote_ip": HOST, "remote_port": PORT},
    )

    while True:
        client, addr = sock.accept()
        t = threading.Thread(target=client_handler, args=(client, addr), daemon=True)
        t.start()


if __name__ == "__main__":
    main()

