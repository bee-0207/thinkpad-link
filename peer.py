#!/usr/bin/env python3
"""Two-way link between two computers (Wi-Fi hotspot or Ethernet cable).

One laptop listens, the other connects. After that, BOTH sides can type
messages and send files at the same time.

    python3 peer.py listen               # laptop A
    python3 peer.py connect 192.168.50.1 # laptop B (use laptop A's IP)

While connected:
    any text        send a chat message
    /send <file>    send a file (checked with SHA-256 on arrival)
    /quit           disconnect

Received files are saved in a "received" folder next to where you ran it.
Only uses Python's standard library (Python 3.8+), no pip install needed.
"""
import argparse
import hashlib
import json
import queue
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

PORT = 5000
CHUNK = 1 << 20  # 1 MB
RECV_DIR = Path("received")

_print_lock = threading.Lock()


def say(text):
    with _print_lock:
        print(text, flush=True)


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1000:
            return f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} TB"


def rate(nbytes, seconds):
    return f"{human(nbytes / max(seconds, 1e-6))}/s"


# Wire format: every frame is a 4-byte length, then a JSON header. A "file"
# header is followed by exactly header["size"] raw bytes, then a "file_end"
# header carrying the SHA-256 so the receiver can verify the copy.

def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(n - len(buf), CHUNK))
        if not chunk:
            raise ConnectionError("peer disconnected")
        buf += chunk
    return bytes(buf)


def read_header(sock):
    (n,) = struct.unpack(">I", recv_exact(sock, 4))
    return json.loads(recv_exact(sock, n))


def write_header(sock, header):
    data = json.dumps(header).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def send_file(sock, path):
    size = path.stat().st_size
    write_header(sock, {"type": "file", "name": path.name, "size": size})
    h = hashlib.sha256()
    start = time.time()
    left = size
    with open(path, "rb") as f:
        while left:
            chunk = f.read(min(left, CHUNK))
            if not chunk:
                raise IOError(f"{path.name} shrank while sending")
            sock.sendall(chunk)
            h.update(chunk)
            left -= len(chunk)
    write_header(sock, {"type": "file_end", "sha256": h.hexdigest()})
    secs = time.time() - start
    say(f"[sent {path.name}: {human(size)} in {secs:.1f}s, {rate(size, secs)}]")


def receive_file(sock, hdr, outbox):
    name = Path(hdr["name"]).name  # drop any folder parts the sender included
    if name in ("", ".", ".."):
        name = "unnamed"
    RECV_DIR.mkdir(exist_ok=True)
    dest = RECV_DIR / name
    tmp = dest.with_name(name + ".part")
    size = hdr["size"]
    say(f"[receiving {name} ({human(size)})...]")
    h = hashlib.sha256()
    start = time.time()
    try:
        with open(tmp, "wb") as f:
            left = size
            while left:
                chunk = sock.recv(min(left, CHUNK))
                if not chunk:
                    raise ConnectionError("peer disconnected mid-file")
                f.write(chunk)
                h.update(chunk)
                left -= len(chunk)
        end = read_header(sock)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    secs = time.time() - start
    ok = end.get("sha256") == h.hexdigest()
    if ok:
        tmp.replace(dest)
        say(f"[got {name}: saved to {dest.resolve()}, {rate(size, secs)}, checksum OK]")
    else:
        tmp.unlink()
        say(f"[got {name} but checksum FAILED, discarded; ask them to resend]")
    outbox.put(("header", {"type": "ack", "name": name, "ok": ok}))


def reader(sock, outbox, closed):
    try:
        while True:
            hdr = read_header(sock)
            kind = hdr.get("type")
            if kind == "msg":
                say(f"peer: {hdr['text']}")
            elif kind == "file":
                receive_file(sock, hdr, outbox)
            elif kind == "ack":
                status = "arrived intact" if hdr["ok"] else "FAILED checksum, resend it"
                say(f"[peer says {hdr['name']} {status}]")
    except (ConnectionError, OSError, ValueError, struct.error):
        pass
    closed.set()
    say("[connection closed; press Enter to exit]")


def writer(sock, outbox):
    # The only thread that writes to the socket, so messages, files and acks
    # never get interleaved mid-frame.
    try:
        while (job := outbox.get()) is not None:
            kind, arg = job
            if kind == "header":
                write_header(sock, arg)
            else:
                send_file(sock, arg)
    except OSError as e:
        say(f"[send failed: {e}]")


def run(sock):
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    outbox = queue.Queue()
    closed = threading.Event()
    threading.Thread(target=reader, args=(sock, outbox, closed), daemon=True).start()
    w = threading.Thread(target=writer, args=(sock, outbox), daemon=True)
    w.start()
    say("Connected. Type a message and press Enter. /send <file> sends a file, /quit exits.")
    try:
        for line in sys.stdin:
            if closed.is_set():
                break
            line = line.strip()
            if line == "/quit":
                break
            if line.startswith("/send "):
                path = Path(line[6:].strip().strip('"'))
                if path.is_file():
                    outbox.put(("file", path))
                else:
                    say(f"[no such file: {path}]")
            elif line:
                outbox.put(("header", {"type": "msg", "text": line}))
    except KeyboardInterrupt:
        pass
    outbox.put(None)
    w.join()  # finish anything still queued (e.g. a file mid-send)
    sock.close()


def local_ips():
    try:
        ips = socket.gethostbyname_ex(socket.gethostname())[2]
    except OSError:
        ips = []
    ips = [ip for ip in ips if not ip.startswith("127.")]
    if not ips:  # usual on Linux, where the hostname maps to 127.0.1.1
        try:
            out = subprocess.run(["hostname", "-I"], capture_output=True, text=True).stdout
            ips = [ip for ip in out.split() if ":" not in ip]  # skip IPv6
        except OSError:
            pass
    return ips


def listen(port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    ips = local_ips()
    say(f"This laptop's IP address(es): {', '.join(ips) or "unknown, run 'ip a'"}")
    say(f"Waiting on port {port}. On the other laptop run:  python3 peer.py connect <IP above>")
    conn, addr = srv.accept()
    srv.close()
    say(f"[{addr[0]} connected]")
    run(conn)


def connect(host, port, wait):
    deadline = time.time() + wait
    while True:
        try:
            sock = socket.create_connection((host, port), timeout=5)
            break
        except OSError as e:
            if time.time() > deadline:
                sys.exit(f"Could not reach {host}:{port} ({e}). See HOW-TO-RUN.txt, Troubleshooting.")
            say(f"[can't reach {host}:{port} yet ({e}); retrying...]")
            time.sleep(2)
    sock.settimeout(None)
    run(sock)


def main():
    ap = argparse.ArgumentParser(description="Two-way message and file link between two computers.")
    sub = ap.add_subparsers(dest="mode", required=True)
    l = sub.add_parser("listen", help="wait for the other laptop to connect")
    l.add_argument("--port", type=int, default=PORT)
    c = sub.add_parser("connect", help="connect to the listening laptop")
    c.add_argument("host", help="IP address of the listening laptop")
    c.add_argument("--port", type=int, default=PORT)
    c.add_argument("--wait", type=int, default=30, help="seconds to keep retrying")
    args = ap.parse_args()
    if args.mode == "listen":
        listen(args.port)
    else:
        connect(args.host, args.port, args.wait)


if __name__ == "__main__":
    main()
