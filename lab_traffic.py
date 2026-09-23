"""Record controlled localhost normal and port-scan traffic with TShark."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import http.server
import http.client
import socket
import subprocess
import threading
import time
from pathlib import Path

TARGET = "127.0.0.2"

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"Local NetWatch test\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def record(tshark, interface, output, behavior):
    command = [tshark, "-i", interface, "-f", f"host {TARGET}", "-a", "duration:7", "-w", str(output)]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, encoding="utf-8", errors="replace")
    try:
        time.sleep(1.5)
        if behavior == "normal":
            server = http.server.ThreadingHTTPServer((TARGET, 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for _ in range(12):
                    connection = http.client.HTTPConnection(TARGET, server.server_port, timeout=2)
                    connection.request("GET", "/")
                    connection.getresponse().read()
                    connection.close()
                    time.sleep(0.16)
            finally:
                server.shutdown()
                server.server_close()
        else:
            def probe(port):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
                    connection.settimeout(0.2)
                    return connection.connect_ex((TARGET, port))
            with ThreadPoolExecutor(max_workers=16) as pool:
                list(pool.map(probe, range(1, 121)))
        stdout, stderr = process.communicate(timeout=15)
        if process.returncode:
            raise RuntimeError(f"TShark capture gagal: {stderr.strip() or stdout.strip()}")
        if not output.is_file() or output.stat().st_size < 100:
            raise RuntimeError(f"Capture kosong: {output}")
        print(f"{behavior}: {output} ({output.stat().st_size} bytes)")
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tshark", default="tshark")
    parser.add_argument("--interface", default="5", help="TShark loopback interface number from tshark -D")
    parser.add_argument("--out-dir", type=Path, default=Path("captures"))
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    record(args.tshark, args.interface, args.out_dir / "normal-local.pcapng", "normal")
    record(args.tshark, args.interface, args.out_dir / "scan-local.pcapng", "scan")


if __name__ == "__main__":
    main()
