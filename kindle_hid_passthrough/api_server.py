#!/usr/bin/env python3
"""
API Server for BTManager WAF app

HTTP server that exposes daemon operations via a REST-like API.
Runs embedded in the daemon process; all operations go through DaemonController.

Port 8321 on localhost.
"""

import json
import os
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse

from config import Protocol, config, get_version, normalize_addr

__all__ = ['APIServer', 'RequestHandler', 'PORT']

PORT = 8321


class APIServer(ThreadingMixIn, HTTPServer):
    """Threaded HTTP server that skips FQDN lookup (fails on Kindle without idna codec)."""
    allow_reuse_address = True
    daemon_threads = True
    controller = None  # Set by daemon.main()

    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)
        host, port = self.server_address[:2]
        self.server_name = host or 'localhost'
        self.server_port = port


class RequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for BTManager API."""

    def log_message(self, _format, *args):
        """Suppress default stderr logging."""
        pass

    def _send_json(self, data):
        body = json.dumps(data).encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        # Extract single values from query params
        def param(name):
            vals = params.get(name, [])
            return vals[0] if vals else None

        match path:
            case '/health':
                self._send_json({"ok": True})
            case '/status':
                self._handle_status()
            case '/start':
                self._handle_start()
            case '/stop':
                self._handle_stop()
            case '/devices':
                self._handle_devices()
            case '/remove':
                self._handle_remove(param('addr'))
            case '/clear-cache':
                self._handle_clear_cache()
            case '/scan':
                self._handle_scan()
            case '/scan-status':
                self._handle_scan_status()
            case '/pair':
                self._handle_pair(param('addr'), param('protocol'), param('name'))
            case '/pair-status':
                self._handle_pair_status()
            case '/connect':
                self._handle_connect(param('addr'), param('protocol'))
            case '/disconnect':
                self._handle_disconnect()
            case '/cursor-start':
                self._handle_cursor_start()
            case '/cursor-stop':
                self._handle_cursor_stop()
            case '/logs':
                self._handle_logs(param('lines'))
            case _:
                self._send_json({"ok": False, "error": "Not found"})

    @property
    def _controller(self):
        """Get controller from server instance."""
        return self.server.controller

    def _handle_status(self):
        status = self._controller.get_status()
        status["ok"] = True
        status["version"] = get_version()
        self._send_json(status)

    def _handle_start(self):
        controller = self._controller
        if controller.daemon.running and not controller.daemon._suspended:
            self._send_json({"ok": True, "message": "Daemon already running"})
            return
        controller.request_connect()
        self._send_json({"ok": True, "message": "Daemon resuming"})

    def _handle_stop(self):
        controller = self._controller
        if controller.daemon._suspended:
            self._send_json({"ok": True, "message": "Already stopped"})
            return
        controller.request_disconnect(suspend=True)
        self._send_json({"ok": True, "message": "Daemon stopped"})

    def _handle_devices(self):
        status = self._controller.get_status()
        self._send_json({"ok": True, "devices": status["devices"]})

    def _handle_remove(self, address):
        if not address:
            self._send_json({"ok": False, "error": "No address provided"})
            return

        result = self._controller.request_remove(address)
        if result["removed"]:
            self._send_json({
                "ok": True,
                "message": "Device removed",
                "address": normalize_addr(address),
                "keys_removed": result["keys_removed"],
            })
        else:
            self._send_json({"ok": False, "error": f"Device not found: {normalize_addr(address)}"})

    def _handle_clear_cache(self):
        count = self._controller.request_clear_cache()
        self._send_json({"ok": True, "message": "Cache cleared", "files_removed": count})

    def _handle_scan(self):
        controller = self._controller
        if controller.is_scanning:
            self._send_json({"ok": True, "message": "Scan already in progress"})
            return
        controller.request_scan()
        self._send_json({"ok": True, "message": "Scan started"})

    def _handle_scan_status(self):
        controller = self._controller
        if controller.is_scanning:
            self._send_json({
                "ok": True,
                "scanning": True,
                "devices": controller._scan_live_devices,
            })
            return
        if controller.scan_result is not None:
            self._send_json(controller.scan_result)
        else:
            self._send_json({"ok": False, "error": "No scan in progress"})

    def _handle_pair(self, address, protocol_str, name=None):
        controller = self._controller

        if not address:
            self._send_json({"ok": False, "error": "No address provided"})
            return

        protocol = Protocol.CLASSIC if protocol_str == 'classic' else Protocol.BLE

        if controller.is_pairing:
            self._send_json({"ok": True, "message": "Pairing already in progress"})
            return
        controller.request_pair(address, protocol, name)
        self._send_json({"ok": True, "message": "Pairing started"})

    def _handle_pair_status(self):
        controller = self._controller
        if controller.is_pairing:
            self._send_json({"ok": True, "pairing": True})
            return
        if controller.pair_result is not None:
            self._send_json(controller.pair_result)
        else:
            self._send_json({"ok": False, "error": "No pairing in progress"})

    def _handle_connect(self, address, protocol_str):
        controller = self._controller

        if not address:
            self._send_json({"ok": False, "error": "No address provided"})
            return

        controller.request_connect(address, protocol_str or 'ble')
        self._send_json({"ok": True, "message": f"Connecting to {address}"})

    def _handle_disconnect(self):
        controller = self._controller
        controller.request_disconnect()
        self._send_json({"ok": True, "message": "Disconnecting"})

    def _handle_cursor_start(self):
        try:
            self._controller.request_cursor_start()
        except OSError as e:
            self._send_json({"ok": False, "error": f"Failed to start cursor overlay: {e}"})
            return
        self._send_json({"ok": True, "message": "Cursor overlay starting"})

    def _handle_cursor_stop(self):
        self._controller.request_cursor_stop()
        self._send_json({"ok": True, "message": "Cursor overlay stopped"})

    def _handle_logs(self, lines_str):
        log_file = config.log_file
        num_lines = 50
        if lines_str:
            try:
                num_lines = max(1, min(int(lines_str), 200))
            except ValueError:
                pass

        if not os.path.exists(log_file):
            self._send_json({"ok": True, "lines": [], "file": log_file})
            return

        try:
            with open(log_file, 'rb') as f:
                f.seek(0, 2)
                size = f.tell()
                chunk_size = min(size, num_lines * 200)
                f.seek(max(0, size - chunk_size))
                data = f.read().decode('utf-8', errors='replace')

            all_lines = data.splitlines()
            tail = all_lines[-num_lines:]
            # Shorten for small screens: strip date, ms, abbreviate level
            # "2026-02-21 19:08:33,922 INFO name:" -> "19:08:33 I name:"
            short = []
            for line in tail:
                # Strip "YYYY-MM-DD " prefix (11 chars)
                if len(line) > 11 and line[4] == '-' and line[10] == ' ':
                    line = line[11:]
                # Strip ",NNN" milliseconds after time
                if len(line) > 8 and line[8] == ',':
                    line = line[:8] + line[12:]
                # Shorten level names
                line = line.replace(' INFO ', ' I ')
                line = line.replace(' WARNING ', ' W ')
                line = line.replace(' ERROR ', ' E ')
                line = line.replace(' DEBUG ', ' D ')
                short.append(line)
            self._send_json({"ok": True, "lines": short})
        except OSError as e:
            self._send_json({"ok": False, "error": str(e)})

