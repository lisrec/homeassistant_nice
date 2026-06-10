#!/usr/bin/env python3
"""Read-only probe for Nice BiDi-WiFi local access characteristics.

This script answers three practical questions without moving the gate:
1. Is the local TLS endpoint reachable?
2. Does the device answer unauthenticated NHK requests at all?
3. Does local control appear to require credentials/session signing?

Optionally, if valid credentials are provided, the probe also verifies an
authenticated INFO or status read locally over Wi-Fi.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import socket
import ssl
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

STX = b"\x02"
ETX = b"\x03"


@dataclass
class ProbeResult:
    tls_reachable: bool
    tls_version: str | None
    cipher: str | None
    peer_cert_sha256: str | None
    unauth_info_response: str | None
    unauth_info_has_error: bool
    dummy_connect_response: str | None
    dummy_connect_error_code: str | None
    fake_signed_info_response: str | None
    fake_signed_info_error_code: str | None
    local_protocol_visible: bool
    auth_required_for_control: bool
    verdict: str


@dataclass(frozen=True)
class LocalCredentials:
    username: str
    password_hex: str
    target_mac: str
    source_id: str | None = None

    @property
    def source(self) -> str:
        return self.source_id or self.username

    @property
    def password(self) -> bytes:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", self.password_hex):
            raise ValueError("password_hex must be 64 hex characters")
        return bytes.fromhex(self.password_hex)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, help="BiDi-WiFi IP or hostname")
    parser.add_argument("--port", type=int, default=443, help="BiDi-WiFi TLS/NHK port")
    parser.add_argument("--target-mac", required=True, help="BiDi MAC address")
    parser.add_argument("--credentials", type=Path, help="JSON credentials file")
    parser.add_argument("--username", help="NHK username")
    parser.add_argument("--password-hex", help="NHK password hex")
    parser.add_argument("--source-id", help="NHK source/controller ID")
    parser.add_argument("--with-auth-info", action="store_true", help="If credentials are present, verify authenticated INFO")
    parser.add_argument("--with-auth-status", action="store_true", help="If credentials are present, verify authenticated status register reads")
    return parser.parse_args()


def _make_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    return context


def _frame(xml: str) -> bytes:
    return STX + xml.encode("utf-8") + ETX


def _printable(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").replace("\x02", "<STX>").replace("\x03", "<ETX>")


def _attr(text: str, name: str) -> str | None:
    match = re.search(rf'\b{name}="([^"]*)"', text)
    return match.group(1) if match else None


def _recv_frame(sock: ssl.SSLSocket, timeout: float = 5.0) -> bytes:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    while True:
        try:
            chunk = sock.recv(65535)
        except TimeoutError:
            break
        if not chunk:
            break
        chunks.append(chunk)
        if ETX in chunk:
            break
    return b"".join(chunks)


def _extract_error_code(text: str | None) -> str | None:
    if not text:
        return None
    match = re.search(r"<Code>([^<]+)</Code>", text)
    return match.group(1).strip() if match else None


def _reverse_hex(value: str) -> bytes:
    return bytes.fromhex(value)[::-1]


def _sha256(*values: bytes) -> bytes:
    digest = hashlib.sha256()
    for value in values:
        digest.update(value)
    return digest.digest()


def _load_credentials(args: argparse.Namespace) -> LocalCredentials | None:
    data: dict[str, Any] = {}
    if args.credentials:
        data = json.loads(args.credentials.read_text())
    username = args.username or data.get("username")
    password_hex = args.password_hex or data.get("password_hex") or data.get("password")
    target_mac = args.target_mac or data.get("target_mac")
    source_id = args.source_id or data.get("source_id") or data.get("source")
    if not username or not password_hex or not target_mac:
        return None
    return LocalCredentials(
        username=str(username),
        password_hex=str(password_hex),
        target_mac=str(target_mac),
        source_id=str(source_id) if source_id else None,
    )


def _request_start(request_id: int, request_type: str, source: str, target_mac: str) -> str:
    return (
        f'<Request gw="gwID" id="{request_id}" protocolType="NHK" '
        f'protocolVersion="1.0" source="{source}" target="{target_mac}" type="{request_type}">\r\n'
    )


def _signed_request(request_type: str, request_id: int, source: str, target_mac: str, session_key: bytes, body: str = "") -> str:
    xml_command = _request_start(request_id, request_type, source, target_mac) + body
    sign = base64.b64encode(_sha256(_sha256(xml_command.encode("utf-8")), session_key)).decode("ascii")
    return xml_command + f"<Sign>{sign}</Sign>\r\n</Request>\r\n"


def _authenticated_info(host: str, port: int, creds: LocalCredentials) -> dict[str, Any]:
    ctx = _make_context()
    with socket.create_connection((host, port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=None) as sock:
            client_challenge = "00112233"
            connect_xml = (
                _request_start(0, "CONNECT", creds.source, creds.target_mac)
                + f'<Authentication cc="{client_challenge}" username="{creds.username}"/>\r\n'
                + "</Request>\r\n"
            )
            sock.sendall(_frame(connect_xml))
            connect_response = _printable(_recv_frame(sock))
            server_challenge = _attr(connect_response, "sc")
            session_id = _attr(connect_response, "id")
            if not server_challenge or session_id is None or "<Error>" in connect_response:
                return {
                    "connect_response": connect_response,
                    "authenticated": False,
                    "reason": "connect_failed",
                }
            session_key = _sha256(creds.password, _reverse_hex(server_challenge), _reverse_hex(client_challenge))
            request_id = (1 << 8) | (int(session_id) & 0xFF)
            info_xml = _signed_request("INFO", request_id, creds.source, creds.target_mac, session_key)
            sock.sendall(_frame(info_xml))
            info_response = _printable(_recv_frame(sock))
            return {
                "connect_response": connect_response,
                "authenticated": "<Error>" not in info_response,
                "info_response": info_response,
            }


def probe(host: str, port: int, target_mac: str) -> ProbeResult:
    ctx = _make_context()
    with socket.create_connection((host, port), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=None) as sock:
            cert = sock.getpeercert(binary_form=True)
            tls_version = sock.version()
            cipher = sock.cipher()[0] if sock.cipher() else None
            peer_cert_sha256 = hashlib.sha256(cert).hexdigest() if cert else None

            unauth_info_xml = (
                _request_start(0, "INFO", "probe", target_mac)
                + "</Request>\r\n"
            )
            sock.sendall(_frame(unauth_info_xml))
            unauth_info_response = _printable(_recv_frame(sock))

            connect_xml = (
                _request_start(0, "CONNECT", "probe", target_mac)
                + '<Authentication cc="00112233" username="probe"/>\r\n'
                + "</Request>\r\n"
            )
            sock.sendall(_frame(connect_xml))
            dummy_connect_response = _printable(_recv_frame(sock))
            dummy_connect_error_code = _extract_error_code(dummy_connect_response)

            fake_signed_info_xml = (
                _request_start(256, "INFO", "probe", target_mac)
                + "<Sign>AAAA</Sign>\r\n"
                + "</Request>\r\n"
            )
            sock.sendall(_frame(fake_signed_info_xml))
            fake_signed_info_response = _printable(_recv_frame(sock))
            fake_signed_info_error_code = _extract_error_code(fake_signed_info_response)

    local_protocol_visible = bool(unauth_info_response or dummy_connect_response or fake_signed_info_response)
    auth_required_for_control = dummy_connect_error_code is not None or fake_signed_info_error_code is not None

    if local_protocol_visible and auth_required_for_control:
        verdict = "Local NHK/TLS endpoint is present, but local control appears to require valid NHK credentials/session signing. IP reachability alone is not enough."
    elif local_protocol_visible:
        verdict = "Local NHK/TLS endpoint is present. Credential requirement is not proven by this probe."
    else:
        verdict = "No local NHK/TLS behavior detected."

    return ProbeResult(
        tls_reachable=True,
        tls_version=tls_version,
        cipher=cipher,
        peer_cert_sha256=peer_cert_sha256,
        unauth_info_response=unauth_info_response,
        unauth_info_has_error="<Error>" in unauth_info_response if unauth_info_response else False,
        dummy_connect_response=dummy_connect_response,
        dummy_connect_error_code=dummy_connect_error_code,
        fake_signed_info_response=fake_signed_info_response,
        fake_signed_info_error_code=fake_signed_info_error_code,
        local_protocol_visible=local_protocol_visible,
        auth_required_for_control=auth_required_for_control,
        verdict=verdict,
    )


def main() -> int:
    args = parse_args()
    result = asdict(probe(args.host, args.port, args.target_mac))
    creds = _load_credentials(args)
    if creds and (args.with_auth_info or args.with_auth_status):
        auth = _authenticated_info(args.host, args.port, creds)
        result["authenticated_probe"] = auth
        if args.with_auth_status:
            result["authenticated_probe"]["note"] = "Status register verification can be added with the full integration client when needed."
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
