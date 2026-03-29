import os
import re
import socket
from typing import Tuple

from dotenv import load_dotenv
from flask import Flask, jsonify, request

# Load environment variables from .env for local development.
# In Docker Compose, variables are injected directly and this call is harmless.
load_dotenv()

app = Flask(__name__)


def _normalize_mac(mac: str) -> str:
    """Return a MAC string with separators removed."""
    return re.sub(r"[^0-9A-Fa-f]", "", mac)


def _is_valid_mac(mac: str) -> bool:
    """Validate MAC address format (12 hex characters after normalization)."""
    normalized = _normalize_mac(mac)
    return bool(re.fullmatch(r"[0-9A-Fa-f]{12}", normalized))


def _is_valid_ipv4(ip_addr: str) -> bool:
    """Validate IPv4 address format."""
    try:
        socket.inet_aton(ip_addr)
    except OSError:
        return False
    return ip_addr.count(".") == 3


def _send_magic_packet(mac: str, destination_ip: str, port: int = 9) -> None:
    """Send Wake-on-LAN magic packet to destination IP and UDP port."""
    normalized = _normalize_mac(mac)
    mac_bytes = bytes.fromhex(normalized)
    magic_packet = b"\xff" * 6 + mac_bytes * 16

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(magic_packet, (destination_ip, port))


def _get_required_config() -> Tuple[str, str, str, str, int]:
    """Load and validate required environment configuration."""
    auth_key = os.getenv("AUTH_KEY", "").strip()
    target_mac = os.getenv("TARGET_MAC", "").strip()
    response_message = os.getenv("RESPONSE_MESSAGE", "").strip()
    wol_destination_ip = os.getenv("WOL_DESTINATION_IP", "255.255.255.255").strip()

    try:
        wol_port = int(os.getenv("WOL_PORT", "9"))
    except ValueError as exc:
        raise RuntimeError("Invalid WOL_PORT. Expected integer value.") from exc

    missing = []
    if not auth_key:
        missing.append("AUTH_KEY")
    if not target_mac:
        missing.append("TARGET_MAC")
    if not response_message:
        missing.append("RESPONSE_MESSAGE")

    if missing:
        raise RuntimeError(f"Missing required environment variable(s): {', '.join(missing)}")

    if not _is_valid_mac(target_mac):
        raise RuntimeError("Invalid TARGET_MAC format. Expected MAC like AA:BB:CC:DD:EE:FF")

    if not _is_valid_ipv4(wol_destination_ip):
        raise RuntimeError("Invalid WOL_DESTINATION_IP format. Expected IPv4 like 192.168.1.255")

    if not (1 <= wol_port <= 65535):
        raise RuntimeError("Invalid WOL_PORT range. Expected value between 1 and 65535.")

    return auth_key, target_mac, response_message, wol_destination_ip, wol_port


AUTH_KEY, TARGET_MAC, RESPONSE_MESSAGE, WOL_DESTINATION_IP, WOL_PORT = _get_required_config()


@app.route("/wake", methods=["POST"])
def wake() -> tuple:
    """Authorize request and trigger Wake-on-LAN packet."""
    auth_header = request.headers.get("Authorization", "").strip()

    if not auth_header:
        return jsonify({"error": "Missing Authorization header"}), 401

    expected_bearer = f"Bearer {AUTH_KEY}"
    if auth_header not in {AUTH_KEY, expected_bearer}:
        return jsonify({"error": "Invalid Authorization header"}), 403

    try:
        _send_magic_packet(TARGET_MAC, WOL_DESTINATION_IP, WOL_PORT)
    except OSError:
        # Keep error generic to avoid leaking internal network details.
        return jsonify({"error": "Failed to send Wake-on-LAN packet"}), 500

    return jsonify({"message": RESPONSE_MESSAGE}), 200


if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8080"))
    app.run(host=host, port=port)
