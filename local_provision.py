#!/usr/bin/env python3
"""
MTTL-W01 Local SoftAP Provisioning Script
=========================================
Protocol: LGAPMODE0010
Automates device information request, Wi-Fi credential delivery,
and apply/reboot without requiring a power cycle.

Educational / research use only. Use exclusively on devices you own.
"""

import socket
import time

# ======================= CONFIG — edit here =======================
CONFIG = {
    "device_ap_ip": "192.168.1.1",      # Device IP while in SoftAP mode (default gateway)
    "device_ap_port": 30300,
    # Your real home network credentials
    "home_wifi_ssid": "YOUR_WIFI_SSID",
    "home_wifi_password": "YOUR_WIFI_PASSWORD",
}

MAGIC = b"LGAPMODE0010"


def build_message(cmd_byte: int, payload: bytes = b"") -> bytes:
    """Build packet: MAGIC + command byte + payload"""
    return MAGIC + bytes([cmd_byte]) + payload


def recv_response(sock: socket.socket, timeout: float = 5.0) -> bytes:
    sock.settimeout(timeout)
    try:
        return sock.recv(4096)
    except socket.timeout:
        return b""


def parse_device_info(response: bytes) -> dict:
    info = {"raw": response}
    if not response.startswith(MAGIC):
        return info
    body = response[len(MAGIC):]
    if body[:2] == b"MO":
        try:
            after_header = body[8:]
            info["mac"] = after_header[:12].decode(errors="ignore")
            rest = after_header[24:]
            info["parts"] = [
                p.decode(errors="ignore") for p in rest.split(b"\x00") if p
            ]
        except Exception as e:
            info["parse_error"] = str(e)
    return info


def build_wifi_payload(ssid: str, password: str) -> bytes:
    ssid_bytes = ssid.encode("utf-8")[:32]
    pass_bytes = password.encode("utf-8")[:32]

    ssid_field = ssid_bytes.ljust(32, b"\x00")
    pass_field = pass_bytes.ljust(32, b"\x00")

    block = ssid_field + pass_field  # 64 bytes
    return block * 2  # 128 bytes (repeated twice)


def main():
    cfg = CONFIG

    if len(cfg["home_wifi_password"]) < 8:
        print("[!] Error: Wi-Fi password must be at least 8 characters.")
        return

    sock = None
    # Connection attempts with retry to ensure stable IP
    for attempt in range(1, 4):
        try:
            print(
                f"[*] Connection attempt ({attempt}/3) to "
                f"{cfg['device_ap_ip']}:{cfg['device_ap_port']}..."
            )
            sock = socket.create_connection(
                (cfg["device_ap_ip"], cfg["device_ap_port"]), timeout=5
            )
            print("[+] TCP connection established")
            break
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            time.sleep(2)

    if not sock:
        print(
            "[!] Could not connect to the device. "
            "Make sure you are connected to the device SoftAP first."
        )
        return

    try:
        # ---------- Step 1: Request device information (0x67) ----------
        print("\n[*] Sending device information request (0x67)...")
        sock.sendall(build_message(0x67, b"\x00" * 7))
        resp = recv_response(sock)
        print(f"[<] Raw response: {resp!r}")
        print(f"[<] Parsed data: {parse_device_info(resp)}")

        if not resp:
            print(
                "[!] No response received — verify you are connected "
                "to the correct SoftAP."
            )
            return

        time.sleep(0.5)

        # ---------- Step 2: Announce Wi-Fi data length (0x65) ----------
        wifi_payload = build_wifi_payload(
            cfg["home_wifi_ssid"], cfg["home_wifi_password"]
        )
        length = len(wifi_payload)

        print(
            f"\n[*] Announcing {length} bytes of Wi-Fi data (0x65)..."
        )
        announce_payload = (
            b"\x00\x00" + bytes([length & 0xFF]) + b"\x00\x00\x00"
        )
        sock.sendall(build_message(0x65, announce_payload))
        resp = recv_response(sock, timeout=3)
        print(f"[<] Announce response: {resp!r}")

        time.sleep(0.5)

        # ---------- Step 3: Send Wi-Fi credentials ----------
        print(
            f"\n[*] Sending Wi-Fi credentials "
            f"(SSID: {cfg['home_wifi_ssid']})..."
        )
        sock.sendall(wifi_payload)
        resp = recv_response(sock, timeout=5)
        print(f"[<] Confirmation response: {resp!r}")

        if resp.startswith(MAGIC) and len(resp) > len(MAGIC):
            status = resp[len(MAGIC)]
            print(f"[<] Status code: 0x{status:02x}")
            if status in (0xC9, 0xCA):
                print("[+] Wi-Fi credentials accepted successfully!")
            else:
                print(
                    f"[?] Unexpected status code (0x{status:02x}), "
                    "continuing with apply command."
                )

        time.sleep(0.5)

        # ---------- Step 4: Send apply / reboot command (0x72 = 'r') ----------
        print(
            "\n[*] Sending apply and reboot command (0x72)..."
        )
        reboot_cmd = build_message(0x72, b"\x00" * 7)
        sock.sendall(reboot_cmd)

        resp = recv_response(sock, timeout=2)
        if resp:
            print(f"[<] Reboot command response: {resp!r}")

        # Clean socket shutdown to signal end of session to the Wi-Fi chip
        time.sleep(1.0)
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass

        print(
            "\n[+] Transmission complete. The device will close SoftAP "
            "and join the home router within 15–20 seconds without a power cycle."
        )

    finally:
        sock.close()


if __name__ == "__main__":
    main()
