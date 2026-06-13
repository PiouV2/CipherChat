# main.py — Encrypted two-way peer chat using SM4-CBC and HMAC-SHA256.

import os
import socket
# Secure random utilities for password generation
import secrets
# Threading primitives used to run receiver in background
import threading
# Tuple type hint
from typing import Tuple

# Crypto helpers: key derivation, encryption and verification
from crypto_utils import derive_keys, encrypt_and_tag, verify_and_decrypt
# Protocol helpers: packet framing and I/O
from protocol import send_packet, recv_packet
# ASCII art splash banner
from banner import SPLASH

# Default host address used when prompting
DEFAULT_HOST = "127.0.0.1"
# Default TCP port used when prompting
DEFAULT_PORT = 5000
# Command string to end the chat session
QUIT_CMD = "/quit"


def prompt_default(prompt: str, default: str) -> str:
    # Read input with a visible default and strip whitespace
    value = input(f"{prompt} [{default}]: ").strip()
    # Return the provided value or the default when empty
    return value if value else default


def prompt_mode() -> str:
    # Prompt repeatedly until user types a valid mode
    while True:
        # Read and normalize input
        mode = input("Select mode [sender/receiver]: ").strip().lower()
        # Accept only 'sender' or 'receiver'
        if mode in ("sender", "receiver"):
            return mode
        # Inform about invalid choice and loop
        print("Invalid mode. Please type 'sender' or 'receiver'.")


def prompt_password_sender() -> str:
    # Generate a secure, URL-safe random password suggestion
    generated = secrets.token_urlsafe(12)
    print(f"Generated password: {generated}")
    print("Keep this password and enter the same one in the receiver terminal.")
    # Ask whether to use the generated password or provide a custom one
    choice = input("Use this password? [Y/n]: ").strip().lower()
    if choice in ("n", "no"):
        # If user declines, prompt for a custom password
        custom = input("Enter new password: ").strip()
        return custom if custom else generated
    # Otherwise return the generated password
    return generated


def prompt_password_receiver() -> str:
    # Receiver simply types the shared password
    return input("Enter shared password: ").strip()


def run_peer(host: str, port: int, username: str, password: str, is_server: bool) -> None:
    # Derive symmetric SM4 key and HMAC key from password
    sm4_key, hmac_key = derive_keys(password)

    # Placeholder for server socket if we act as server
    server_sock = None
    # Create a TCP socket for communication (or will be replaced by accepted conn)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if is_server:
        # Prepare listening socket for incoming connection
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((host, port))
        server_sock.listen(1)
        print(f"Listening on {host}:{port} ...")
        # Accept a single incoming connection
        conn, addr = server_sock.accept()
        # Use accepted connection for communication
        sock = conn
        print(f"Connected by {addr}.")
    else:
        # Connect out to the remote peer
        sock.connect((host, port))
        print("Connected to peer.")

    # Event to signal the receiver thread to stop
    stop_event = threading.Event()

    def receiver_loop() -> None:
        # Background loop: receive and process packets until stop requested
        try:
            while not stop_event.is_set():
                # Read one framed packet (or None on disconnect)
                packet = recv_packet(sock)
                if packet is None:
                    # Peer closed connection; notify and stop
                    print("\nConnection closed by peer.")
                    stop_event.set()
                    break

                # Inspect packet type
                ptype = packet.get("type")
                if ptype == "quit":
                    # Peer requested termination
                    print("\nPeer ended the session.")
                    stop_event.set()
                    break

                if ptype != "chat":
                    # Ignore unknown packet types
                    continue

                try:
                    # Verify HMAC and decrypt the ciphertext
                    plaintext = verify_and_decrypt(
                        packet["iv"], packet["ciphertext"], packet["tag"], sm4_key, hmac_key
                    )
                    # Display sender and plaintext
                    sender = packet.get("username", "peer")
                    print(f"\n{sender}: {plaintext.decode('utf-8')}")
                    # Re-print prompt after incoming message
                    print("> ", end="", flush=True)
                except Exception as exc:
                    # On any decryption/HMAC/padding error, discard
                    print(f"Invalid message discarded: {exc}")
        finally:
            # Ensure stop condition is set on exit
            stop_event.set()

    # Start receiver thread as a daemon so it won't block process exit
    recv_thread = threading.Thread(target=receiver_loop, daemon=True)
    recv_thread.start()

    try:
        # Main send loop: read user input and send encrypted packets
        print("Type messages. Use /quit to exit.")
        while not stop_event.is_set():
            try:
                # Prompt user for a message
                msg = input("> ").strip()
            except EOFError:
                # Treat EOF (Ctrl+D) as quit command
                msg = QUIT_CMD

            if not msg:
                # Ignore empty lines
                continue

            if msg == QUIT_CMD:
                # Build and send quit packet
                packet = {"type": "quit", "username": username}
                send_packet(sock, packet)
                try:
                    # Clear the terminal (cross-platform)
                    os.system("cls" if os.name == "nt" else "clear")
                except Exception:
                    # Ignore if terminal clear fails
                    pass
                # Signal receiver to stop and break out
                stop_event.set()
                break

            # Encrypt and HMAC the user's message
            iv, ciphertext, tag = encrypt_and_tag(msg.encode("utf-8"), sm4_key, hmac_key)
            # Construct chat packet containing binary fields
            packet = {
                "type": "chat",
                "username": username,
                "iv": iv,
                "ciphertext": ciphertext,
                "tag": tag,
            }
            # Send packet over the socket
            send_packet(sock, packet)
    finally:
        # Cleanup: request receiver stop and close sockets
        stop_event.set()
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        sock.close()
        if server_sock:
            try:
                server_sock.close()
            except Exception:
                pass
        recv_thread.join(timeout=1)
        print("Disconnected.")


def main():
    # Clear terminal immediately on program start (cross-platform)
    try:
        os.system("cls" if os.name == "nt" else "clear")
    except Exception:
        pass

    # Display the splash banner
    print(SPLASH)

    # Prompt user for role, host and port
    mode = prompt_mode()
    host = prompt_default("Host", DEFAULT_HOST)
    port_str = prompt_default("Port", str(DEFAULT_PORT))

    # Validate and parse port number
    try:
        port = int(port_str)
    except ValueError:
        print("Invalid port. Using default 5000.")
        port = DEFAULT_PORT

    # Prompt for username with fallback
    username = input("Username: ").strip() or "user"

    # For sender mode, generate/ask for password and connect out
    if mode == "sender":
        password = prompt_password_sender()
        run_peer(host, port, username, password, is_server=False)
    else:
        # For receiver mode, ask for shared password and listen
        password = prompt_password_receiver()
        run_peer(host, port, username, password, is_server=True)


if __name__ == "__main__":
    main()