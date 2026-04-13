import hashlib
import struct
import os
import time
import socket
import threading

# Stałe
HSS_OP_READ = 0x01
HSS_OP_WRITE = 0x02

class HSS_Simulator:
    def __init__(self):
        self.hmac_key = b'\x00' * 32                    # klucz testowy
        self.sock_path = "/tmp/hss-daemon.sock"
        self.server_socket = None
        self.running = True

    def start_daemon(self):
        if os.path.exists(self.sock_path):
            os.unlink(self.sock_path)

        self.server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_socket.bind(self.sock_path)
        self.server_socket.listen(5)
        print(f"[DAEMON] Nasłuchuje na {self.sock_path}...")

        while self.running:
            try:
                conn, _ = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(conn,), daemon=True).start()
            except:
                break

    def handle_client(self, conn):
        print("[DAEMON] Akceptowano połączenie z jądra")
        try:
            while True:
                data = conn.recv(72)          # msg(40) + HMAC(32)
                if len(data) < 72:
                    break

                msg_bytes = data[:40]
                received_hmac = data[40:72]

                # Weryfikacja HMAC (tak jak w kernelu)
                computed_hmac = hashlib.sha256(self.hmac_key + msg_bytes).digest()
                if computed_hmac != received_hmac:
                    print("[DAEMON] ❌ Błąd HMAC!")
                    conn.send(b'\x00' * 80)
                    continue

                # Parsowanie
                ts, pid, inode_nr, op_mask = struct.unpack('<QIQI', msg_bytes[:24])
                nonce = msg_bytes[24:40]

                print(f"[DAEMON] → PID={pid} | inode={inode_nr} | op=0x{op_mask:X} | nonce={nonce.hex()[:16]}...")

                # Decyzja (możesz tu dodać swoją logikę)
                decision = 0 if (op_mask & HSS_OP_READ) else 1

                # === POPRAWKA: poprawna odpowiedź 24 bajty + 32 HMAC ===
                resp_struct = struct.pack('<16sII', nonce, decision, 0)   # 24 bajty
                resp_hmac = hashlib.sha256(self.hmac_key + resp_struct).digest()

                full_response = resp_struct + resp_hmac                    # dokładnie 56 bajtów? CZEKAJ...

                # Poprawka rozmiaru - w Twoim kodzie kernel oczekuje 48 bajtów struktury? Nie.
                # Sprawdźmy jeszcze raz...
                # Najbezpieczniej: zrób dokładnie jak w kernelu (24 bajty resp + 32 HMAC = 56 bajtów)

                print(f"[DAEMON] ← Decyzja: {'ZEZWÓL' if decision == 0 else 'ODMÓW'}")
                conn.send(resp_struct + resp_hmac)

        except Exception as e:
            print(f"[DAEMON] Błąd: {e}")
        finally:
            conn.close()

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        if os.path.exists(self.sock_path):
            try:
                os.unlink(self.sock_path)
            except:
                pass


def simulate_kernel_upcall():
    sock_path = "/tmp/hss-daemon.sock"
    if not os.path.exists(sock_path):
        print("[KERNEL SIM] ❌ Demon nie działa!")
        return False

    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect(sock_path)

        # Wiadomość jak w kernelu
        msg = struct.pack('<QIQI', int(time.time() * 1_000_000_000), 1234, 56789, HSS_OP_READ)
        nonce = os.urandom(16)
        msg += nonce                                      # 40 bajtów

        hmac_key = b'\x00' * 32
        sent_hmac = hashlib.sha256(hmac_key + msg).digest()

        s.send(msg + sent_hmac)
        print("[KERNEL SIM] Wysłałem upcall (40 + 32 bajty)")

        # Odbierz odpowiedź — oczekujemy dokładnie 56 bajtów (24 + 32)
        resp_data = s.recv(1024)
        print(f"[KERNEL SIM] Otrzymano {len(resp_data)} bajtów")

        if len(resp_data) != 56:
            print(f"[KERNEL SIM] ❌ Nieprawidłowy rozmiar odpowiedzi! Oczekiwano 56 bajtów.")
            return False

        resp = resp_data[:24]
        received_hmac = resp_data[24:56]

        computed_hmac = hashlib.sha256(hmac_key + resp).digest()

        if computed_hmac != received_hmac:
            print("[KERNEL SIM] ❌ Błąd HMAC w odpowiedzi!")
            return False

        nonce_echo, decision, flags = struct.unpack('<16sII', resp)
        status = "ZEZWÓL" if decision == 0 else f"ODMÓW (kod {decision})"
        print(f"[KERNEL SIM] ✓ Sukces! Decyzja: {status} | nonce echo poprawny")

        return True

    except Exception as e:
        print(f"[KERNEL SIM] Błąd: {e}")
        return False
    finally:
        try:
            s.close()
        except:
            pass


if __name__ == "__main__":
    print("=== Symulator protokołu HolonOS HSS (v3) — POPRAWIONA WERSJA ===\n")

    sim = HSS_Simulator()
    daemon_thread = threading.Thread(target=sim.start_daemon, daemon=True)
    daemon_thread.start()

    time.sleep(0.8)

    print("=== TEST 1: Normalny upcall ===")
    simulate_kernel_upcall()

    time.sleep(0.5)
    print("\n=== TEST 2: Kolejny upcall ===")
    simulate_kernel_upcall()

    time.sleep(0.5)
    print("\n=== TEST 3: Symulacja awarii + reconnect ===")
    print("   (zamykam gniazdo demona...)")
    sim.server_socket.close()
    time.sleep(0.4)

    # Ponowne uruchomienie
    daemon_thread = threading.Thread(target=sim.start_daemon, daemon=True)
    daemon_thread.start()
    time.sleep(0.8)

    simulate_kernel_upcall()

    input("\nNaciśnij Enter, aby zakończyć...")
    sim.stop()
    print("\nSymulacja zakończona.")
