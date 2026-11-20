"""
server_app.py
Smart Office Authentication Server (Bob) — Lightweight ECC P-256 Protocol.
Supports Vietnamese & English GUI (Tkinter) + real TCP socket networking.

Run: python server_app.py
"""

import json
import os
import socket
import struct
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, scrolledtext, ttk
from typing import Callable, Dict, Optional

import crypto_ecc as ecc
from i18n import tr

DATA_FILE = "bob_server_data.json"
OTP_TTL_SECONDS = 120


# ==============================================================================
# Framed JSON TCP Helpers
# ==============================================================================
def send_json(sock: socket.socket, payload: dict) -> None:
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    header = struct.pack("!I", len(raw))
    sock.sendall(header + raw)


def recv_json(sock: socket.socket, max_bytes: int = 1_048_576) -> Optional[dict]:
    header = _recv_exact(sock, 4)
    if not header:
        return None
    (length,) = struct.unpack("!I", header)
    if length <= 0 or length > max_bytes:
        raise ValueError("Invalid message length")
    body = _recv_exact(sock, length)
    if not body:
        return None
    return json.loads(body.decode("utf-8"))


def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


# ==============================================================================
# Authentication Server Core Engine (Bob)
# ==============================================================================
class AuthServerEngine:
    def __init__(
        self,
        data_file: str = DATA_FILE,
        on_log: Optional[Callable[[str, str], None]] = None,
        on_otp: Optional[Callable[[str, str, str, int], None]] = None,
        on_users_changed: Optional[Callable[[], None]] = None,
    ):
        self.data_file = data_file
        self.on_log = on_log or (lambda msg, tag="info": None)
        self.on_otp = on_otp or (lambda id_a, contact, otp, ttl: None)
        self.on_users_changed = on_users_changed or (lambda: None)

        self.lock = threading.Lock()
        self.running = False
        self.server_sock: Optional[socket.socket] = None
        self.delta_t: int = 30

        # Server ECC P-256 keypair (d_B, P_B) and users DB
        self.d_b: int = 0
        self.p_b: ecc.Point = None
        self.users: Dict[str, dict] = {}
        # Active OTP sessions: id_a -> {"otp": str, "ts_issued": int, "used": bool}
        self.pending_otps: Dict[str, dict] = {}

        self._load_or_init_data()

    def _load_or_init_data(self) -> None:
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.d_b = int(data["d_b"], 16)
                self.p_b = ecc.hex_to_point(data["p_b"])
                self.users = data.get("users", {})
                self.on_log("[KEY] Loaded Bob's NIST P-256 ECC keypair from disk.", "info")
                return
            except Exception as e:
                self.on_log(f"[WARN] Could not load {self.data_file}: {e}", "warn")
        self.regenerate_keys(save=True)

    def save_data(self) -> None:
        payload = {
            "d_b": f"{self.d_b:064x}",
            "p_b": ecc.point_to_hex(self.p_b),
            "users": self.users,
        }
        with open(self.data_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

    def regenerate_keys(self, save: bool = True) -> None:
        with self.lock:
            self.d_b, self.p_b = ecc.generate_keypair()
            if save:
                self.save_data()
        self.on_log(
            f"[KEY] Generated NIST P-256 keypair. P_B = {ecc.point_to_hex(self.p_b)[:32]}...",
            "info",
        )

    def get_cert_b(self) -> dict:
        return {
            "subject": "Bob_SmartOffice_AuthServer",
            "curve": "NIST P-256 (secp256r1)",
            "P_B": ecc.point_to_hex(self.p_b),
        }

    def delete_user(self, id_a: str) -> bool:
        with self.lock:
            if id_a in self.users:
                del self.users[id_a]
                self.pending_otps.pop(id_a, None)
                self.save_data()
                self.on_users_changed()
                return True
        return False

    def start(self, host: str, port: int, delta_t: int = 30) -> None:
        if self.running:
            return
        self.delta_t = delta_t
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((host, port))
        self.server_sock.listen(16)
        self.server_sock.settimeout(1.0)
        self.running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self) -> None:
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except OSError:
                pass
            self.server_sock = None

    def _accept_loop(self) -> None:
        while self.running and self.server_sock:
            try:
                conn, addr = self.server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_client, args=(conn, addr), daemon=True
            ).start()

    def _handle_client(self, conn: socket.socket, addr) -> None:
        try:
            conn.settimeout(15.0)
            req = recv_json(conn)
            if not req:
                return
            action = req.get("action")
            if action == "ping":
                resp = {"status": "ok", "cert_b": self.get_cert_b()}
            elif action == "register":
                resp = self._handle_register(req, addr)
            elif action == "auth_request":
                resp = self._handle_auth_request(req, addr)
            elif action == "auth_verify":
                resp = self._handle_auth_verify(req, addr)
            else:
                resp = {"status": "error", "message": f"Unknown action: {action}"}
            send_json(conn, resp)
        except Exception as e:
            self.on_log(f"[ERROR] Client {addr}: {e}", "err")
            try:
                send_json(conn, {"status": "error", "message": str(e)})
            except Exception:
                pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    # --------------------------------------------------------------------------
    # Phase 1: Registration (Secure Channel)
    # --------------------------------------------------------------------------
    def _handle_register(self, req: dict, addr) -> dict:
        id_a = req.get("ID_A", "").strip()
        pa_hex = req.get("P_A", "").strip()
        salt_hex = req.get("salt_A", "").strip()
        contact = req.get("contact", "").strip()
        device = req.get("device", "Unknown")

        if not id_a or not pa_hex or not contact:
            return {"status": "error", "message": "Missing registration fields"}
        try:
            pa_bytes = bytes.fromhex(pa_hex)
            if len(pa_bytes) != 32:
                raise ValueError("P_A must be 256-bit (32 bytes)")
        except Exception as e:
            return {"status": "error", "message": f"Invalid P_A: {e}"}

        reg_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.lock:
            self.users[id_a] = {
                "ID_A": id_a,
                "P_A": pa_hex,
                "salt_A": salt_hex,
                "contact": contact,
                "device": device,
                "registered_at": reg_time,
            }
            self.save_data()

        self.on_log(
            f"[PHASE 1 - REGISTER] {addr[0]} | User '{id_a}' ({device}) registered. "
            f"P_A={pa_hex[:16]}... | Contact={contact}",
            "ok",
        )
        self.on_users_changed()
        return {
            "status": "ok",
            "message": f"Registered user '{id_a}' successfully",
            "cert_b": self.get_cert_b(),
        }

    # --------------------------------------------------------------------------
    # Phase 2, Steps 1-2: Receive (ID_A, req), generate 6-digit OTP N1
    # --------------------------------------------------------------------------
    def _handle_auth_request(self, req: dict, addr) -> dict:
        id_a = req.get("ID_A", "").strip()
        device = req.get("device", "Unknown")

        with self.lock:
            user = self.users.get(id_a)
            if not user:
                self.on_log(
                    f"[PHASE 2 - REQ] Rejected unknown user '{id_a}' from {addr[0]}",
                    "err",
                )
                return {"status": "error", "message": f"User '{id_a}' is not registered"}

            n1 = ecc.generate_otp_6digits()
            now_ts = int(time.time())
            self.pending_otps[id_a] = {
                "otp": n1,
                "ts_issued": now_ts,
                "used": False,
            }
            contact = user["contact"]
            salt_hex = user.get("salt_A", "")

        self.on_log(
            f"[PHASE 2 - STEP 1-2] Auth request from '{id_a}' ({device}, {addr[0]}). "
            f"Generated 6-digit OTP N1={n1} -> sent via out-of-band ({contact}).",
            "info",
        )
        self.on_otp(id_a, contact, n1, OTP_TTL_SECONDS)

        return {
            "status": "ok",
            "message": f"OTP N1 sent via {contact}",
            "contact": contact,
            "salt_A": salt_hex,
            "cert_b": self.get_cert_b(),
            "otp_ttl": OTP_TTL_SECONDS,
        }

    # --------------------------------------------------------------------------
    # Phase 2, Steps 3-8: Verify ts1, decrypt Q, derive KS, check MAC_A, verify H-chain
    # --------------------------------------------------------------------------
    def _handle_auth_verify(self, req: dict, addr) -> dict:
        t_start = time.perf_counter()

        id_a = req.get("ID_A", "").strip()
        ts1 = req.get("ts1")
        c1_hex = req.get("C1", "")
        c2_hex = req.get("C2", "")
        ct_hex = req.get("CT", "")
        mac_hex = req.get("MAC_A", "")

        with self.lock:
            user = self.users.get(id_a)
            otp_rec = self.pending_otps.get(id_a)

        if not user or not otp_rec:
            self.on_log(
                f"[PHASE 2 - VERIFY] Rejected '{id_a}': no active OTP session.", "err"
            )
            return {"status": "fail", "reason": "No active OTP session / unknown user"}

        if otp_rec["used"]:
            self.on_log(
                f"[PHASE 2 - VERIFY] Rejected '{id_a}': OTP N1 already used (replay attempt).",
                "err",
            )
            return {"status": "fail", "reason": "OTP already used (possible replay attack)"}

        # Step 3: Check timestamp freshness |ts_now - ts1| <= delta_t and OTP TTL
        ts_now = int(time.time())
        if ts1 is None or abs(ts_now - int(ts1)) > self.delta_t:
            self.on_log(
                f"[PHASE 2 - STEP 3] Timestamp check FAILED for '{id_a}': "
                f"ts1={ts1}, ts_now={ts_now}, Δt={self.delta_t}s -> Abort session.",
                "err",
            )
            return {
                "status": "fail",
                "reason": f"Timestamp expired/invalid (|ts_now - ts1| > {self.delta_t}s)",
            }

        if (ts_now - otp_rec["ts_issued"]) > OTP_TTL_SECONDS:
            self.on_log(
                f"[PHASE 2 - STEP 3] OTP N1 expired for '{id_a}' (> {OTP_TTL_SECONDS}s).",
                "err",
            )
            return {"status": "fail", "reason": "OTP N1 expired"}

        self.on_log(
            f"[PHASE 2 - STEP 3] Timestamp OK for '{id_a}' (|Δ|={abs(ts_now - int(ts1))}s <= {self.delta_t}s).",
            "info",
        )

        # Step 4: Decrypt Q = C2 - d_B * C1
        try:
            c1 = ecc.hex_to_point(c1_hex)
            c2 = ecc.hex_to_point(c2_hex)
            ct_bytes = bytes.fromhex(ct_hex)
            mac_bytes = bytes.fromhex(mac_hex)
            q_point = ecc.elgamal_decrypt_point(c1, c2, self.d_b)
        except Exception as e:
            self.on_log(f"[PHASE 2 - STEP 4] ECC point decryption error: {e}", "err")
            return {"status": "fail", "reason": f"Invalid ECC points: {e}"}

        # Step 5: Compute KS = SHA3-256(N1 || Q)
        n1 = otp_rec["otp"]
        ks = ecc.compute_session_key(n1, q_point)

        # Step 6: Verify MAC_A = HMAC-SHA3-256(KS, CT || C1 || C2 || ts1 || ID_A)
        mac_ok = ecc.verify_mac(ks, ct_bytes, c1, c2, int(ts1), id_a, mac_bytes)
        if not mac_ok:
            self.on_log(
                f"[PHASE 2 - STEP 6] MAC_A verification FAILED for '{id_a}' "
                f"(wrong OTP N1 or tampered message) -> Abort session.",
                "err",
            )
            return {
                "status": "fail",
                "reason": "MAC_A verification failed (wrong OTP N1 or integrity error)",
            }

        self.on_log(
            f"[PHASE 2 - STEP 4-6] Decrypted Q, derived KS={ks.hex()[:16]}..., MAC_A VALID.",
            "info",
        )

        # Mark OTP as used (prevents replay of the same OTP)
        with self.lock:
            self.pending_otps[id_a]["used"] = True

        # Step 7: Recover R = CT XOR KS
        r_bytes = ecc.xor_bytes(ct_bytes, ks)

        # Step 8: Iteratively hash R with SHA3-256 up to 256 times to match P_A
        pa_target = bytes.fromhex(user["P_A"])
        chain_ok, steps_found = ecc.verify_hash_chain(r_bytes, pa_target, ecc.HASH_CHAIN_LEN)
        elapsed_ms = (time.perf_counter() - t_start) * 1000.0

        if chain_ok:
            t_used = ecc.HASH_CHAIN_LEN - steps_found
            self.on_log(
                f"[PHASE 2 - STEP 7-8] SUCCESS! Hash chain matched P_A after {steps_found} hashes "
                f"(client t={t_used}). Alice '{id_a}' AUTHENTICATED in {elapsed_ms:.2f} ms.",
                "ok",
            )
            return {
                "status": "ok",
                "message": f"Alice '{id_a}' authenticated successfully!",
                "hash_steps_server": steps_found,
                "client_t_inferred": t_used,
                "server_time_ms": round(elapsed_ms, 3),
            }
        else:
            self.on_log(
                f"[PHASE 2 - STEP 8] FAILED! Hash chain did not reach P_A for '{id_a}' "
                f"(wrong password PW_A). Elapsed: {elapsed_ms:.2f} ms.",
                "err",
            )
            return {
                "status": "fail",
                "reason": "Hash chain verification failed (invalid password PW_A)",
                "server_time_ms": round(elapsed_ms, 3),
            }


# ==============================================================================
# Server Tkinter GUI
# ==============================================================================
class ServerGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.lang = "vi"
        self.latest_otp_info: Optional[tuple] = None

        self.engine = AuthServerEngine(
            on_log=self._log_threadsafe,
            on_otp=self._otp_threadsafe,
            on_users_changed=self._refresh_users_threadsafe,
        )

        self.root.geometry("920x700")
        self.root.minsize(840, 620)

        self._setup_styles()
        self._build_ui()
        self._apply_language()
        self._refresh_users_table()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _setup_styles(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Header.TLabel", font=("Segoe UI", 12, "bold"), foreground="#1B365D")
        style.configure("Banner.TLabel", font=("Segoe UI", 9, "italic"), foreground="#4A5568")
        style.configure("OTP.TLabel", font=("Consolas", 12, "bold"), foreground="#B91C1C")
        style.configure("Accent.TButton", font=("Segoe UI", 9, "bold"))

    def _build_ui(self) -> None:
        # Top bar: Title + Language Switcher
        top_bar = ttk.Frame(self.root, padding=(10, 8, 10, 4))
        top_bar.pack(fill=tk.X)

        self.lbl_header = ttk.Label(top_bar, style="Header.TLabel")
        self.lbl_header.pack(side=tk.LEFT)

        lang_frame = ttk.Frame(top_bar)
        lang_frame.pack(side=tk.RIGHT)
        self.lbl_lang = ttk.Label(lang_frame)
        self.lbl_lang.pack(side=tk.LEFT, padx=(0, 6))
        self.lang_var = tk.StringVar(value="Tiếng Việt")
        self.lang_combo = ttk.Combobox(
            lang_frame,
            textvariable=self.lang_var,
            values=["Tiếng Việt", "English"],
            state="readonly",
            width=12,
        )
        self.lang_combo.pack(side=tk.LEFT)
        self.lang_combo.bind("<<ComboboxSelected>>", self._on_lang_change)

        self.lbl_banner = ttk.Label(self.root, style="Banner.TLabel", padding=(10, 0, 10, 4))
        self.lbl_banner.pack(fill=tk.X)

        # Config Frame
        self.frm_cfg = ttk.LabelFrame(self.root, padding=10)
        self.frm_cfg.pack(fill=tk.X, padx=10, pady=4)

        row1 = ttk.Frame(self.frm_cfg)
        row1.pack(fill=tk.X, pady=(0, 6))

        self.lbl_host = ttk.Label(row1)
        self.lbl_host.pack(side=tk.LEFT)
        self.ent_host = ttk.Entry(row1, width=15)
        self.ent_host.insert(0, "127.0.0.1")
        self.ent_host.pack(side=tk.LEFT, padx=(4, 12))

        self.lbl_port = ttk.Label(row1)
        self.lbl_port.pack(side=tk.LEFT)
        self.ent_port = ttk.Entry(row1, width=7)
        self.ent_port.insert(0, "9999")
        self.ent_port.pack(side=tk.LEFT, padx=(4, 12))

        self.lbl_dt = ttk.Label(row1)
        self.lbl_dt.pack(side=tk.LEFT)
        self.ent_dt = ttk.Entry(row1, width=6)
        self.ent_dt.insert(0, "30")
        self.ent_dt.pack(side=tk.LEFT, padx=(4, 14))

        self.btn_start = ttk.Button(row1, style="Accent.TButton", command=self._toggle_server)
        self.btn_start.pack(side=tk.LEFT, padx=(0, 10))

        self.lbl_status_val = ttk.Label(row1, font=("Segoe UI", 9, "bold"), foreground="#B91C1C")
        self.lbl_status_val.pack(side=tk.LEFT)

        row2 = ttk.Frame(self.frm_cfg)
        row2.pack(fill=tk.X)
        self.lbl_pb = ttk.Label(row2)
        self.lbl_pb.pack(side=tk.LEFT)
        self.ent_pb = ttk.Entry(row2, state="readonly", font=("Consolas", 9))
        self.ent_pb.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 8))
        self._update_pb_entry()

        self.btn_regen = ttk.Button(row2, command=self._on_regen_keys)
        self.btn_regen.pack(side=tk.RIGHT)

        # Out-of-band OTP Simulator Panel
        self.frm_otp = ttk.LabelFrame(self.root, padding=8)
        self.frm_otp.pack(fill=tk.X, padx=10, pady=4)
        self.lbl_otp_display = ttk.Label(self.frm_otp, style="OTP.TLabel")
        self.lbl_otp_display.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Registered Users Table
        self.frm_users = ttk.LabelFrame(self.root, padding=8)
        self.frm_users.pack(fill=tk.BOTH, expand=False, padx=10, pady=4)

        cols = ("id", "contact", "pa", "reg_time")
        self.tree = ttk.Treeview(self.frm_users, columns=cols, show="headings", height=5)
        self.tree.column("id", width=130)
        self.tree.column("contact", width=200)
        self.tree.column("pa", width=340)
        self.tree.column("reg_time", width=150)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        sb = ttk.Scrollbar(self.frm_users, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.LEFT, fill=tk.Y)

        btn_user_frame = ttk.Frame(self.frm_users, padding=(8, 0, 0, 0))
        btn_user_frame.pack(side=tk.RIGHT, fill=tk.Y)
        self.btn_del_user = ttk.Button(btn_user_frame, command=self._on_delete_user)
        self.btn_del_user.pack(anchor=tk.N)

        # Log Console
        self.frm_log = ttk.LabelFrame(self.root, padding=8)
        self.frm_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=(4, 10))

        self.txt_log = scrolledtext.ScrolledText(
            self.frm_log, height=12, font=("Consolas", 9), state="disabled", wrap=tk.WORD
        )
        self.txt_log.pack(fill=tk.BOTH, expand=True)
        self.txt_log.tag_config("info", foreground="#1E3A8A")
        self.txt_log.tag_config("ok", foreground="#15803D")
        self.txt_log.tag_config("warn", foreground="#B45309")
        self.txt_log.tag_config("err", foreground="#B91C1C")

        self.btn_clear_log = ttk.Button(self.frm_log, command=self._clear_log)
        self.btn_clear_log.pack(anchor=tk.E, pady=(4, 0))

    def _on_lang_change(self, _event=None) -> None:
        self.lang = "vi" if self.lang_var.get() == "Tiếng Việt" else "en"
        self._apply_language()

    def _apply_language(self) -> None:
        L = self.lang
        self.root.title(tr(L, "srv_title"))
        self.lbl_header.config(text=tr(L, "srv_title"))
        self.lbl_lang.config(text=tr(L, "lang_label"))
        self.lbl_banner.config(text=tr(L, "params_banner"))
        self.frm_cfg.config(text=tr(L, "srv_config"))
        self.lbl_host.config(text=tr(L, "srv_host"))
        self.lbl_port.config(text=tr(L, "srv_port"))
        self.lbl_dt.config(text=tr(L, "srv_delta_t"))
        self.lbl_pb.config(text=tr(L, "srv_pb_label"))
        self.btn_regen.config(text=tr(L, "srv_regen_key"))
        self.frm_otp.config(text=tr(L, "srv_otp_box"))
        self.frm_users.config(text=tr(L, "srv_users_box"))
        self.btn_del_user.config(text=tr(L, "srv_del_user"))
        self.frm_log.config(text=tr(L, "log_title"))
        self.btn_clear_log.config(text=tr(L, "clear_log"))

        self.tree.heading("id", text=tr(L, "col_id"))
        self.tree.heading("contact", text=tr(L, "col_contact"))
        self.tree.heading("pa", text=tr(L, "col_pa"))
        self.tree.heading("reg_time", text=tr(L, "col_reg_time"))

        if self.engine.running:
            self.btn_start.config(text=tr(L, "srv_stop"))
            self.lbl_status_val.config(text=f"● {tr(L, 'srv_running')}", foreground="#15803D")
        else:
            self.btn_start.config(text=tr(L, "srv_start"))
            self.lbl_status_val.config(text=f"● {tr(L, 'srv_stopped')}", foreground="#B91C1C")

        if self.latest_otp_info:
            id_a, contact, otp, ttl = self.latest_otp_info
            self.lbl_otp_display.config(
                text=tr(L, "srv_otp_latest", id_a=id_a, contact=contact, otp=otp, ttl=ttl)
            )
        else:
            self.lbl_otp_display.config(text=tr(L, "srv_otp_empty"))

    def _update_pb_entry(self) -> None:
        self.ent_pb.config(state="normal")
        self.ent_pb.delete(0, tk.END)
        self.ent_pb.insert(0, ecc.point_to_hex(self.engine.p_b))
        self.ent_pb.config(state="readonly")

    def _toggle_server(self) -> None:
        if not self.engine.running:
            try:
                host = self.ent_host.get().strip() or "127.0.0.1"
                port = int(self.ent_port.get().strip())
                dt = int(self.ent_dt.get().strip())
                self.engine.start(host, port, dt)
                self._append_log(tr(self.lang, "srv_started_log", host=host, port=port, dt=dt), "ok")
            except Exception as e:
                messagebox.showerror(tr(self.lang, "error"), str(e))
        else:
            self.engine.stop()
            self._append_log(tr(self.lang, "srv_stopped_log"), "warn")
        self._apply_language()

    def _on_regen_keys(self) -> None:
        if messagebox.askyesno(tr(self.lang, "warning"), tr(self.lang, "srv_regen_confirm")):
            self.engine.regenerate_keys(save=True)
            self._update_pb_entry()

    def _on_delete_user(self) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        id_a = self.tree.item(sel[0], "values")[0]
        self.engine.delete_user(id_a)
        self._append_log(f"[DB] Deleted user '{id_a}'.", "warn")

    def _refresh_users_table(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        with self.engine.lock:
            for id_a, u in self.engine.users.items():
                self.tree.insert(
                    "",
                    tk.END,
                    values=(id_a, u["contact"], u["P_A"][:36] + "...", u.get("registered_at", "")),
                )

    def _refresh_users_threadsafe(self) -> None:
        self.root.after(0, self._refresh_users_table)

    def _otp_threadsafe(self, id_a: str, contact: str, otp: str, ttl: int) -> None:
        def _upd():
            self.latest_otp_info = (id_a, contact, otp, ttl)
            self.lbl_otp_display.config(
                text=tr(self.lang, "srv_otp_latest", id_a=id_a, contact=contact, otp=otp, ttl=ttl)
            )
        self.root.after(0, _upd)

    def _log_threadsafe(self, msg: str, tag: str = "info") -> None:
        self.root.after(0, lambda: self._append_log(msg, tag))

    def _append_log(self, msg: str, tag: str = "info") -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.txt_log.config(state="normal")
        self.txt_log.insert(tk.END, f"[{ts}] {msg}\n", tag)
        self.txt_log.see(tk.END)
        self.txt_log.config(state="disabled")

    def _clear_log(self) -> None:
        self.txt_log.config(state="normal")
        self.txt_log.delete("1.0", tk.END)
        self.txt_log.config(state="disabled")

    def _on_close(self) -> None:
        self.engine.stop()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    ServerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
