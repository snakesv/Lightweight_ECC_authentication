"""
client_app.py
Smart Office User Client Workstation (Alice) — Lightweight ECC P-256 Protocol.
Supports Vietnamese & English GUI (Tkinter) + real TCP socket networking.

Run: python client_app.py
"""

import json
import os
import secrets
import socket
import struct
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, scrolledtext, ttk
from typing import Callable, Dict, Optional, Tuple

import crypto_ecc as ecc
from i18n import tr

KEYSTORE_FILE = "alice_client_keystore.json"


# ==============================================================================
# Framed JSON TCP Helpers
# ==============================================================================
def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def rpc_call(host: str, port: int, payload: dict, timeout: float = 15.0) -> dict:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        sock.sendall(struct.pack("!I", len(raw)) + raw)

        header = _recv_exact(sock, 4)
        if not header:
            raise ConnectionError("Server closed connection without response")
        (length,) = struct.unpack("!I", header)
        body = _recv_exact(sock, length)
        if not body:
            raise ConnectionError("Incomplete response from server")
        return json.loads(body.decode("utf-8"))


# ==============================================================================
# Authentication Client Core Engine (Alice)
# ==============================================================================
class AuthClientEngine:
    def __init__(
        self,
        keystore_file: str = KEYSTORE_FILE,
        on_log: Optional[Callable[[str, str], None]] = None,
    ):
        self.keystore_file = keystore_file
        self.on_log = on_log or (lambda msg, tag="info": None)
        self.keystore: Dict[str, dict] = self._load_keystore()
        self.active_cert_b: Optional[dict] = None
        self.active_salt_hex: Optional[str] = None

    def _load_keystore(self) -> Dict[str, dict]:
        if os.path.exists(self.keystore_file):
            try:
                with open(self.keystore_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_keystore(self) -> None:
        with open(self.keystore_file, "w", encoding="utf-8") as f:
            json.dump(self.keystore, f, indent=2, ensure_ascii=False)

    def ping(self, host: str, port: int) -> dict:
        resp = rpc_call(host, port, {"action": "ping"})
        if resp.get("status") == "ok" and "cert_b" in resp:
            self.active_cert_b = resp["cert_b"]
        return resp

    # --------------------------------------------------------------------------
    # Phase 1: Registration (Secure Channel)
    # --------------------------------------------------------------------------
    def register(
        self, host: str, port: int, id_a: str, password: str, contact: str, device: str
    ) -> Tuple[dict, float]:
        t0 = time.perf_counter()
        salt = secrets.token_bytes(16)
        x_a = ecc.derive_secret_xa(password, salt)
        p_a = ecc.hash_chain(x_a, ecc.HASH_CHAIN_LEN)
        client_ms = (time.perf_counter() - t0) * 1000.0

        self.on_log(
            f"[PHASE 1] Computed x_A = PBKDF2-SHA3-256(PW_A, salt_A) & "
            f"P_A = H^(256)(x_A) = {p_a.hex()[:20]}... ({client_ms:.2f} ms)",
            "info",
        )

        payload = {
            "action": "register",
            "ID_A": id_a,
            "P_A": p_a.hex(),
            "salt_A": salt.hex(),
            "contact": contact,
            "device": device,
        }
        resp = rpc_call(host, port, payload)
        if resp.get("status") == "ok":
            self.keystore[id_a] = {
                "salt_A": salt.hex(),
                "contact": contact,
                "cert_b": resp.get("cert_b"),
            }
            self._save_keystore()
            self.active_cert_b = resp.get("cert_b")
            self.on_log(
                f"[PHASE 1] Registration succeeded for '{id_a}'. Saved salt_A & Cert_B locally.",
                "ok",
            )
        else:
            self.on_log(f"[PHASE 1] Registration failed: {resp.get('message')}", "err")
        return resp, client_ms

    # --------------------------------------------------------------------------
    # Phase 2, Steps 1-2: Request OTP N1 and receive Cert_B
    # --------------------------------------------------------------------------
    def request_otp(self, host: str, port: int, id_a: str, device: str) -> dict:
        self.on_log(f"[PHASE 2 - STEP 1] Sending auth request (ID_A='{id_a}', req) to Bob...", "info")
        resp = rpc_call(
            host,
            port,
            {"action": "auth_request", "ID_A": id_a, "device": device},
        )
        if resp.get("status") == "ok":
            self.active_cert_b = resp.get("cert_b")
            self.active_salt_hex = resp.get("salt_A") or self.keystore.get(id_a, {}).get("salt_A")
            self.on_log(
                f"[PHASE 2 - STEP 2] Received Cert_B (P_B={self.active_cert_b['P_B'][:20]}...). "
                f"OTP N1 sent to {resp.get('contact')}.",
                "ok",
            )
        else:
            self.on_log(f"[PHASE 2 - STEP 1] Request failed: {resp.get('message')}", "err")
        return resp

    # --------------------------------------------------------------------------
    # Phase 2, Steps 3-10: Compute R, Q, C1, C2, KS, CT, MAC_A & send to Bob
    # --------------------------------------------------------------------------
    def authenticate(
        self, host: str, port: int, id_a: str, password: str, otp_n1: str
    ) -> Tuple[dict, float]:
        if not self.active_cert_b:
            raise ValueError("Missing server Cert_B. Run Step 1 (Request OTP) first.")

        salt_hex = self.active_salt_hex or self.keystore.get(id_a, {}).get("salt_A")
        if not salt_hex:
            raise ValueError(f"Missing salt_A for user '{id_a}'. Register first.")

        salt = bytes.fromhex(salt_hex)
        p_b = ecc.hex_to_point(self.active_cert_b["P_B"])

        # Start cryptographic computation timing (excluding network RTT)
        t_pbkdf0 = time.perf_counter()
        x_a = ecc.derive_secret_xa(password, salt)
        t_pbkdf_ms = (time.perf_counter() - t_pbkdf0) * 1000.0

        t_proto0 = time.perf_counter()
        # Step 3: Choose random 1 < t < 256  -> t in [2, 255]
        t_val = secrets.randbelow(ecc.HASH_CHAIN_LEN - 2) + 2

        # Step 4: R = H^(t)(x_A)
        r_hash = ecc.hash_chain(x_a, t_val)

        # Step 5-6: Choose random v in [1, N-1], compute Q = v * G
        v = secrets.randbelow(ecc.N - 1) + 1
        q_point = ecc.scalar_mult(v, ecc.G)

        # Step 7: Choose random r in [1, N-1], compute C1 = r*G, C2 = r*P_B + Q
        _, c1, c2 = ecc.elgamal_encrypt_point(q_point, p_b)

        # Step 8: KS = SHA3-256(N1 || Q)
        ks = ecc.compute_session_key(otp_n1, q_point)

        # Step 9: CT = KS XOR R
        ct = ecc.xor_bytes(ks, r_hash)

        # Step 10: MAC_A = HMAC-SHA3-256(KS, CT || C1 || C2 || ts1 || ID_A)
        ts1 = int(time.time())
        mac_a = ecc.compute_mac(ks, ct, c1, c2, ts1, id_a)

        proto_ms = (time.perf_counter() - t_proto0) * 1000.0

        self.on_log(
            f"[PHASE 2 - STEP 3-10] t={t_val} | R={r_hash.hex()[:16]}... | "
            f"KS={ks.hex()[:16]}... | MAC_A={mac_a.hex()[:16]}... | ts1={ts1}",
            "info",
        )
        self.on_log(
            f"[TIMING] PBKDF2-SHA3-256: {t_pbkdf_ms:.2f} ms | "
            f"ECC+Hash+HMAC (Steps 3-10): {proto_ms:.2f} ms",
            "info",
        )

        payload = {
            "action": "auth_verify",
            "ID_A": id_a,
            "ts1": ts1,
            "C1": ecc.point_to_hex(c1),
            "C2": ecc.point_to_hex(c2),
            "CT": ct.hex(),
            "MAC_A": mac_a.hex(),
        }
        resp = rpc_call(host, port, payload)
        if resp.get("status") == "ok":
            self.on_log(
                f"[RESULT] AUTHENTICATION SUCCESS! Server verified in "
                f"{resp.get('server_time_ms', 0):.2f} ms (server hash steps={resp.get('hash_steps_server')}).",
                "ok",
            )
        else:
            self.on_log(
                f"[RESULT] AUTHENTICATION FAILED: {resp.get('reason') or resp.get('message')}",
                "err",
            )
        return resp, proto_ms


# ==============================================================================
# Client Tkinter GUI
# ==============================================================================
class ClientGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.lang = "vi"
        self.last_result_state = "waiting"  # "waiting" | "ok" | "fail"
        self.last_result_detail = ""

        self.engine = AuthClientEngine(on_log=self._log_threadsafe)

        self.root.geometry("860x710")
        self.root.minsize(780, 630)

        self._setup_styles()
        self._build_ui()
        self._apply_language()

    def _setup_styles(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Header.TLabel", font=("Segoe UI", 12, "bold"), foreground="#0F4C5C")
        style.configure("Banner.TLabel", font=("Segoe UI", 9, "italic"), foreground="#4A5568")
        style.configure("Accent.TButton", font=("Segoe UI", 9, "bold"))
        style.configure("ResultWait.TLabel", font=("Segoe UI", 10, "bold"), foreground="#4A5568")
        style.configure("ResultOK.TLabel", font=("Segoe UI", 10, "bold"), foreground="#15803D")
        style.configure("ResultFail.TLabel", font=("Segoe UI", 10, "bold"), foreground="#B91C1C")

    def _build_ui(self) -> None:
        # Top bar
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

        # Connection settings
        self.frm_conn = ttk.LabelFrame(self.root, padding=8)
        self.frm_conn.pack(fill=tk.X, padx=10, pady=4)

        self.lbl_srv_ip = ttk.Label(self.frm_conn)
        self.lbl_srv_ip.pack(side=tk.LEFT)
        self.ent_ip = ttk.Entry(self.frm_conn, width=15)
        self.ent_ip.insert(0, "127.0.0.1")
        self.ent_ip.pack(side=tk.LEFT, padx=(4, 12))

        self.lbl_srv_port = ttk.Label(self.frm_conn)
        self.lbl_srv_port.pack(side=tk.LEFT)
        self.ent_port = ttk.Entry(self.frm_conn, width=7)
        self.ent_port.insert(0, "9999")
        self.ent_port.pack(side=tk.LEFT, padx=(4, 12))

        self.lbl_device = ttk.Label(self.frm_conn)
        self.lbl_device.pack(side=tk.LEFT)
        self.dev_var = tk.StringVar(value="Laptop")
        self.cmb_dev = ttk.Combobox(
            self.frm_conn,
            textvariable=self.dev_var,
            values=["Laptop", "Desktop", "Mobile Phone", "Tablet"],
            state="readonly",
            width=13,
        )
        self.cmb_dev.pack(side=tk.LEFT, padx=(4, 12))

        self.btn_ping = ttk.Button(self.frm_conn, command=self._on_ping)
        self.btn_ping.pack(side=tk.RIGHT)

        # Notebook with Phase 1 & Phase 2 tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.X, padx=10, pady=6)

        # --- Tab 1: Phase 1 Registration ---
        self.tab1 = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(self.tab1, text="Phase 1")

        grid1 = ttk.Frame(self.tab1)
        grid1.pack(fill=tk.X)

        self.lbl_p1_id = ttk.Label(grid1)
        self.lbl_p1_id.grid(row=0, column=0, sticky=tk.W, pady=4)
        self.ent_p1_id = ttk.Entry(grid1, width=30)
        self.ent_p1_id.insert(0, "alice")
        self.ent_p1_id.grid(row=0, column=1, sticky=tk.W, padx=8, pady=4)

        self.lbl_p1_pw = ttk.Label(grid1)
        self.lbl_p1_pw.grid(row=1, column=0, sticky=tk.W, pady=4)
        self.ent_p1_pw = ttk.Entry(grid1, width=30, show="*")
        self.ent_p1_pw.grid(row=1, column=1, sticky=tk.W, padx=8, pady=4)

        self.show_p1_pw_var = tk.BooleanVar(value=False)
        self.chk_p1_pw = ttk.Checkbutton(
            grid1, variable=self.show_p1_pw_var, command=self._toggle_p1_pw
        )
        self.chk_p1_pw.grid(row=1, column=2, sticky=tk.W, padx=4)

        self.lbl_p1_contact = ttk.Label(grid1)
        self.lbl_p1_contact.grid(row=2, column=0, sticky=tk.W, pady=4)
        self.ent_p1_contact = ttk.Entry(grid1, width=30)
        self.ent_p1_contact.insert(0, "alice@smartoffice.vn")
        self.ent_p1_contact.grid(row=2, column=1, sticky=tk.W, padx=8, pady=4)

        self.btn_register = ttk.Button(grid1, style="Accent.TButton", command=self._on_register)
        self.btn_register.grid(row=3, column=1, sticky=tk.W, padx=8, pady=(10, 4))

        self.lbl_p1_note = ttk.Label(self.tab1, wraplength=780, foreground="#4A5568")
        self.lbl_p1_note.pack(fill=tk.X, pady=(6, 0))

        # --- Tab 2: Phase 2 Authentication ---
        self.tab2 = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(self.tab2, text="Phase 2")

        self.frm_s1 = ttk.LabelFrame(self.tab2, padding=8)
        self.frm_s1.pack(fill=tk.X, pady=(0, 6))

        self.lbl_p2_id = ttk.Label(self.frm_s1)
        self.lbl_p2_id.grid(row=0, column=0, sticky=tk.W, pady=3)
        self.ent_p2_id = ttk.Entry(self.frm_s1, width=22)
        self.ent_p2_id.insert(0, "alice")
        self.ent_p2_id.grid(row=0, column=1, sticky=tk.W, padx=6, pady=3)

        self.lbl_p2_pw = ttk.Label(self.frm_s1)
        self.lbl_p2_pw.grid(row=0, column=2, sticky=tk.W, padx=(12, 0), pady=3)
        self.ent_p2_pw = ttk.Entry(self.frm_s1, width=22, show="*")
        self.ent_p2_pw.grid(row=0, column=3, sticky=tk.W, padx=6, pady=3)

        self.show_p2_pw_var = tk.BooleanVar(value=False)
        self.chk_p2_pw = ttk.Checkbutton(
            self.frm_s1, variable=self.show_p2_pw_var, command=self._toggle_p2_pw
        )
        self.chk_p2_pw.grid(row=0, column=4, sticky=tk.W, padx=4)

        self.btn_req_otp = ttk.Button(self.frm_s1, style="Accent.TButton", command=self._on_req_otp)
        self.btn_req_otp.grid(row=1, column=0, columnspan=4, sticky=tk.W, pady=(8, 2))

        self.frm_s2 = ttk.LabelFrame(self.tab2, padding=8)
        self.frm_s2.pack(fill=tk.X, pady=(0, 6))

        self.lbl_otp = ttk.Label(self.frm_s2)
        self.lbl_otp.pack(side=tk.LEFT)
        self.ent_otp = ttk.Entry(self.frm_s2, width=12, font=("Consolas", 11, "bold"))
        self.ent_otp.pack(side=tk.LEFT, padx=(6, 14))

        self.btn_auth = ttk.Button(self.frm_s2, style="Accent.TButton", command=self._on_authenticate)
        self.btn_auth.pack(side=tk.LEFT)

        res_row = ttk.Frame(self.tab2)
        res_row.pack(fill=tk.X, pady=(4, 0))
        self.lbl_res_title = ttk.Label(res_row)
        self.lbl_res_title.pack(side=tk.LEFT)
        self.lbl_res_val = ttk.Label(res_row, style="ResultWait.TLabel")
        self.lbl_res_val.pack(side=tk.LEFT, padx=8)

        # Log Console
        self.frm_log = ttk.LabelFrame(self.root, padding=8)
        self.frm_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=(2, 10))

        self.txt_log = scrolledtext.ScrolledText(
            self.frm_log, height=13, font=("Consolas", 9), state="disabled", wrap=tk.WORD
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
        self.root.title(tr(L, "cli_title"))
        self.lbl_header.config(text=tr(L, "cli_title"))
        self.lbl_lang.config(text=tr(L, "lang_label"))
        self.lbl_banner.config(text=tr(L, "params_banner"))
        self.frm_conn.config(text=tr(L, "cli_conn_box"))
        self.lbl_srv_ip.config(text=tr(L, "cli_srv_ip"))
        self.lbl_srv_port.config(text=tr(L, "cli_srv_port"))
        self.lbl_device.config(text=tr(L, "cli_device"))
        self.btn_ping.config(text=tr(L, "cli_ping"))

        self.notebook.tab(self.tab1, text=tr(L, "tab_phase1"))
        self.notebook.tab(self.tab2, text=tr(L, "tab_phase2"))

        self.lbl_p1_id.config(text=tr(L, "lbl_id_a"))
        self.lbl_p1_pw.config(text=tr(L, "lbl_pw_a"))
        self.chk_p1_pw.config(text=tr(L, "lbl_show_pw"))
        self.lbl_p1_contact.config(text=tr(L, "lbl_contact"))
        self.btn_register.config(text=tr(L, "btn_register"))
        self.lbl_p1_note.config(text=tr(L, "p1_note"))

        self.frm_s1.config(text=tr(L, "p2_step1_box"))
        self.lbl_p2_id.config(text=tr(L, "lbl_id_a"))
        self.lbl_p2_pw.config(text=tr(L, "lbl_pw_a"))
        self.chk_p2_pw.config(text=tr(L, "lbl_show_pw"))
        self.btn_req_otp.config(text=tr(L, "btn_req_otp"))

        self.frm_s2.config(text=tr(L, "p2_step2_box"))
        self.lbl_otp.config(text=tr(L, "lbl_otp"))
        self.btn_auth.config(text=tr(L, "btn_auth"))

        self.lbl_res_title.config(text=tr(L, "lbl_result"))
        self._render_result_label()

        self.frm_log.config(text=tr(L, "log_title"))
        self.btn_clear_log.config(text=tr(L, "clear_log"))

    def _render_result_label(self) -> None:
        L = self.lang
        if self.last_result_state == "ok":
            txt = tr(L, "res_ok") + (f" ({self.last_result_detail})" if self.last_result_detail else "")
            self.lbl_res_val.config(text=txt, style="ResultOK.TLabel")
        elif self.last_result_state == "fail":
            txt = tr(L, "res_fail") + (f" ({self.last_result_detail})" if self.last_result_detail else "")
            self.lbl_res_val.config(text=txt, style="ResultFail.TLabel")
        else:
            self.lbl_res_val.config(text=tr(L, "res_waiting"), style="ResultWait.TLabel")

    def _toggle_p1_pw(self) -> None:
        self.ent_p1_pw.config(show="" if self.show_p1_pw_var.get() else "*")

    def _toggle_p2_pw(self) -> None:
        self.ent_p2_pw.config(show="" if self.show_p2_pw_var.get() else "*")

    def _get_endpoint(self) -> Tuple[str, int]:
        return self.ent_ip.get().strip() or "127.0.0.1", int(self.ent_port.get().strip())

    def _on_ping(self) -> None:
        def _worker():
            try:
                host, port = self._get_endpoint()
                resp = self.engine.ping(host, port)
                if resp.get("status") == "ok":
                    self._log_threadsafe(
                        f"[PING] Connected to {host}:{port}. P_B={resp['cert_b']['P_B'][:24]}...",
                        "ok",
                    )
                    self.root.after(0, lambda: messagebox.showinfo(tr(self.lang, "success"), tr(self.lang, "conn_ok")))
                else:
                    raise RuntimeError(resp.get("message", "Unknown error"))
            except Exception as e:
                self._log_threadsafe(f"[PING] Failed: {e}", "err")
                self.root.after(
                    0,
                    lambda err=e: messagebox.showerror(tr(self.lang, "error"), tr(self.lang, "conn_fail", err=err)),
                )
        threading.Thread(target=_worker, daemon=True).start()

    def _on_register(self) -> None:
        id_a = self.ent_p1_id.get().strip()
        pw = self.ent_p1_pw.get()
        contact = self.ent_p1_contact.get().strip()
        device = self.dev_var.get()
        if not id_a or not pw or not contact:
            messagebox.showwarning(tr(self.lang, "warning"), tr(self.lang, "err_fill_fields"))
            return

        def _worker():
            try:
                host, port = self._get_endpoint()
                resp, ms = self.engine.register(host, port, id_a, pw, contact, device)
                if resp.get("status") == "ok":
                    # Sync ID_A into Phase 2 tab for convenience
                    self.root.after(0, lambda: self._sync_p2_id(id_a))
                    self.root.after(
                        0,
                        lambda: messagebox.showinfo(
                            tr(self.lang, "success"),
                            tr(self.lang, "reg_success_msg", id_a=id_a, ms=ms),
                        ),
                    )
                else:
                    self.root.after(
                        0,
                        lambda: messagebox.showerror(tr(self.lang, "error"), resp.get("message", "Error")),
                    )
            except Exception as e:
                self._log_threadsafe(f"[PHASE 1] Error: {e}", "err")
                self.root.after(
                    0,
                    lambda err=e: messagebox.showerror(tr(self.lang, "error"), tr(self.lang, "conn_fail", err=err)),
                )
        threading.Thread(target=_worker, daemon=True).start()

    def _sync_p2_id(self, id_a: str) -> None:
        self.ent_p2_id.delete(0, tk.END)
        self.ent_p2_id.insert(0, id_a)

    def _on_req_otp(self) -> None:
        id_a = self.ent_p2_id.get().strip()
        pw = self.ent_p2_pw.get()
        device = self.dev_var.get()
        if not id_a or not pw:
            messagebox.showwarning(tr(self.lang, "warning"), tr(self.lang, "err_fill_auth1"))
            return

        def _worker():
            try:
                host, port = self._get_endpoint()
                resp = self.engine.request_otp(host, port, id_a, device)
                if resp.get("status") == "ok":
                    contact = resp.get("contact", "Email/Mobile")
                    self.root.after(
                        0,
                        lambda: messagebox.showinfo(
                            tr(self.lang, "info"),
                            tr(self.lang, "otp_req_ok", contact=contact),
                        ),
                    )
                else:
                    self.root.after(
                        0,
                        lambda: messagebox.showerror(tr(self.lang, "error"), resp.get("message", "Error")),
                    )
            except Exception as e:
                self._log_threadsafe(f"[PHASE 2] OTP Request Error: {e}", "err")
                self.root.after(
                    0,
                    lambda err=e: messagebox.showerror(tr(self.lang, "error"), tr(self.lang, "conn_fail", err=err)),
                )
        threading.Thread(target=_worker, daemon=True).start()

    def _on_authenticate(self) -> None:
        id_a = self.ent_p2_id.get().strip()
        pw = self.ent_p2_pw.get()
        otp = self.ent_otp.get().strip()
        if not id_a or not pw or len(otp) != 6 or not otp.isdigit():
            messagebox.showwarning(tr(self.lang, "warning"), tr(self.lang, "err_fill_otp"))
            return

        def _worker():
            try:
                host, port = self._get_endpoint()
                resp, cli_ms = self.engine.authenticate(host, port, id_a, pw, otp)
                if resp.get("status") == "ok":
                    srv_ms = resp.get("server_time_ms", 0.0)
                    self.last_result_state = "ok"
                    self.last_result_detail = f"Client: {cli_ms:.2f} ms | Server: {srv_ms:.2f} ms"
                else:
                    self.last_result_state = "fail"
                    self.last_result_detail = resp.get("reason") or resp.get("message", "")
                self.root.after(0, self._render_result_label)
            except Exception as e:
                self.last_result_state = "fail"
                self.last_result_detail = str(e)
                self._log_threadsafe(f"[PHASE 2] Auth Error: {e}", "err")
                self.root.after(0, self._render_result_label)
        threading.Thread(target=_worker, daemon=True).start()

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


def main() -> None:
    root = tk.Tk()
    ClientGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
