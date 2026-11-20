================================================================================
USER GUIDE & .EXE PACKAGING (VIETNAMESE / ENGLISH)
Lightweight Two-Factor Authentication Solution Based on ECC NIST P-256 for Smart Offices
================================================================================

1. FILE STRUCTURE
--------------------------------------------------------------------------------
- crypto_ecc.py  : Pure Python cryptographic library (no external dependencies required):
NIST ECC P-256 (secp256r1), SHA3-256, PBKDF2-HMAC-SHA3-256,
HMAC-SHA3-256, ElGamal over ECC, and H^(256) hash chains.
- i18n.py        : Bilingual language module (Vietnamese [VI] / English [EN]).
- server_app.py  : Authentication Server application (Bob) with a Tkinter-based GUI.
- client_app.py  : User Client application (Alice) with a Tkinter-based GUI.
- build_exe.bat  : Automated script to package the applications into .exe files on Windows using PyInstaller.

2. RUNNING DIRECTLY FROM PYTHON SOURCE CODE
--------------------------------------------------------------------------------
Requirements: Python 3.8 or higher (no additional external libraries required).
Step 1: Open a terminal/cmd and run the Server (Bob):
python server_app.py
-> Click "Start Server".
Step 2: Open another terminal/cmd and run the Client (Alice):
python client_app.py
-> In the "Phase 1: Registration" tab, enter ID_A, password, and Email/Mobile -> Click Register. -> "Phase 2: Authentication" tab: enter ID_A and password -> Click Step 1 (Receive OTP N1). 
-> Locate the 6-digit OTP displayed within the red box on the Bob Server interface. 
-> Enter the OTP N1 into Step 2 on the Alice Client interface -> Click Authenticate.
Step 3: Switch between Vietnamese and English languages ​​directly via the option in the top-right corner of each window.

3. PACKAGING INTO TWO .EXE FILES (WINDOWS 11 / WINDOWS SERVER 2022)
--------------------------------------------------------------------------------
Step 1: Extract this entire folder onto a Windows machine with Python 3.8+ installed.
Step 2: Double-click the "build_exe.bat" file (or execute it via Command Prompt).
Step 3: The script will automatically install PyInstaller and compile two standalone executable files in the `dist\` directory:
- dist\SmartOffice_Server.exe (Bob Server)
- dist\SmartOffice_Client.exe (Alice Client)
These two .exe files can be copied and run directly on any 64-bit Windows machine without requiring a Python installation.
