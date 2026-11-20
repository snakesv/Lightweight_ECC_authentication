================================================================================
HƯỚNG DẪN SỬ DỤNG & ĐÓNG GÓI .EXE (TIẾNG VIỆT / ENGLISH)
Giải pháp Xác thực Hai nhân tố Hạng nhẹ dựa trên ECC NIST P-256 cho Văn phòng Thông minh
================================================================================

1. CẤU TRÚC TỆP TIN / FILE STRUCTURE
--------------------------------------------------------------------------------
- crypto_ecc.py  : Thư viện mật mã thuần Python (không cần cài thư viện ngoài):
                   NIST ECC P-256 (secp256r1), SHA3-256, PBKDF2-HMAC-SHA3-256,
                   HMAC-SHA3-256, ElGamal trên ECC, chuỗi băm H^(256).
- i18n.py        : Bộ ngôn ngữ song ngữ Tiếng Việt (VI) / Tiếng Anh (EN).
- server_app.py  : Chương trình Máy chủ Xác thực (Bob) có giao diện Tkinter.
- client_app.py  : Chương trình Máy trạm Người dùng (Alice) có giao diện Tkinter.
- build_exe.bat  : Kịch bản tự động đóng gói 2 tệp tin .exe trên Windows bằng PyInstaller.

2. CHẠY TRỰC TIẾP TỪ MÃ NGUỒN PYTHON / RUN DIRECTLY FROM PYTHON
--------------------------------------------------------------------------------
Yêu cầu: Python 3.8 trở lên (không cần cài thêm bất kỳ thư viện ngoài nào).
Bước 1: Mở terminal/cmd và chạy Máy chủ Bob:
        python server_app.py
        -> Nhấn "Khởi động Máy chủ" (Start Server).
Bước 2: Mở terminal/cmd khác và chạy Máy trạm Alice:
        python client_app.py
        -> Tab "Giai đoạn 1: Đăng ký": nhập ID_A, mật khẩu, Email/Mobile -> Nhấn Đăng ký.
        -> Tab "Giai đoạn 2: Xác thực": nhập ID_A, mật khẩu -> Nhấn Bước 1 (Nhận OTP N1).
        -> Xem mã OTP 6 chữ số hiển thị trên khung màu đỏ của Máy chủ Bob.
        -> Nhập mã OTP N1 vào Bước 2 trên Máy trạm Alice -> Nhấn Xác thực.
Bước 3: Chuyển đổi ngôn ngữ Tiếng Việt / English trực tiếp ở góc trên bên phải mỗi cửa sổ.

3. ĐÓNG GÓI THÀNH 2 TỆP TIN .EXE TRÊN WINDOWS 11 / WINDOWS SERVER 2022
--------------------------------------------------------------------------------
Bước 1: Giải nén toàn bộ thư mục này trên máy Windows đã cài Python 3.8+.
Bước 2: Nhấp đúp chuột vào tệp "build_exe.bat" (hoặc chạy trong Command Prompt).
Bước 3: Kịch bản sẽ tự cài PyInstaller và biên dịch 2 tệp tin độc lập trong thư mục dist\:
        - dist\SmartOffice_Server.exe  (Máy chủ Bob)
        - dist\SmartOffice_Client.exe  (Máy trạm Alice)
Hai tệp .exe này có thể sao chép và chạy trực tiếp trên bất kỳ máy Windows 64-bit nào
mà không cần cài đặt Python.
