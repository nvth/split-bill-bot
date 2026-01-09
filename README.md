# Telegram VietQR Bot (Python)

Author: nvth

Teammate: Agent GPT-5.2-Codex

Bot Telegram tao VietQR (NAPAS), quan ly tai khoan va gui QR vao group.

## Cai dat

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

## Cau hinh

Tao file `.env` tu `.env.example`:

```
BOT_TOKEN=...
ENCRYPTION_KEY=...
```

Tao khoa ma hoa:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Luu y: doi khoa se khong giai ma duoc du lieu cu trong `bot.db`.

## Chay bot

```bash
python bot.py
```

## Su dung

- Dung `/start` trong chat rieng de mo menu.
- Lenh duy nhat tren menu Telegram: `/start`, `/help`, `/id`.
- `/id` chi dung trong group de lay chat id.

### Menu chinh

- Tao QR (tao QR, chia bill).
- Quan ly tai khoan (them tai khoan, chon mac dinh, danh sach).
- Quan ly nhom chat (them/xoa/dat mac dinh).

### Chia bill

- Nhap tong tien va noi dung (optional).
- Chon so nguoi, bot se hoi xac nhan truoc khi gui QR vao group.
- Noi dung QR la noi dung nguoi dung nhap (neu co).

## Group va QR

- Khi bot duoc them vao group, bot se tu dong luu chat id cho user do.
- Co the xem danh sach group va dat mac dinh trong menu.

## Anh nen QR

- Dat `bg.png` trong cung thu muc.
- Chinh vi tri/kich thuoc QR qua bang `settings` (BG_IMAGE_PATH, QR_PANEL_X, QR_PANEL_Y, QR_SIZE).

## Luu tru

- Bot luu thong tin trong SQLite (`bot.db`), du lieu nhay cam duoc ma hoa.
- Admin/allowed duoc luu trong bang `admin_users`, `allowed_users`.
