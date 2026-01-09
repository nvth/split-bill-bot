import logging
import os
import shlex
import sqlite3
import time
from io import BytesIO
from typing import Optional

from dotenv import load_dotenv
from cryptography.fernet import Fernet, InvalidToken
from PIL import Image, ImageDraw, ImageFont
from telegram import BotCommand, InputFile, InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (
    ApplicationBuilder,
    CallbackQueryHandler,
    ChatMemberHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters
)
import qrcode

load_dotenv()

logging.basicConfig(
    format='%(asctime)s %(levelname)s %(name)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

BOT_TOKEN = (os.getenv('BOT_TOKEN') or '').strip()
DB_PATH = (os.getenv('DB_PATH') or 'bot.db').strip()
ENCRYPTION_KEY = (os.getenv('ENCRYPTION_KEY') or '').strip()
SETTINGS: dict[str, str] = {}

if not ENCRYPTION_KEY:
    raise SystemExit('Missing ENCRYPTION_KEY in .env')

try:
    FERNET = Fernet(ENCRYPTION_KEY.encode())
except Exception:
    raise SystemExit('Invalid ENCRYPTION_KEY (must be a Fernet key).')

if not BOT_TOKEN:
    raise SystemExit('Missing BOT_TOKEN in .env')

BANKS = [
    ('Vietcombank', '970436'),
    ('VietinBank', '970415'),
    ('BIDV', '970418'),
    ('Agribank', '970405'),
    ('Techcombank', '970407'),
    ('ACB', '970416'),
    ('Sacombank', '970403'),
    ('MB', '970422'),
    ('TPBank', '970423'),
    ('VPBank', '970432'),
    ('VIB', '970441')
]


def tlv(tlv_id: str, value: str) -> str:
    length = str(len(value)).zfill(2)
    return f'{tlv_id}{length}{value}'


def crc16_ccitt_false(data: str) -> str:
    crc = 0xFFFF
    for ch in data:
        crc ^= ord(ch) << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return f'{crc:04X}'


def normalize_amount(raw: str) -> str:
    if not raw:
        return ''
    cleaned = ''.join(ch for ch in raw if ch.isdigit() or ch == '.')
    if not cleaned:
        return ''
    parts = cleaned.split('.')
    if len(parts) > 2:
        return ''
    if len(parts) == 2 and len(parts[1]) > 2:
        return ''
    return cleaned.lstrip('0') or '0'


def build_vietqr_payload(bank_bin: str, account_no: str, account_name: str, amount: str, purpose: str) -> str:
    clean_bank = (bank_bin or '').replace(' ', '')
    clean_account = (account_no or '').replace(' ', '')

    if not clean_bank or not clean_account:
        raise ValueError('Missing bank BIN or account number')
    if not clean_bank.isdigit() or len(clean_bank) not in (6, 8):
        raise ValueError('Invalid bank BIN (should be 6 or 8 digits)')
    if not clean_account.isdigit() or len(clean_account) < 6:
        raise ValueError('Invalid account number (digits only, min 6)')

    amount_str = normalize_amount(amount)
    merchant_name = (account_name or 'NA')[:25]
    purpose_str = (purpose or '')[:99]

    beneficiary = ''.join([
        tlv('00', clean_bank),
        tlv('01', clean_account)
    ])

    merchant_info = ''.join([
        tlv('00', 'A000000727'),
        tlv('01', beneficiary),
        tlv('02', 'QRIBFTTA')
    ])

    payload_parts = [
        tlv('00', '01'),
        tlv('01', '12' if amount_str else '11'),
        tlv('38', merchant_info),
        tlv('52', '0000'),
        tlv('53', '704'),
        tlv('54', amount_str) if amount_str else '',
        tlv('58', 'VN'),
        tlv('59', merchant_name),
        tlv('60', 'HANOI'),
        tlv('62', tlv('08', purpose_str)) if purpose_str else ''
    ]

    payload = ''.join(part for part in payload_parts if part)
    crc = crc16_ccitt_false(f'{payload}6304')
    return f'{payload}63' + '04' + crc


def build_help_message() -> str:
    return '\n'.join([
        'Cach dung:',
        'Dung /start de mo menu va quan ly tai khoan.',
        'Lenh /id chi dung trong group de lay chat id.'
    ])


def parse_args(text: str) -> list[str]:
    if not text:
        return []
    parts = shlex.split(text)
    if parts and parts[0].startswith('/'):
        return parts[1:]
    return parts


def parse_id_set(raw: str) -> set[str]:
    return {item.strip() for item in raw.split(',') if item.strip()}


def encrypt_value(value: str) -> str:
    if not value:
        return value
    if value.startswith('enc:'):
        return value
    token = FERNET.encrypt(value.encode()).decode()
    return f'enc:{token}'


def decrypt_value(value: str) -> str:
    if not value:
        return value
    if value.startswith('enc:'):
        token = value[4:]
        try:
            return FERNET.decrypt(token.encode()).decode()
        except InvalidToken:
            return ''
    return value


SETTINGS_DEFAULTS = {
    'DEFAULT_BANK_BIN': '',
    'DEFAULT_ACCOUNT_NO': '',
    'DEFAULT_ACCOUNT_NAME': '',
    'DEFAULT_BANK_NAME': '',
    'BG_IMAGE_PATH': 'bg.png',
    'QR_PANEL_X': '',
    'QR_PANEL_Y': '',
    'QR_SIZE': '',
    'DEBUG': 'false',
    'GROUP_CHAT_ID': ''
}


def get_setting(key: str, default: str = '') -> str:
    return SETTINGS.get(key, default)


def is_debug_enabled() -> bool:
    return get_setting('DEBUG', 'false').strip().lower() in ('1', 'true', 'yes', 'on')


def load_settings() -> None:
    SETTINGS.clear()
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute('SELECT key, value FROM settings').fetchall()
    for key, value in rows:
        SETTINGS[key] = value or ''


def seed_settings_from_env() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        for key, default_value in SETTINGS_DEFAULTS.items():
            env_value = (os.getenv(key) or '').strip()
            value = env_value if env_value else default_value
            conn.execute(
                'INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)',
                (key, value)
            )

def migrate_encrypted_data() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            'SELECT id, bank_name, bank_bin, account_no, account_name FROM accounts'
        ).fetchall()
        for account_id, bank_name, bank_bin, account_no, account_name in rows:
            if any(
                val and not str(val).startswith('enc:')
                for val in (bank_name, bank_bin, account_no, account_name)
            ):
                conn.execute(
                    '''
                    UPDATE accounts
                    SET bank_name = ?, bank_bin = ?, account_no = ?, account_name = ?
                    WHERE id = ?
                    ''',
                    (
                        encrypt_value(bank_name or ''),
                        encrypt_value(bank_bin or ''),
                        encrypt_value(account_no or ''),
                        encrypt_value(account_name or ''),
                        account_id
                    )
                )

        rows = conn.execute(
            'SELECT user_id, chat_id, chat_title FROM group_chats'
        ).fetchall()
        for user_id, chat_id, chat_title in rows:
            if chat_title and not str(chat_title).startswith('enc:'):
                conn.execute(
                    '''
                    UPDATE group_chats
                    SET chat_title = ?
                    WHERE user_id = ? AND chat_id = ?
                    ''',
                    (encrypt_value(chat_title), user_id, chat_id)
                )

        rows = conn.execute(
            'SELECT user_id, username, first_name FROM access_requests'
        ).fetchall()
        for user_id, username, first_name in rows:
            if any(
                val and not str(val).startswith('enc:')
                for val in (username, first_name)
            ):
                conn.execute(
                    '''
                    UPDATE access_requests
                    SET username = ?, first_name = ?
                    WHERE user_id = ?
                    ''',
                    (
                        encrypt_value(username or ''),
                        encrypt_value(first_name or ''),
                        user_id
                    )
                )


def is_admin_user(user_id: int) -> bool:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            'SELECT 1 FROM admin_users WHERE user_id = ?',
            (user_id,)
        ).fetchone()
    return row is not None


def is_allowed_user(update: Update) -> bool:
    user_id = update.effective_user.id
    if is_admin_user(user_id):
        return True
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            'SELECT 1 FROM allowed_users WHERE user_id = ?',
            (user_id,)
        ).fetchone()
    return row is not None


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
            '''
        )
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                bank_name TEXT,
                bank_bin TEXT,
                account_no TEXT,
                account_name TEXT,
                is_default INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER
            )
            '''
        )
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS group_chats (
                user_id INTEGER NOT NULL,
                chat_id INTEGER NOT NULL,
                is_default INTEGER NOT NULL DEFAULT 0,
                chat_title TEXT,
                created_at INTEGER,
                PRIMARY KEY (user_id, chat_id)
            )
            '''
        )
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS allowed_users (
                user_id INTEGER PRIMARY KEY,
                created_at INTEGER
            )
            '''
        )
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS admin_users (
                user_id INTEGER PRIMARY KEY,
                created_at INTEGER
            )
            '''
        )
        conn.execute(
            '''
            CREATE TABLE IF NOT EXISTS access_requests (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                created_at INTEGER
            )
            '''
        )

        table_exists = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='user_profile'"
        ).fetchone()
        if table_exists:
            rows = conn.execute(
                'SELECT user_id, bank_bin, account_no, account_name, bank_name FROM user_profile'
            ).fetchall()
            for row in rows:
                user_id, bank_bin, account_no, account_name, bank_name = row
                count = conn.execute(
                    'SELECT COUNT(*) FROM accounts WHERE user_id = ?',
                    (user_id,)
                ).fetchone()[0]
                if count == 0 and (bank_bin or account_no or account_name or bank_name):
                    conn.execute(
                        '''
                        INSERT INTO accounts (user_id, bank_name, bank_bin, account_no, account_name, is_default, created_at)
                        VALUES (?, ?, ?, ?, ?, 1, ?)
                        ''',
                        (
                            user_id,
                            bank_name or '',
                            bank_bin or '',
                            account_no or '',
                            account_name or '',
                            int(time.time())
                        )
                    )

        allowed_env = parse_id_set(os.getenv('ALLOWED_USER_IDS') or '')
        for user_id in allowed_env:
            conn.execute(
                'INSERT OR IGNORE INTO allowed_users (user_id, created_at) VALUES (?, ?)',
                (int(user_id), int(time.time()))
            )

        admin_env = parse_id_set(os.getenv('ADMIN_USER_IDS') or '')
        for user_id in admin_env:
            conn.execute(
                'INSERT OR IGNORE INTO admin_users (user_id, created_at) VALUES (?, ?)',
                (int(user_id), int(time.time()))
            )

        columns = {row[1] for row in conn.execute('PRAGMA table_info(group_chats)').fetchall()}
        if 'user_id' not in columns:
            admin_ids = sorted([int(uid) for uid in admin_env] or [0])
            default_owner = admin_ids[0]
            conn.execute(
                '''
                CREATE TABLE IF NOT EXISTS group_chats_new (
                    user_id INTEGER NOT NULL,
                    chat_id INTEGER NOT NULL,
                    is_default INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER,
                    PRIMARY KEY (user_id, chat_id)
                )
                '''
            )
            conn.execute(
                '''
                INSERT INTO group_chats_new (user_id, chat_id, is_default, created_at)
                SELECT ?, chat_id, is_default, created_at FROM group_chats
                ''',
                (default_owner,)
            )
            conn.execute('DROP TABLE group_chats')
            conn.execute('ALTER TABLE group_chats_new RENAME TO group_chats')
        columns = {row[1] for row in conn.execute('PRAGMA table_info(group_chats)').fetchall()}
        if 'chat_title' not in columns:
            conn.execute('ALTER TABLE group_chats ADD COLUMN chat_title TEXT')
        seed_settings_from_env()

    load_settings()
    migrate_encrypted_data()

    group_chat_id = get_setting('GROUP_CHAT_ID', '').strip()
    if group_chat_id:
        admin_ids = sorted([int(uid) for uid in parse_id_set(os.getenv('ADMIN_USER_IDS') or '')] or [0])
        default_owner = admin_ids[0]
        with sqlite3.connect(DB_PATH) as conn:
            has_group = conn.execute(
                'SELECT COUNT(*) FROM group_chats WHERE user_id = ?',
                (default_owner,)
            ).fetchone()[0]
            if has_group == 0:
                conn.execute(
                    '''
                    INSERT OR IGNORE INTO group_chats (user_id, chat_id, is_default, chat_title, created_at)
                    VALUES (?, ?, 1, '', ?)
                    ''',
                    (default_owner, int(group_chat_id), int(time.time()))
                )


def get_default_group_id(user_id: int) -> Optional[int]:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            'SELECT chat_id FROM group_chats WHERE user_id = ? AND is_default = 1 LIMIT 1',
            (user_id,)
        ).fetchone()
    if row:
        return int(row[0])
    return None


def add_group_chat(user_id: int, chat_id: int, chat_title: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        has_default = conn.execute(
            'SELECT COUNT(*) FROM group_chats WHERE user_id = ? AND is_default = 1',
            (user_id,)
        ).fetchone()[0]
        is_default = 0 if has_default else 1
        conn.execute(
            '''
            INSERT OR IGNORE INTO group_chats (user_id, chat_id, is_default, chat_title, created_at)
            VALUES (?, ?, ?, ?, ?)
            ''',
            (user_id, chat_id, is_default, encrypt_value(chat_title), int(time.time()))
        )
        conn.execute(
            '''
            UPDATE group_chats SET chat_title = ?
            WHERE user_id = ? AND chat_id = ? AND (chat_title IS NULL OR chat_title = '')
            ''',
            (encrypt_value(chat_title), user_id, chat_id)
        )


def remove_group_chat(user_id: int, chat_id: int) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        was_default = conn.execute(
            'SELECT is_default FROM group_chats WHERE user_id = ? AND chat_id = ?',
            (user_id, chat_id)
        ).fetchone()
        conn.execute(
            'DELETE FROM group_chats WHERE user_id = ? AND chat_id = ?',
            (user_id, chat_id)
        )
        if was_default and was_default[0]:
            row = conn.execute(
                'SELECT chat_id FROM group_chats WHERE user_id = ? ORDER BY created_at ASC LIMIT 1',
                (user_id,)
            ).fetchone()
            if row:
                conn.execute(
                    'UPDATE group_chats SET is_default = 1 WHERE user_id = ? AND chat_id = ?',
                    (user_id, row[0])
                )


def set_default_group(user_id: int, chat_id: int) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            'UPDATE group_chats SET is_default = 0 WHERE user_id = ?',
            (user_id,)
        )
        conn.execute(
            'UPDATE group_chats SET is_default = 1 WHERE user_id = ? AND chat_id = ?',
            (user_id, chat_id)
        )


def list_group_chats(user_id: int) -> list[int]:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            'SELECT chat_id FROM group_chats WHERE user_id = ? ORDER BY is_default DESC, created_at ASC',
            (user_id,)
        ).fetchall()
    return [int(row[0]) for row in rows]


def list_group_entries(user_id: int) -> list[dict]:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            '''
            SELECT chat_id, is_default, chat_title
            FROM group_chats
            WHERE user_id = ?
            ORDER BY is_default DESC, created_at ASC
            ''',
            (user_id,)
        ).fetchall()
    return [
        {
            'chat_id': int(row[0]),
            'is_default': bool(row[1]),
            'chat_title': decrypt_value(row[2] or '')
        }
        for row in rows
    ]

def list_allowed_users() -> list[int]:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            'SELECT user_id FROM allowed_users ORDER BY created_at ASC'
        ).fetchall()
    return [int(row[0]) for row in rows]


def list_admin_users() -> list[int]:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            'SELECT user_id FROM admin_users ORDER BY created_at ASC'
        ).fetchall()
    return [int(row[0]) for row in rows]


def get_accounts(user_id: int) -> list[dict]:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            '''
            SELECT id, bank_name, bank_bin, account_no, account_name, is_default
            FROM accounts
            WHERE user_id = ?
            ORDER BY is_default DESC, id ASC
            ''',
            (user_id,)
        ).fetchall()
    return [
        {
            'id': row[0],
            'bank_name': decrypt_value(row[1] or ''),
            'bank_bin': decrypt_value(row[2] or ''),
            'account_no': decrypt_value(row[3] or ''),
            'account_name': decrypt_value(row[4] or ''),
            'is_default': bool(row[5])
        }
        for row in rows
    ]


def get_default_account(user_id: int) -> Optional[dict]:
    accounts = get_accounts(user_id)
    if not accounts:
        return None
    for account in accounts:
        if account.get('is_default'):
            return account
    return accounts[0]


def account_count(user_id: int) -> int:
    with sqlite3.connect(DB_PATH) as conn:
        return conn.execute(
            'SELECT COUNT(*) FROM accounts WHERE user_id = ?',
            (user_id,)
        ).fetchone()[0]


def save_account(user_id: int, account: dict) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        has_default = conn.execute(
            'SELECT COUNT(*) FROM accounts WHERE user_id = ? AND is_default = 1',
            (user_id,)
        ).fetchone()[0]
        is_default = 0 if has_default else 1
        conn.execute(
            '''
            INSERT INTO accounts (user_id, bank_name, bank_bin, account_no, account_name, is_default, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                user_id,
                encrypt_value(account.get('bank_name', '')),
                encrypt_value(account.get('bank_bin', '')),
                encrypt_value(account.get('account_no', '')),
                encrypt_value(account.get('account_name', '')),
                is_default,
                int(time.time())
            )
        )


def set_default_account(user_id: int, account_id: int) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('UPDATE accounts SET is_default = 0 WHERE user_id = ?', (user_id,))
        conn.execute(
            'UPDATE accounts SET is_default = 1 WHERE user_id = ? AND id = ?',
            (user_id, account_id)
        )


def profile_missing(user_id: int) -> bool:
    return account_count(user_id) == 0

def build_bank_keyboard(include_back: bool = False, back_target: str = 'menu') -> InlineKeyboardMarkup:
    rows = []
    row = []
    for idx, (name, bin_code) in enumerate(BANKS, start=1):
        row.append(InlineKeyboardButton(name, callback_data=f'bank:{name}:{bin_code}'))
        if idx % 3 == 0:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    if include_back:
        rows.append([InlineKeyboardButton('Back', callback_data=f'back:{back_target}')])
    return InlineKeyboardMarkup(rows)


def build_account_keyboard(accounts: list[dict], include_back: bool = False, back_target: str = 'menu') -> InlineKeyboardMarkup:
    rows = []
    for account in accounts:
        label = f"{account['bank_name']} - {account['account_no']}"
        rows.append([InlineKeyboardButton(label, callback_data=f'acct:{account["id"]}')])
    if include_back:
        rows.append([InlineKeyboardButton('Back', callback_data=f'back:{back_target}')])
    return InlineKeyboardMarkup(rows)


def build_back_keyboard(target: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton('Back', callback_data=f'back:{target}')]])


def build_main_menu_keyboard(is_admin: bool = False) -> InlineKeyboardMarkup:
    rows = [
        [
            InlineKeyboardButton('Tao QR', callback_data='menu:qr'),
            InlineKeyboardButton('Quan ly tai khoan', callback_data='menu:bank')
        ],
        [
            InlineKeyboardButton('Quan ly nhom chat', callback_data='menu:groups')
        ]
    ]
    if is_admin:
        rows.append([
            InlineKeyboardButton('Quan ly nguoi dung', callback_data='menu:users')
        ])
    rows.append([InlineKeyboardButton('Huong dan', callback_data='menu:help')])
    return InlineKeyboardMarkup(rows)


def build_register_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[InlineKeyboardButton('Dang ky su dung', callback_data='reg:request')]])


def build_qr_menu_keyboard() -> InlineKeyboardMarkup:
    rows = [
        [
            InlineKeyboardButton('Tao QR', callback_data='menu:qr:normal'),
            InlineKeyboardButton('Chia bill', callback_data='menu:qr:bill')
        ],
        [
            InlineKeyboardButton('Back', callback_data='back:menu')
        ]
    ]
    return InlineKeyboardMarkup(rows)


def build_bill_people_keyboard() -> InlineKeyboardMarkup:
    rows = [
        [
            InlineKeyboardButton('2 nguoi', callback_data='bill:2'),
            InlineKeyboardButton('3 nguoi', callback_data='bill:3'),
            InlineKeyboardButton('4 nguoi', callback_data='bill:4')
        ],
        [
            InlineKeyboardButton('5 nguoi', callback_data='bill:5'),
            InlineKeyboardButton('6 nguoi', callback_data='bill:6'),
            InlineKeyboardButton('8 nguoi', callback_data='bill:8')
        ]
    ]
    return InlineKeyboardMarkup(rows)


def build_bill_confirm_keyboard() -> InlineKeyboardMarkup:
    rows = [
        [
            InlineKeyboardButton('Xac nhan gui', callback_data='billconfirm:yes'),
            InlineKeyboardButton('Huy', callback_data='billconfirm:no')
        ]
    ]
    return InlineKeyboardMarkup(rows)

async def submit_access_request(user, context: ContextTypes.DEFAULT_TYPE) -> bool:
    inserted = False
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute(
            '''
            INSERT OR IGNORE INTO access_requests (user_id, username, first_name, created_at)
            VALUES (?, ?, ?, ?)
            ''',
            (
                user.id,
                encrypt_value(user.username or ''),
                encrypt_value(user.first_name or ''),
                int(time.time())
            )
        )
        inserted = cursor.rowcount > 0

    if inserted:
        admins = list_admin_users()
        if admins:
            info = f'Yeu cau truy cap tu {user.first_name} (id: {user.id})'
            if user.username:
                info += f' @{user.username}'
            for admin_id in admins:
                try:
                    await context.bot.send_message(chat_id=int(admin_id), text=info)
                except Exception:
                    logger.warning('Failed to notify admin %s', admin_id)
    return inserted


async def group_block_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = (update.message.text or '').strip()
    if text.startswith('/id'):
        chat_id = update.effective_chat.id
        await update.message.reply_text(f'Chat ID: {chat_id}')
        return
    if text.startswith('/help'):
        await update.message.reply_text('Vui long nhan tin rieng voi bot (/start)')
    else:
        await update.message.reply_text('Vui long nhan tin rieng voi bot.')


async def bot_added_to_group_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_member_update = update.my_chat_member
    if not chat_member_update:
        return
    chat = update.effective_chat
    if not chat or chat.type not in ('group', 'supergroup'):
        return
    new_status = chat_member_update.new_chat_member.status
    old_status = chat_member_update.old_chat_member.status
    if new_status not in ('member', 'administrator'):
        return
    if old_status not in ('left', 'kicked'):
        return
    if not update.effective_user:
        return
    chat_title = (chat.title or '').strip()
    add_group_chat(update.effective_user.id, chat.id, chat_title)


def build_group_manage_keyboard() -> InlineKeyboardMarkup:
    rows = [
        [
            InlineKeyboardButton('Them group', callback_data='group:add'),
            InlineKeyboardButton('Xoa group', callback_data='group:del')
        ],
        [
            InlineKeyboardButton('Dat mac dinh', callback_data='group:default'),
            InlineKeyboardButton('Danh sach', callback_data='group:list')
        ],
        [
            InlineKeyboardButton('Back', callback_data='back:menu')
        ]
    ]
    return InlineKeyboardMarkup(rows)


def build_group_list_keyboard(entries: list[dict], action: str) -> InlineKeyboardMarkup:
    rows = []
    for entry in entries:
        title = entry.get('chat_title', '').strip()
        label = f"{title} ({entry['chat_id']})" if title else f"{entry['chat_id']}"
        if entry['is_default']:
            label = f"* {label}"
        rows.append([InlineKeyboardButton(label, callback_data=f"group:{action}:{entry['chat_id']}")])
    rows.append([InlineKeyboardButton('Back', callback_data='menu:groups')])
    return InlineKeyboardMarkup(rows)

def build_bank_manage_keyboard() -> InlineKeyboardMarkup:
    rows = [
        [
            InlineKeyboardButton('Them tai khoan', callback_data='bank:menu:add'),
            InlineKeyboardButton('Chon mac dinh', callback_data='bank:menu:default')
        ],
        [
            InlineKeyboardButton('Danh sach', callback_data='bank:menu:list'),
            InlineKeyboardButton('Back', callback_data='back:menu')
        ]
    ]
    return InlineKeyboardMarkup(rows)

def build_user_manage_keyboard() -> InlineKeyboardMarkup:
    rows = [
        [
            InlineKeyboardButton('Them user', callback_data='user:add'),
            InlineKeyboardButton('Xoa user', callback_data='user:del')
        ],
        [
            InlineKeyboardButton('Danh sach', callback_data='user:list'),
            InlineKeyboardButton('Back', callback_data='back:menu')
        ]
    ]
    return InlineKeyboardMarkup(rows)


def build_user_list_keyboard(user_ids: list[int], action: str) -> InlineKeyboardMarkup:
    rows = []
    for uid in user_ids:
        rows.append([InlineKeyboardButton(str(uid), callback_data=f'user:{action}:{uid}')])
    rows.append([InlineKeyboardButton('Back', callback_data='menu:users')])
    return InlineKeyboardMarkup(rows)


def parse_amount_to_int(raw: str) -> Optional[int]:
    amount_str = normalize_amount(raw or '')
    if not amount_str:
        return None
    if '.' in amount_str:
        try:
            return int(round(float(amount_str)))
        except ValueError:
            return None
    try:
        return int(amount_str)
    except ValueError:
        return None


def format_vnd(amount: int) -> str:
    return f'{amount:,}'.replace(',', '.')


def parse_int(value: str, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_optional_int(value: str) -> Optional[int]:
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def measure_text_block(lines: list[str], font: ImageFont.ImageFont, line_gap: int) -> tuple[int, int, list[tuple[int, int]]]:
    dummy = Image.new('RGB', (1, 1))
    draw = ImageDraw.Draw(dummy)
    line_sizes: list[tuple[int, int]] = []
    for line in lines:
        if not line:
            line_sizes.append((0, 0))
            continue
        try:
            box = draw.textbbox((0, 0), line, font=font)
            line_sizes.append((box[2] - box[0], box[3] - box[1]))
        except AttributeError:
            line_sizes.append(draw.textsize(line, font=font))
    text_width = max((size[0] for size in line_sizes), default=0)
    text_height = sum(size[1] for size in line_sizes)
    text_height += max(0, (len(lines) - 1)) * line_gap
    return text_width, text_height, line_sizes


def build_qr_panel(qr_img: Image.Image, bank_name: str, account_name: str, account_no: str) -> Image.Image:
    font = ImageFont.load_default()
    lines = [bank_name.strip(), account_name.strip() or 'NA', account_no.strip() or '']

    padding = 16
    gap = 8
    line_gap = 4
    text_width, text_height, line_sizes = measure_text_block(lines, font, line_gap)
    panel_width = max(qr_img.width, text_width) + padding * 2
    panel_height = qr_img.height + gap + text_height + padding * 2
    panel = Image.new('RGB', (panel_width, panel_height), 'white')
    panel_draw = ImageDraw.Draw(panel)
    border_color = '#0B5B3E'
    radius = 16
    border_width = 3
    try:
        panel_draw.rounded_rectangle(
            (0, 0, panel_width - 1, panel_height - 1),
            radius=radius,
            outline=border_color,
            width=border_width,
            fill='white'
        )
    except AttributeError:
        panel_draw.rectangle(
            (0, 0, panel_width - 1, panel_height - 1),
            outline=border_color,
            width=border_width,
            fill='white'
        )
    qr_x = (panel_width - qr_img.width) // 2
    panel.paste(qr_img, (qr_x, padding))

    text_y = padding + qr_img.height + gap
    for idx, line in enumerate(lines):
        if line:
            line_width, line_height = line_sizes[idx]
            text_x = (panel_width - line_width) // 2
            panel_draw.text((text_x, text_y), line, fill='black', font=font)
            text_y += line_height + line_gap

    return panel


def detect_frame_bbox(background: Image.Image) -> Optional[tuple[int, int, int, int]]:
    width, height = background.size
    start_x = 0
    end_x = int(width * 0.65)
    start_y = int(height * 0.25)
    end_y = height - 1
    threshold = 90
    min_x, min_y = width, height
    max_x, max_y = 0, 0
    pixels = background.load()
    found = False
    for y in range(start_y, end_y + 1):
        for x in range(start_x, end_x + 1):
            r, g, b = pixels[x, y]
            if r < threshold and g < threshold and b < threshold:
                found = True
                if x < min_x:
                    min_x = x
                if y < min_y:
                    min_y = y
                if x > max_x:
                    max_x = x
                if y > max_y:
                    max_y = y
    if not found:
        return None
    inset = 10
    min_x += inset
    min_y += inset
    max_x -= inset
    max_y -= inset
    if max_x <= min_x or max_y <= min_y:
        return None
    return (min_x, min_y, max_x, max_y)


def compose_qr_on_background(
    qr_panel: Image.Image,
    background: Image.Image,
    frame_bbox: Optional[tuple[int, int, int, int]] = None
) -> Image.Image:
    bg = background.copy()
    bg_w, bg_h = bg.size
    panel_w, panel_h = qr_panel.size

    margin = 24
    x = parse_optional_int(get_setting('QR_PANEL_X', ''))
    y = parse_optional_int(get_setting('QR_PANEL_Y', ''))
    if x is None or y is None:
        if frame_bbox:
            left, top, right, bottom = frame_bbox
            available_w = max(0, right - left)
            available_h = max(0, bottom - top)
            x = left + max(0, (available_w - panel_w) // 2) if x is None else x
            y = top + max(0, (available_h - panel_h) // 2) if y is None else y
            if x is not None:
                x -= 44
            if y is not None:
                y += 39
        else:
            if x is None:
                x = margin
            if y is None:
                y = bg_h - panel_h - margin
    x = max(0, min(x, bg_w - panel_w))
    y = max(0, min(y, bg_h - panel_h))
    bg.paste(qr_panel, (x, y))
    return bg


def resize_qr_image(qr_img: Image.Image, target_size: int) -> Image.Image:
    target_size = max(120, target_size)
    return qr_img.resize((target_size, target_size), Image.NEAREST)


def resolve_qr_size(
    background: Image.Image,
    bank_name: str,
    account_name: str,
    account_no: str,
    frame_bbox: Optional[tuple[int, int, int, int]]
) -> int:
    bg_w, bg_h = background.size
    default_size = int(min(bg_w, bg_h) * 0.32)
    size_setting = get_setting('QR_SIZE', '').strip()
    if size_setting:
        return parse_int(size_setting, default_size)
    if not frame_bbox:
        return default_size
    left, top, right, bottom = frame_bbox
    frame_w = max(0, right - left)
    frame_h = max(0, bottom - top)
    font = ImageFont.load_default()
    lines = [bank_name.strip(), account_name.strip() or 'NA', account_no.strip() or '']
    padding = 16
    gap = 8
    line_gap = 4
    text_width, text_height, _ = measure_text_block(lines, font, line_gap)
    frame_margin = 12
    available_w = max(0, frame_w - padding * 2 - frame_margin * 2)
    available_h = max(0, frame_h - (gap + text_height + padding * 2) - frame_margin * 2)
    target_size = int(min(available_w, available_h) * 0.81)
    if target_size <= 0:
        return default_size
    return target_size


def build_qr_background_image(payload: str, bank_name: str, account_name: str, account_no: str) -> Image.Image:
    bg_path = get_setting('BG_IMAGE_PATH', 'bg.png').strip()
    if not os.path.isfile(bg_path):
        raise FileNotFoundError(f'Khong tim thay anh nen: {bg_path}')
    background = Image.open(bg_path).convert('RGB')
    frame_bbox = detect_frame_bbox(background)
    qr_img = qrcode.make(payload).convert('RGB')
    target_size = resolve_qr_size(background, bank_name, account_name, account_no, frame_bbox)
    qr_img = resize_qr_image(qr_img, target_size)
    qr_panel = build_qr_panel(qr_img, bank_name, account_name, account_no)
    return compose_qr_on_background(qr_panel, background, frame_bbox=frame_bbox)


async def create_qr_request(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    amount: str,
    purpose: str,
    bank_bin: Optional[str] = None,
    account_no: Optional[str] = None
) -> None:
    user_id = update.effective_user.id
    default_account = get_default_account(user_id)
    if not default_account:
        await update.message.reply_text('Chua co tai khoan nao. Goi /start hoac /addbank de them.')
        return
    if not default_account.get('account_name') or not default_account.get('bank_name'):
        await update.message.reply_text('Chua co thong tin ten tai khoan/ten ngan hang. Goi /start de nhap.')
        return

    bank_bin = bank_bin or default_account['bank_bin'] or get_setting('DEFAULT_BANK_BIN', '')
    account_no = account_no or default_account['account_no'] or get_setting('DEFAULT_ACCOUNT_NO', '')
    if not bank_bin or not account_no:
        await update.message.reply_text('Chua co thong tin mac dinh hoac chua truyen vao lenh.')
        return

    try:
        payload = build_vietqr_payload(
            bank_bin=bank_bin,
            account_no=account_no,
            account_name=default_account['account_name'],
            amount=amount,
            purpose=purpose
        )
    except ValueError as exc:
        await update.message.reply_text(f'Loi: {exc}')
        logger.warning('Invalid payload input: %s', exc)
        return

    context.user_data['qr_pending'] = {
        'payload': payload,
        'account_no': account_no,
        'account_name': default_account['account_name'],
        'bank_name': default_account['bank_name'],
        'created_at': time.time()
    }
    if is_debug_enabled():
        await update.message.reply_text(f'VietQR payload:\n{payload}')
    buttons = [
        [
            InlineKeyboardButton('Gui vao group', callback_data='qr:group'),
            InlineKeyboardButton('Gui QR rieng', callback_data='qr:private')
        ]
    ]
    await update.message.reply_text(
        'Ban muon gui QR o dau?',
        reply_markup=InlineKeyboardMarkup(buttons)
    )


async def help_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_chat.type != 'private':
        await update.message.reply_text('Vui long nhan tin rieng voi bot (/start)')
        return
    if not is_allowed_user(update):
        await update.message.reply_text(
            'Ban chua duoc cap quyen. Bam nut de gui yeu cau.',
            reply_markup=build_register_keyboard()
        )
        return
    name = (update.effective_user.first_name or '').strip()
    greeting = f'Chao {name}, chon mot dich vu cua chung toi:' if name else 'Chon mot dich vu cua chung toi:'
    is_admin = is_admin_user(update.effective_user.id)
    await update.message.reply_text(greeting, reply_markup=build_main_menu_keyboard(is_admin=is_admin))


async def start_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_allowed_user(update):
        if update.effective_user:
            await submit_access_request(update.effective_user, context)
        await update.message.reply_text(
            'Ban chua duoc cap quyen. Bam nut de gui yeu cau.',
            reply_markup=build_register_keyboard()
        )
        return
    name = (update.effective_user.first_name or '').strip()
    greeting = f'Chao {name}, chon mot dich vu cua chung toi:' if name else 'Chon mot dich vu cua chung toi:'
    is_admin = is_admin_user(update.effective_user.id)
    await update.message.reply_text(greeting, reply_markup=build_main_menu_keyboard(is_admin=is_admin))


async def id_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_allowed_user(update):
        await update.message.reply_text('Ban khong co quyen su dung bot nay.')
        return
    if update.effective_chat.type == 'private':
        await update.message.reply_text('Lenh /id chi dung trong group de lay chat id.')
        return
    chat_id = update.effective_chat.id
    user_id = update.effective_user.id
    await update.message.reply_text(f'Chat ID: {chat_id}\nUser ID: {user_id}')

async def addbank_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_allowed_user(update):
        await update.message.reply_text('Ban khong co quyen su dung bot nay.')
        return
    if update.effective_chat.type != 'private':
        await update.message.reply_text('Lenh /addbank chi dung trong chat rieng.')
        return
    user_id = update.effective_user.id
    if account_count(user_id) >= 5:
        await update.message.reply_text('Da dat toi da 5 tai khoan.')
        return
    context.user_data['profile_state'] = 'bank_select'
    await update.message.reply_text('Chon ngan hang:', reply_markup=build_bank_keyboard(include_back=True, back_target='menu'))


async def bank_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_allowed_user(update):
        await update.message.reply_text('Ban khong co quyen su dung bot nay.')
        return
    if update.effective_chat.type != 'private':
        await update.message.reply_text('Lenh /bank chi dung trong chat rieng.')
        return
    user_id = update.effective_user.id
    accounts = get_accounts(user_id)
    if not accounts:
        await update.message.reply_text('Chua co tai khoan nao. Dung /addbank de them.')
        return
    await update.message.reply_text(
        'Chon tai khoan mac dinh:',
        reply_markup=build_account_keyboard(accounts, include_back=True, back_target='menu')
    )


async def qr_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = update.message.text or ''
    args = parse_args(text)
    logger.info('QR request chat_id=%s chat_type=%s text=%s', update.effective_chat.id, update.effective_chat.type, text)

    if not is_allowed_user(update):
        await update.message.reply_text('Ban khong co quyen su dung bot nay.')
        return

    if not args:
        await update.message.reply_text(build_help_message())
        return

    if update.effective_chat.type != 'private':
        await update.message.reply_text('Vui long nhan lenh /qr trong chat rieng voi bot.')
        return

    bank_bin = None
    account_no = None
    if len(args) >= 3 and args[0].isdigit() and args[1].isdigit():
        bank_bin = args[0]
        account_no = args[1]
        amount = args[2]
        purpose = ' '.join(args[3:])
    else:
        amount = args[0]
        purpose = ' '.join(args[1:])

    await create_qr_request(update, context, amount, purpose, bank_bin=bank_bin, account_no=account_no)


async def bill_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_allowed_user(update):
        await update.message.reply_text('Ban khong co quyen su dung bot nay.')
        return

    if update.effective_chat.type != 'private':
        await update.message.reply_text('Lenh /bill chi dung trong chat rieng.')
        return

    args = parse_args(update.message.text or '')
    if not args:
        await update.message.reply_text('Dung: /bill <tong> [noi_dung]')
        return

    total = parse_amount_to_int(args[0])
    if total is None or total <= 0:
        await update.message.reply_text('Tong tien khong hop le.')
        return

    note = ' '.join(args[1:]).strip()
    context.user_data['bill_total'] = total
    context.user_data['bill_note'] = note

    await update.message.reply_text(
        f'Chon so nguoi de chia deu. Tong: {format_vnd(total)} VND',
        reply_markup=build_bill_people_keyboard()
    )


async def bill_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    if not is_allowed_user(update):
        await query.edit_message_text('Ban khong co quyen su dung bot nay.')
        return
    data = query.data or ''
    if not data.startswith('bill:'):
        return

    try:
        people = int(data.split(':', 1)[1])
    except ValueError:
        await query.edit_message_text('So nguoi khong hop le.')
        return

    total = context.user_data.get('bill_total')
    note = context.user_data.get('bill_note', '')
    if not total:
        await query.edit_message_text('Khong tim thay thong tin bill. Hay go /bill lai.')
        return

    per = total // people
    remainder = total % people
    if per <= 0:
        await query.edit_message_text('Tong tien qua nho de chia.')
        return
    context.user_data['bill_pending'] = {
        'people': people,
        'per': per,
        'remainder': remainder,
        'note': note or ''
    }
    confirm_lines = [
        f'Chia bill {people} nguoi',
        f'Moi nguoi: {format_vnd(per)} VND'
    ]
    if remainder > 10:
        confirm_lines.append(f'Du {format_vnd(remainder)} VND (cong cho nguoi dau tien)')
    if note:
        confirm_lines.append(f'Noi dung: {note}')
    await query.edit_message_text(
        '\n'.join(confirm_lines) + '\n\nXac nhan gui QR vao group?',
        reply_markup=build_bill_confirm_keyboard()
    )


async def bill_confirm_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    if not is_allowed_user(update):
        await query.edit_message_text('Ban khong co quyen su dung bot nay.')
        return
    data = query.data or ''
    if data == 'billconfirm:no':
        context.user_data.pop('bill_pending', None)
        await query.edit_message_text('Da huy.')
        return
    if data != 'billconfirm:yes':
        return

    pending = context.user_data.get('bill_pending') or {}
    people = int(pending.get('people') or 0)
    per = int(pending.get('per') or 0)
    remainder = int(pending.get('remainder') or 0)
    note = (pending.get('note') or '').strip()
    if people <= 0 or per <= 0:
        await query.edit_message_text('Khong tim thay thong tin bill. Hay go /bill lai.')
        return

    user_id = update.effective_user.id
    default_account = get_default_account(user_id)
    if not default_account:
        await query.edit_message_text('Chua co tai khoan nao. Goi /start hoac /addbank de them.')
        return
    if not default_account.get('account_name') or not default_account.get('bank_name'):
        await query.edit_message_text('Chua co thong tin ten tai khoan/ten ngan hang. Goi /start de nhap.')
        return

    group_id = get_default_group_id(user_id)
    if not group_id:
        await query.edit_message_text('Chua co group. Dung /addgroup <chat_id> de them.')
        return

    purpose = note or ''
    try:
        payload = build_vietqr_payload(
            bank_bin=default_account['bank_bin'],
            account_no=default_account['account_no'],
            account_name=default_account['account_name'],
            amount=str(per),
            purpose=purpose
        )
        img = build_qr_background_image(
            payload,
            default_account['bank_name'],
            default_account['account_name'],
            default_account['account_no']
        )
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        buffer.name = 'bill_qr.png'
    except Exception as exc:
        logger.exception('Failed to generate bill QR')
        await query.edit_message_text(f'Khong tao duoc QR: {exc}')
        return

    caption_lines = []
    if note:
        caption_lines.append(note)
    else:
        caption_lines.append(f'Chia bill {people} nguoi')
    caption_lines.append(f'Moi nguoi: {format_vnd(per)} VND')
    if remainder > 10:
        caption_lines.append(f'Du {format_vnd(remainder)} VND (cong cho nguoi dau tien)')
    if note:
        caption_lines.append(f'Noi dung: {note}')

    await context.bot.send_photo(
        chat_id=group_id,
        photo=InputFile(buffer),
        caption='\n'.join(caption_lines)
    )
    if is_debug_enabled():
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f'VietQR payload:\n{payload}')
    context.user_data.pop('bill_pending', None)
    await query.edit_message_text('Da gui QR vao group.')

async def account_select_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    if not is_allowed_user(update):
        await query.edit_message_text('Ban khong co quyen su dung bot nay.')
        return
    data = query.data or ''
    if not data.startswith('acct:'):
        return
    try:
        account_id = int(data.split(':', 1)[1])
    except ValueError:
        await query.edit_message_text('Tai khoan khong hop le.')
        return
    user_id = update.effective_user.id
    set_default_account(user_id, account_id)
    await query.edit_message_text('Da dat tai khoan mac dinh.', reply_markup=build_back_keyboard('menu'))


async def register_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    user = update.effective_user
    if is_allowed_user(update):
        name = (user.first_name or '').strip()
        greeting = f'Chao {name}, chon mot dich vu cua chung toi:' if name else 'Chon mot dich vu cua chung toi:'
        is_admin = is_admin_user(user.id)
        await query.edit_message_text(greeting, reply_markup=build_main_menu_keyboard(is_admin=is_admin))
        return
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            'INSERT OR IGNORE INTO allowed_users (user_id, created_at) VALUES (?, ?)',
            (user.id, int(time.time()))
        )
        conn.execute('DELETE FROM access_requests WHERE user_id = ?', (user.id,))
    name = (user.first_name or '').strip()
    greeting = f'Chao {name}, chon mot dich vu cua chung toi:' if name else 'Chon mot dich vu cua chung toi:'
    is_admin = is_admin_user(user.id)
    await query.edit_message_text(greeting, reply_markup=build_main_menu_keyboard(is_admin=is_admin))


async def approve_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_admin_user(user_id):
        await update.message.reply_text('Ban khong co quyen su dung lenh nay.')
        return
    args = parse_args(update.message.text or '')
    if not args:
        await update.message.reply_text('Dung: /approve <user_id>')
        return
    try:
        target_id = int(args[0])
    except ValueError:
        await update.message.reply_text('User ID khong hop le.')
        return
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            'INSERT OR IGNORE INTO allowed_users (user_id, created_at) VALUES (?, ?)',
            (target_id, int(time.time()))
        )
        conn.execute('DELETE FROM access_requests WHERE user_id = ?', (target_id,))
    await update.message.reply_text(f'Da cap quyen cho {target_id}.')


async def deny_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_admin_user(user_id):
        await update.message.reply_text('Ban khong co quyen su dung lenh nay.')
        return
    args = parse_args(update.message.text or '')
    if not args:
        await update.message.reply_text('Dung: /deny <user_id>')
        return
    try:
        target_id = int(args[0])
    except ValueError:
        await update.message.reply_text('User ID khong hop le.')
        return
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('DELETE FROM access_requests WHERE user_id = ?', (target_id,))
    await update.message.reply_text(f'Da tu choi {target_id}.')


async def addgroup_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    args = parse_args(update.message.text or '')
    if not args:
        await update.message.reply_text('Dung: /addgroup <chat_id>')
        return
    try:
        chat_id = int(args[0])
    except ValueError:
        await update.message.reply_text('Chat ID khong hop le.')
        return
    chat_title = ''
    try:
        chat = await context.bot.get_chat(chat_id)
        chat_title = (chat.title or '').strip()
    except Exception:
        logger.warning('Failed to fetch chat title for %s', chat_id)
    add_group_chat(user_id, chat_id, chat_title)
    await update.message.reply_text(f'Da them group {chat_id}.')


async def delgroup_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.effective_user.id
    if not is_allowed_user(update):
        await update.message.reply_text('Ban khong co quyen su dung lenh nay.')
        return
    args = parse_args(update.message.text or '')
    if not args:
        await update.message.reply_text('Dung: /delgroup <chat_id>')
        return
    try:
        chat_id = int(args[0])
    except ValueError:
        await update.message.reply_text('Chat ID khong hop le.')
        return
    remove_group_chat(user_id, chat_id)
    await update.message.reply_text(f'Da xoa group {chat_id}.')


async def menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    if not is_allowed_user(update):
        await query.edit_message_text('Ban khong co quyen su dung bot nay.')
        return
    data = query.data or ''
    if not data.startswith('menu:'):
        return
    action = data.split(':', 1)[1]
    user_id = update.effective_user.id

    if action == 'qr':
        await query.edit_message_text(
            'Chon thao tac QR:',
            reply_markup=build_qr_menu_keyboard()
        )
        return
    if action.startswith('qr:'):
        sub_action = action.split(':', 1)[1]
        if sub_action == 'normal':
            context.user_data['menu_state'] = 'qr'
            await query.edit_message_text(
                'Nhap so tien va noi dung. Vi du: 100000 Tien an trua',
                reply_markup=build_back_keyboard('menu')
            )
            return
        if sub_action == 'bill':
            context.user_data['menu_state'] = 'bill'
            await query.edit_message_text(
                'Nhap tong va noi dung (optional). Vi du: 250000 An trua',
                reply_markup=build_back_keyboard('menu')
            )
            return

    if action == 'bank':
        await query.edit_message_text(
            'Quan ly tai khoan:',
            reply_markup=build_bank_manage_keyboard()
        )
        return

    if action == 'groups':
        await query.edit_message_text(
            'Quan ly nhom chat:',
            reply_markup=build_group_manage_keyboard()
        )
        return

    if action == 'users':
        if not is_admin_user(user_id):
            await query.edit_message_text(
                'Chi admin moi duoc quan ly nguoi dung.',
                reply_markup=build_main_menu_keyboard(is_admin=is_admin_user(user_id))
            )
            return
        await query.edit_message_text(
            'Quan ly nguoi dung:',
            reply_markup=build_user_manage_keyboard()
        )
        return

    if action == 'help':
        await query.edit_message_text(
            build_help_message(),
            reply_markup=build_main_menu_keyboard(is_admin=is_admin_user(user_id))
        )
        return

    await query.edit_message_text(
        'Khong ho tro thao tac nay.',
        reply_markup=build_main_menu_keyboard(is_admin=is_admin_user(user_id))
    )


async def group_manage_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    user_id = update.effective_user.id
    if not is_allowed_user(update):
        await query.edit_message_text('Ban khong co quyen su dung bot nay.')
        return
    data = query.data or ''
    if not data.startswith('group:'):
        return
    parts = data.split(':', 2)
    action = parts[1] if len(parts) > 1 else ''

    if action == 'add':
        context.user_data['menu_state'] = 'group_add'
        await query.edit_message_text(
            'Nhap chat id group (vi du: -1001234567890).',
            reply_markup=build_back_keyboard('menu')
        )
        return

    if action == 'del':
        entries = list_group_entries(user_id)
        if not entries:
            await query.edit_message_text(
                'Chua co group nao.',
                reply_markup=build_group_manage_keyboard()
            )
            return
        await query.edit_message_text(
            'Chon group de xoa:',
            reply_markup=build_group_list_keyboard(entries, 'remove')
        )
        return

    if action == 'default':
        entries = list_group_entries(user_id)
        if not entries:
            await query.edit_message_text(
                'Chua co group nao.',
                reply_markup=build_group_manage_keyboard()
            )
            return
        await query.edit_message_text(
            'Chon group mac dinh:',
            reply_markup=build_group_list_keyboard(entries, 'set')
        )
        return

    if action == 'list':
        entries = list_group_entries(user_id)
        if not entries:
            await query.edit_message_text(
                'Chua co group nao.',
                reply_markup=build_group_manage_keyboard()
            )
            return
        lines = []
        for entry in entries:
            mark = '*' if entry['is_default'] else '-'
            title = (entry.get('chat_title') or '').strip()
            label = f"{title} ({entry['chat_id']})" if title else f"{entry['chat_id']}"
            lines.append(f"{mark} {label}")
        await query.edit_message_text(
            'Danh sach group:\n' + '\n'.join(lines),
            reply_markup=build_group_manage_keyboard()
        )
        return

    if action == 'set' and len(parts) == 3:
        try:
            chat_id = int(parts[2])
        except ValueError:
            await query.edit_message_text('Chat ID khong hop le.', reply_markup=build_group_manage_keyboard())
            return
        set_default_group(user_id, chat_id)
        await query.edit_message_text('Da dat group mac dinh.', reply_markup=build_group_manage_keyboard())
        return

    if action == 'remove' and len(parts) == 3:
        try:
            chat_id = int(parts[2])
        except ValueError:
            await query.edit_message_text('Chat ID khong hop le.', reply_markup=build_group_manage_keyboard())
            return
        remove_group_chat(user_id, chat_id)
        await query.edit_message_text('Da xoa group.', reply_markup=build_group_manage_keyboard())
        return

    await query.edit_message_text('Khong ho tro thao tac nay.', reply_markup=build_group_manage_keyboard())

async def user_manage_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    user_id = update.effective_user.id
    if not is_admin_user(user_id):
        await query.edit_message_text('Ban khong co quyen su dung chuc nang nay.')
        return
    data = query.data or ''
    if not data.startswith('user:'):
        return
    parts = data.split(':', 2)
    action = parts[1] if len(parts) > 1 else ''

    if action == 'add':
        context.user_data['menu_state'] = 'user_add'
        await query.edit_message_text(
            'Nhap user id can them (vi du: 123456789).',
            reply_markup=build_back_keyboard('menu')
        )
        return

    if action == 'del':
        users = list_allowed_users()
        if not users:
            await query.edit_message_text(
                'Chua co user nao.',
                reply_markup=build_user_manage_keyboard()
            )
            return
        await query.edit_message_text(
            'Chon user de xoa:',
            reply_markup=build_user_list_keyboard(users, 'remove')
        )
        return

    if action == 'list':
        users = list_allowed_users()
        if not users:
            await query.edit_message_text(
                'Chua co user nao.',
                reply_markup=build_user_manage_keyboard()
            )
            return
        lines = [f'- {uid}' for uid in users]
        await query.edit_message_text(
            'Danh sach user:\n' + '\n'.join(lines),
            reply_markup=build_user_manage_keyboard()
        )
        return

    if action == 'remove' and len(parts) == 3:
        try:
            target_id = int(parts[2])
        except ValueError:
            await query.edit_message_text('User ID khong hop le.', reply_markup=build_user_manage_keyboard())
            return
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute('DELETE FROM allowed_users WHERE user_id = ?', (target_id,))
        await query.edit_message_text('Da xoa user.', reply_markup=build_user_manage_keyboard())
        return

    await query.edit_message_text('Khong ho tro thao tac nay.', reply_markup=build_user_manage_keyboard())

async def bank_manage_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    if not is_allowed_user(update):
        await query.edit_message_text('Ban khong co quyen su dung bot nay.')
        return
    data = query.data or ''
    if not data.startswith('bank:menu:'):
        return
    action = data.split(':', 2)[2]
    user_id = update.effective_user.id

    if action == 'add':
        if account_count(user_id) >= 5:
            await query.edit_message_text(
                'Da dat toi da 5 tai khoan.',
                reply_markup=build_bank_manage_keyboard()
            )
            return
        context.user_data['profile_state'] = 'bank_select'
        await query.edit_message_text(
            'Chon ngan hang:',
            reply_markup=build_bank_keyboard(include_back=True, back_target='menu')
        )
        return

    if action == 'default':
        accounts = get_accounts(user_id)
        if not accounts:
            await query.edit_message_text(
                'Chua co tai khoan nao. Chon "Them tai khoan" de them.',
                reply_markup=build_bank_manage_keyboard()
            )
            return
        await query.edit_message_text(
            'Chon tai khoan mac dinh:',
            reply_markup=build_account_keyboard(accounts, include_back=True, back_target='menu')
        )
        return

    if action == 'list':
        accounts = get_accounts(user_id)
        if not accounts:
            await query.edit_message_text(
                'Chua co tai khoan nao.',
                reply_markup=build_bank_manage_keyboard()
            )
            return
        lines = []
        for acc in accounts:
            mark = '*' if acc['is_default'] else '-'
            lines.append(f"{mark} {acc['bank_name']} - {acc['account_no']}")
        await query.edit_message_text(
            'Danh sach tai khoan:\n' + '\n'.join(lines),
            reply_markup=build_bank_manage_keyboard()
        )
        return

    await query.edit_message_text('Khong ho tro thao tac nay.', reply_markup=build_bank_manage_keyboard())


async def back_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    if not is_allowed_user(update):
        await query.edit_message_text('Ban khong co quyen su dung bot nay.')
        return
    data = query.data or ''
    if not data.startswith('back:'):
        return
    target = data.split(':', 1)[1]
    if target == 'bank':
        context.user_data['profile_state'] = 'bank_select'
        context.user_data.pop('pending_account', None)
        await query.edit_message_text('Chon ngan hang:', reply_markup=build_bank_keyboard(include_back=True, back_target='menu'))
    elif target == 'account_no':
        pending = context.user_data.get('pending_account') or {}
        if not pending.get('bank_bin'):
            context.user_data['profile_state'] = 'bank_select'
            await query.edit_message_text('Chon ngan hang:', reply_markup=build_bank_keyboard(include_back=True, back_target='menu'))
            return
        context.user_data['profile_state'] = 'account_no'
        await query.edit_message_text(
            'Nhap so tai khoan (chi so, toi thieu 6 so).',
            reply_markup=build_back_keyboard('bank')
        )
    elif target == 'menu':
        context.user_data.pop('profile_state', None)
        context.user_data.pop('pending_account', None)
        await query.edit_message_text(
            'Chon mot dich vu cua chung toi:',
            reply_markup=build_main_menu_keyboard(is_admin=is_admin_user(update.effective_user.id))
        )
    else:
        await query.edit_message_text('Khong ho tro thao tac nay.')


async def bank_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    if not is_allowed_user(update):
        await query.edit_message_text('Ban khong co quyen su dung bot nay.')
        return
    state = context.user_data.get('profile_state')
    if state != 'bank_select':
        await query.edit_message_text('Khong co yeu cau chon ngan hang.')
        return
    data = query.data or ''
    if not data.startswith('bank:'):
        return
    parts = data.split(':', 2)
    if len(parts) != 3:
        await query.edit_message_text('Lua chon ngan hang khong hop le.')
        return
    bank_name = parts[1]
    bank_bin = parts[2]
    user_id = update.effective_user.id
    if account_count(user_id) >= 5:
        context.user_data.pop('profile_state', None)
        await query.edit_message_text('Da dat toi da 5 tai khoan.')
        return
    context.user_data['pending_account'] = {
        'bank_name': bank_name,
        'bank_bin': bank_bin
    }
    context.user_data['profile_state'] = 'account_no'
    await query.edit_message_text(
        f'Da chon {bank_name} ({bank_bin}). Nhap so tai khoan (chi so, toi thieu 6 so).',
        reply_markup=build_back_keyboard('bank')
    )


async def profile_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not is_allowed_user(update):
        await update.message.reply_text('Ban khong co quyen su dung bot nay.')
        return
    if update.effective_chat.type != 'private':
        return
    state = context.user_data.get('profile_state')
    if not state:
        menu_state = context.user_data.get('menu_state')
        if menu_state == 'qr':
            text = (update.message.text or '').strip()
            parts = shlex.split(text)
            if not parts:
                await update.message.reply_text('Nhap so tien va noi dung.')
                return
            amount = parts[0]
            purpose = ' '.join(parts[1:])
            context.user_data.pop('menu_state', None)
            await create_qr_request(update, context, amount, purpose)
        elif menu_state == 'bill':
            text = (update.message.text or '').strip()
            parts = shlex.split(text)
            if not parts:
                await update.message.reply_text('Nhap tong va noi dung (optional).')
                return
            total = parse_amount_to_int(parts[0])
            if total is None or total <= 0:
                await update.message.reply_text('Tong tien khong hop le.')
                return
            note = ' '.join(parts[1:]).strip()
            context.user_data['bill_total'] = total
            context.user_data['bill_note'] = note
            context.user_data.pop('menu_state', None)
            await update.message.reply_text(
                f'Chon so nguoi de chia deu. Tong: {format_vnd(total)} VND',
                reply_markup=build_bill_people_keyboard()
            )
        elif menu_state == 'group_add':
            text = (update.message.text or '').strip()
            try:
                chat_id = int(text)
            except ValueError:
                await update.message.reply_text('Chat ID khong hop le.')
                return
            if not is_allowed_user(update):
                await update.message.reply_text('Ban khong co quyen su dung bot nay.')
                context.user_data.pop('menu_state', None)
                return
            chat_title = ''
            try:
                chat = await context.bot.get_chat(chat_id)
                chat_title = (chat.title or '').strip()
            except Exception:
                logger.warning('Failed to fetch chat title for %s', chat_id)
            add_group_chat(update.effective_user.id, chat_id, chat_title)
            context.user_data.pop('menu_state', None)
            await update.message.reply_text(
                'Da them group.',
                reply_markup=build_main_menu_keyboard(is_admin=is_admin_user(update.effective_user.id))
            )
        elif menu_state == 'user_add':
            text = (update.message.text or '').strip()
            try:
                target_id = int(text)
            except ValueError:
                await update.message.reply_text('User ID khong hop le.')
                return
            if not is_admin_user(update.effective_user.id):
                await update.message.reply_text('Ban khong co quyen su dung chuc nang nay.')
                context.user_data.pop('menu_state', None)
                return
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    'INSERT OR IGNORE INTO allowed_users (user_id, created_at) VALUES (?, ?)',
                    (target_id, int(time.time()))
                )
            context.user_data.pop('menu_state', None)
            await update.message.reply_text(
                'Da them user.',
                reply_markup=build_main_menu_keyboard(is_admin=is_admin_user(update.effective_user.id))
            )
        return

    text = (update.message.text or '').strip()
    user_id = update.effective_user.id
    pending = context.user_data.get('pending_account') or {}

    if state == 'account_no':
        if not text.isdigit() or len(text) < 6:
            await update.message.reply_text('So tai khoan khong hop le. Nhap lai.')
            return
        pending['account_no'] = text
        context.user_data['pending_account'] = pending
        context.user_data['profile_state'] = 'account_name'
        await update.message.reply_text(
            'Nhap ten chu tai khoan (in hoa khong dau).',
            reply_markup=build_back_keyboard('account_no')
        )
        return

    if state == 'account_name':
        if not text:
            await update.message.reply_text('Ten khong hop le. Nhap lai.')
            return
        if account_count(user_id) >= 5:
            context.user_data.pop('profile_state', None)
            context.user_data.pop('pending_account', None)
            await update.message.reply_text('Da dat toi da 5 tai khoan.')
            return
        pending['account_name'] = text
        context.user_data['pending_account'] = pending
        save_account(user_id, pending)
        context.user_data.pop('profile_state', None)
        context.user_data.pop('pending_account', None)
        await update.message.reply_text(
            'Da luu, chon tao QR de tien hanh su dung dich vu.',
            reply_markup=build_main_menu_keyboard(is_admin=is_admin_user(update.effective_user.id))
        )
        return


async def qr_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    if not is_allowed_user(update):
        await query.edit_message_text('Ban khong co quyen su dung bot nay.')
        return

    data = query.data or ''
    if not data.startswith('qr:'):
        return

    pending = context.user_data.get('qr_pending')
    if not pending or 'payload' not in pending:
        await query.edit_message_text('Khong tim thay thong tin QR. Hay go /qr lai.')
        return

    if time.time() - float(pending.get('created_at', 0)) > 300:
        context.user_data.pop('qr_pending', None)
        await query.edit_message_text('QR da het han. Hay go /qr lai.')
        return

    payload = pending['payload']
    account_no = pending.get('account_no') or get_setting('DEFAULT_ACCOUNT_NO', '')
    account_name = pending.get('account_name') or get_setting('DEFAULT_ACCOUNT_NAME', '')
    bank_name = pending.get('bank_name') or get_setting('DEFAULT_BANK_NAME', '')
    destination = data.split(':', 1)[1]

    try:
        img = build_qr_background_image(payload, bank_name, account_name, account_no)
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        buffer.name = 'vietqr.png'

        if destination == 'group':
            group_id = get_default_group_id(update.effective_user.id)
            if not group_id:
                await query.edit_message_text('Chua co group. Dung /addgroup <chat_id> de them.')
                return
            await context.bot.send_photo(chat_id=group_id, photo=InputFile(buffer))
            await query.edit_message_text('Da gui QR vao group.')
        elif destination == 'private':
            await context.bot.send_photo(chat_id=update.effective_chat.id, photo=InputFile(buffer))
            if is_debug_enabled():
                await context.bot.send_message(chat_id=update.effective_chat.id, text=f'VietQR payload:\n{payload}')
            await query.edit_message_text('Da gui QR vao chat rieng.')
        else:
            await query.edit_message_text('Lua chon khong hop le.')
    except Exception as exc:
        logger.exception('Failed to generate or send QR')
        await query.edit_message_text(f'Khong tao duoc QR: {exc}')
    finally:
        context.user_data.pop('qr_pending', None)


def main() -> None:
    init_db()
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    async def post_init(application) -> None:
        commands = [
            BotCommand('start', 'Home'),
            BotCommand('help', 'Huong dan'),
            BotCommand('id', 'Lay chat id (group)')
        ]
        await application.bot.set_my_commands(commands)

    app.post_init = post_init
    app.add_handler(MessageHandler(filters.COMMAND & ~filters.ChatType.PRIVATE, group_block_handler))
    app.add_handler(ChatMemberHandler(bot_added_to_group_handler, ChatMemberHandler.MY_CHAT_MEMBER))
    app.add_handler(CommandHandler('start', start_handler))
    app.add_handler(CommandHandler('help', help_handler))
    app.add_handler(CommandHandler('approve', approve_handler))
    app.add_handler(CommandHandler('deny', deny_handler))
    app.add_handler(CommandHandler('id', id_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, profile_handler))
    app.add_handler(CallbackQueryHandler(bank_manage_callback, pattern='^bank:menu:'))
    app.add_handler(CallbackQueryHandler(bank_callback, pattern='^bank:'))
    app.add_handler(CallbackQueryHandler(account_select_callback, pattern='^acct:'))
    app.add_handler(CallbackQueryHandler(back_callback, pattern='^back:'))
    app.add_handler(CallbackQueryHandler(register_callback, pattern='^reg:'))
    app.add_handler(CallbackQueryHandler(menu_callback, pattern='^menu:'))
    app.add_handler(CallbackQueryHandler(group_manage_callback, pattern='^group:'))
    app.add_handler(CallbackQueryHandler(user_manage_callback, pattern='^user:'))
    app.add_handler(CallbackQueryHandler(qr_callback, pattern='^qr:'))
    app.add_handler(CallbackQueryHandler(bill_callback, pattern='^bill:'))
    app.add_handler(CallbackQueryHandler(bill_confirm_callback, pattern='^billconfirm:'))
    app.run_polling()


if __name__ == '__main__':
    main()
