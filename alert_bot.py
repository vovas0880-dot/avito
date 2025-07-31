
# -*- coding: utf-8 -*-
"""
alert_bot_ultra.py
==================
Утяжелённый alert-бот для Avito Monitor.

Главная задача НЕ меняется: через /start <main_user_id> сохраняем привязку
main_user_id -> alert_chat_id в файле (по умолчанию user_bindings.json),
чтобы основной бот мог слать карточки в этот чат через Bot API.

Дополнительно:
- Надёжное хранилище привязок: атомарная запись, резервные копии, журнал (JSONL),
  валидация структуры, мульти-пути, попытка автопочинки.
- Блокировка файла (lock-file) для конкурентных записей.
- Поддержка /start c аргументом:
    * число (как раньше), 
    * base64url с {"uid": <int>, "sig": <hmac_sha256>} — опционально (SECRET_SALT).
- Команды: /id, /status, /bindings (страницы), /unbind <uid> (админ),
  /rebind <uid> <chat_id> (админ), /export_bindings (json), /import_bindings (админ, reply с json).
- Усиленная диагностика: размер/модификация файла, кол-во привязок, примеры.
- Небольшой rate-limit для ответов, чтобы не ловить 429 от Telegram на частые команды.

ENV:
    ALERT_BOT_TOKEN=xxxxx
    BINDINGS_FILE=user_bindings.json
    BINDINGS_ALT_PATHS=user_bindings.json;data/bindings.json
    BINDINGS_BACKUP_DIR=.backups
    BINDINGS_BACKUP_KEEP=5
    BINDINGS_AUDIT_FILE=bindings_audit.jsonl
    SECRET_SALT=optional_secret_for_hmac
    ADMIN_CHAT_ID=151234567

Зависимости: aiogram 3.x, python 3.10+
"""

import os
import io
import json
import hmac
import base64
import hashlib
import time
import asyncio
import logging
from dataclasses import dataclass
from typing import Dict, Any, Optional, List

from aiogram import Bot, Dispatcher, F, Router, types
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import Command
from aiogram.types import BufferedInputFile
import aiohttp
# ---------- логирование ----------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("alert_ultra")

# ---------- env ----------
BINDINGS_FILE = os.getenv("BINDINGS_FILE", "user_bindings.json")
BINDINGS_ALT_PATHS = os.getenv("BINDINGS_ALT_PATHS", "user_bindings.json;data/bindings.json")
BINDINGS_BACKUP_DIR = os.getenv("BINDINGS_BACKUP_DIR", ".backups")
BINDINGS_BACKUP_KEEP = int(os.getenv("BINDINGS_BACKUP_KEEP", "5"))
BINDINGS_AUDIT_FILE = os.getenv("BINDINGS_AUDIT_FILE", "bindings_audit.jsonl")
SUPPORT_LINK = os.getenv("SUPPORT_LINK", "https://t.me/Multiscan_service1")
SECRET_SALT = os.getenv("SECRET_SALT")  # если задан — включит проверку подписи для b64 payload
ADMIN_CHAT_ID = int(os.getenv("ADMIN_CHAT_ID", "0")) if os.getenv("ADMIN_CHAT_ID", "").lstrip("-").isdigit() else None

# --------- утилиты ----------
def _now() -> float:
    return time.time()

def _ensure_dir(path: str):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)

def _append_jsonl(path: str, obj: dict):
    try:
        _ensure_dir(path)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.warning("audit append failed: %s", e)

def _fsync_replace(path: str, data: str):
    """Атомарная запись с fsync"""
    _ensure_dir(path)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

# --------- простая блокировка файла ----------
class FileLock:
    def __init__(self, path: str, timeout: float = 5.0):
        self.lock_path = path + ".lock"
        self.timeout = timeout

    async def __aenter__(self):
        start = _now()
        while True:
            try:
                # эксклюзивное создание файла
                fd = os.open(self.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.close(fd)
                return self
            except FileExistsError:
                if _now() - start > self.timeout:
                    # протухший lock — удаляем
                    try:
                        os.remove(self.lock_path)
                        logger.warning("stale lock removed: %s", self.lock_path)
                    except Exception:
                        pass
                    # ещё одна попытка
                await asyncio.sleep(0.05)

    async def __aexit__(self, exc_type, exc, tb):
        try:
            os.remove(self.lock_path)
        except Exception:
            pass

# --------- хранилище привязок ----------
@dataclass
class BindingStore:
    main_path: str
    alt_paths: List[str]
    backup_dir: str
    keep_backups: int
    audit_file: str

    def _paths_to_try(self) -> List[str]:
        paths = []
        if self.main_path:
            paths.append(self.main_path)
        for p in self.alt_paths:
            if p and p not in paths:
                paths.append(p)
        return paths

    def _validate(self, data: Dict[str, Any]) -> Dict[str, int]:
        """Пытается привести к {str(main_user_id): int(chat_id)}"""
        out: Dict[str, int] = {}
        if not isinstance(data, dict):
            return out
        for k, v in data.items():
            try:
                ks = str(k)
                # принимаем int/str -> int
                vi = int(v)
                out[ks] = vi
            except Exception:
                logger.warning("Skip invalid binding entry: %r -> %r", k, v)
        return out

    def load(self) -> Dict[str, int]:
        # читаем первый валидный файл
        for p in self._paths_to_try():
            try:
                if not os.path.exists(p):
                    continue
                with open(p, "r", encoding="utf-8") as f:
                    raw = f.read().strip()
                if not raw:
                    continue
                data = json.loads(raw)
                valid = self._validate(data)
                if valid:
                    if p != self.main_path:
                        # мигрируем в основной путь
                        logger.info("Bindings loaded from alt path: %s", p)
                    return valid
            except Exception as e:
                logger.error("Failed to read %s: %s", p, e)
                continue
        # пусто — создаём
        self.save({})
        return {}

    def _backup(self, path: str, content: str):
        try:
            os.makedirs(self.backup_dir, exist_ok=True)
            ts = int(_now())
            name = f"bindings_{ts}.json"
            dst = os.path.join(self.backup_dir, name)
            with open(dst, "w", encoding="utf-8") as f:
                f.write(content)
            # ротация
            items = sorted([x for x in os.listdir(self.backup_dir) if x.endswith(".json")])
            if len(items) > self.keep_backups:
                for old in items[:len(items) - self.keep_backups]:
                    try:
                        os.remove(os.path.join(self.backup_dir, old))
                    except Exception:
                        pass
        except Exception as e:
            logger.warning("Backup failed: %s", e)

    def save(self, data: Dict[str, int]):
        # валидируем перед сохранением
        valid = self._validate(data)
        payload = json.dumps(valid, ensure_ascii=False, indent=2)
        self._backup(self.main_path, payload)
        _fsync_replace(self.main_path, payload)

    async def update_binding(self, uid: int, chat_id: int) -> Dict[str, int]:
        async with FileLock(self.main_path, timeout=5.0):
            data = self.load()
            before = data.get(str(uid))
            data[str(uid)] = int(chat_id)
            self.save(data)
            _append_jsonl(self.audit_file, {
                "ts": _now(), "action": "bind",
                "main_user_id": uid, "chat_id": chat_id, "prev": before
            })
            return data

    async def remove_binding(self, uid: int) -> bool:
        async with FileLock(self.main_path, timeout=5.0):
            data = self.load()
            existed = str(uid) in data
            if existed:
                prev = data.pop(str(uid))
                self.save(data)
                _append_jsonl(self.audit_file, {
                    "ts": _now(), "action": "unbind",
                    "main_user_id": uid, "chat_id": prev
                })
            return existed

    def stat(self) -> Dict[str, Any]:
        paths = self._paths_to_try()
        exists: Dict[str, bool] = {}
        size: Dict[str, int] = {}
        mtime: Dict[str, int] = {}
        for p in paths:
            try:
                st = os.stat(p)
                exists[p] = True
                size[p] = st.st_size
                mtime[p] = int(st.st_mtime)
            except FileNotFoundError:
                exists[p] = False
        return {"paths": paths, "exists": exists, "size": size, "mtime": mtime}

# --------- инициализация стора ----------
alt_paths = [p.strip() for p in BINDINGS_ALT_PATHS.split(";") if p.strip()]
STORE = BindingStore(
    main_path=BINDINGS_FILE,
    alt_paths=alt_paths,
    backup_dir=BINDINGS_BACKUP_DIR,
    keep_backups=BINDINGS_BACKUP_KEEP,
    audit_file=BINDINGS_AUDIT_FILE,
)

# ---------- Router ----------
router = Router(name="alert_ultra")

# ---------- Rate limit простенький на ответы ----------
class SimpleRate:
    def __init__(self, min_interval=0.8):
        self.min_interval = float(min_interval)
        self.last: Dict[int, float] = {}

    def allowed(self, uid: int) -> bool:
        now = _now()
        prev = self.last.get(uid, 0.0)
        if now - prev >= self.min_interval:
            self.last[uid] = now
            return True
        return False

RL = SimpleRate(min_interval=0.6)

# ---------- start payload helpers ----------
def _parse_start_arg(arg: str) -> Optional[int]:
    """Позволяет числа и b64url с {"uid":..,"sig":..} при наличии SECRET_SALT"""
    if not arg:
        return None
    a = arg.strip()
    if a.lstrip("-").isdigit():
        return int(a)
    # base64url decode
    try:
        pad = '=' * ((4 - len(a) % 4) % 4)
        raw = base64.urlsafe_b64decode(a + pad)
        j = json.loads(raw.decode("utf-8"))
        uid = int(j.get("uid"))
        sig = str(j.get("sig", ""))
        if not SECRET_SALT:
            return uid  # подпись не проверяем
        mac = hmac.new(SECRET_SALT.encode("utf-8"), str(uid).encode("utf-8"), hashlib.sha256).hexdigest()
        if hmac.compare_digest(mac, sig):
            return uid
        logger.warning("Invalid signature in start arg")
        return None
    except Exception as e:
        logger.warning("Failed to parse start arg: %s", e)
        return None

# ---------- Handlers ----------
@router.message(Command("start"))
async def start_cmd(m: types.Message):
    try:
        if not RL.allowed(m.chat.id):
            return
        args = (m.text or "").split(maxsplit=1)
        main_user_id = None
        if len(args) >= 2:
            main_user_id = _parse_start_arg(args[1])
        if main_user_id is None:
            await m.answer(
                "Это бот-оповещатель для Avito Monitor.\n\n"
                "Чтобы привязать ваш чат к основному боту — нажмите кнопку из основного бота (она запускает меня с параметром).\n\n"
                f"Поддержка: {SUPPORT_LINK}",
                disable_web_page_preview=True
            )
            return
        data = await STORE.update_binding(int(main_user_id), int(m.chat.id))
        await m.answer(
            "✅ Привязка выполнена!\n\n"
            f"Ваш chat_id: <code>{m.chat.id}</code>\n"
            f"Основной пользователь: <code>{main_user_id}</code>\n"
            f"Всего привязок: <b>{len(data)}</b>\n\n"
            "Теперь вернитесь в основной бот и создайте поиск."
        )
    except Exception as e:
        logger.exception("start_cmd error: %s", e)
        await m.answer(
            "Произошла ошибка при обработке команды. Попробуйте еще раз или обратитесь в поддержку.\n\n"
            f"Поддержка: {SUPPORT_LINK}",
            disable_web_page_preview=True
        )

@router.message(Command("id"))
async def id_cmd(m: types.Message):
    try:
        if not RL.allowed(m.chat.id):
            return
        await m.answer(f"Ваш chat_id: <code>{m.chat.id}</code>")
    except Exception as e:
        logger.exception("id_cmd error: %s", e)
        await m.answer("Ошибка получения ID")

@router.message(Command("status"))
async def status_cmd(m: types.Message):
    try:
        if not RL.allowed(m.chat.id):
            return
        info = STORE.stat()
        data = STORE.load()
        sample = []
        for i, (k, v) in enumerate(list(data.items())[:10]):
            sample.append(f"  {k} → {v}")
        lines = [
            "<b>Статус</b>",
            f"Файлы: {', '.join(info['paths'])}",
            f"Всего привязок: {len(data)}",
        ]
        for p in info["paths"]:
            ex = info["exists"].get(p, False)
            sz = info["size"].get(p, 0)
            mt = info["mtime"].get(p, 0)
            lines.append(f"• {p}: {'OK' if ex else '—'} size={sz} mtime={mt}")
        if sample:
            lines.append("\nПримеры:\n" + "\n".join(sample))
        await m.answer("\n".join(lines), disable_web_page_preview=True)
    except Exception as e:
        logger.exception("status_cmd error: %s", e)
        await m.answer(f"Ошибка статуса: {e}")

@router.message(Command("bindings"))
async def bindings_cmd(m: types.Message):
    """Вывести список привязок (постранично)"""
    try:
        if not RL.allowed(m.chat.id):
            return
        data = STORE.load()
        items = sorted(data.items(), key=lambda kv: int(kv[0]))
        if not items:
            await m.answer("Пока нет ни одной привязки.")
            return
        # пагинация через аргументы /bindings [page] [per_page]
        parts = (m.text or "").split()
        page = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 1
        per_page = int(parts[2]) if len(parts) >= 3 and parts[2].isdigit() else 50
        page = max(1, page)
        per_page = max(1, min(200, per_page))
        start = (page - 1) * per_page
        chunk = items[start:start+per_page]
        lines = [f"<b>Привязки</b> (page {page}, per {per_page}, total {len(items)})"]
        for k, v in chunk:
            lines.append(f"{k} → {v}")
        if start + per_page < len(items):
            lines.append(f"\nДальше: /bindings {page+1} {per_page}")
        await m.answer("\n".join(lines))
    except Exception as e:
        logger.exception("bindings_cmd error: %s", e)
        await m.answer("Ошибка показа привязок")

def _admin(m: types.Message) -> bool:
    return ADMIN_CHAT_ID is not None and m.chat.id == ADMIN_CHAT_ID

@router.message(Command("unbind"))
async def unbind_cmd(m: types.Message):
    try:
        if not _admin(m):
            await m.reply("Команда доступна только админу.")
            return
        parts = (m.text or "").split()
        if len(parts) < 2 or not parts[1].lstrip("-").isdigit():
            await m.reply("Формат: /unbind <main_user_id>")
            return
        uid = int(parts[1])
        ok = await STORE.remove_binding(uid)
        await m.reply("Удалено" if ok else "Такой привязки не было")
    except Exception as e:
        logger.exception("unbind_cmd error: %s", e)
        await m.reply("Ошибка unbind")

@router.message(Command("rebind"))
async def rebind_cmd(m: types.Message):
    try:
        if not _admin(m):
            await m.reply("Команда доступна только админу.")
            return
        parts = (m.text or "").split()
        if len(parts) < 3 or (not parts[1].lstrip("-").isdigit()) or (not parts[2].lstrip("-").isdigit()):
            await m.reply("Формат: /rebind <main_user_id> <chat_id>")
            return
        uid = int(parts[1])
        chat_id = int(parts[2])
        data = await STORE.update_binding(uid, chat_id)
        await m.reply(f"Готово. Всего привязок: {len(data)}")
    except Exception as e:
        logger.exception("rebind_cmd error: %s", e)
        await m.reply("Ошибка rebind")

@router.message(Command("export_bindings"))
async def export_cmd(m: types.Message):
    try:
        if not _admin(m):
            await m.reply("Команда доступна только админу.")
            return
        data = STORE.load()
        buf = io.BytesIO(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"))
        await m.answer_document(BufferedInputFile(buf.getvalue(), filename="user_bindings.json"))
    except Exception as e:
        logger.exception("export_cmd error: %s", e)
        await m.reply("Ошибка экспорта")

@router.message(Command("import_bindings"))
async def import_cmd(m: types.Message, bot: Bot):
    try:
        if not _admin(m):
            await m.reply("Команда доступна только админу.")
            return
        if not m.reply_to_message or not m.reply_to_message.document:
            await m.reply("Ответьте на json-файл привязок командой /import_bindings")
            return

        document = m.reply_to_message.document
        file_info = await bot.get_file(document.file_id)
        file_path = file_info.file_path

        # Теперь загружаем сам файл по URL:
        file_url = f"https://api.telegram.org/file/bot{bot.token}/{file_path}"
        async with aiohttp.ClientSession() as session:
            async with session.get(file_url) as resp:
                file_bytes = await resp.read()

        import json
        data = json.loads(file_bytes.decode("utf-8"))
        STORE.save(data)
        await m.reply("Импорт успешно завершён.")

    except Exception as e:
        await m.reply(f"Ошибка импорта: {e}")





@router.message(F.text)
async def echo(m: types.Message):
    """Эхо/подсказка — остаётся на месте, но с rate-limit"""
    try:
        if not RL.allowed(m.chat.id):
            return
        await m.answer(
            "🤖 Бот-оповещатель активен\n"
            f"Ваш chat_id: <code>{m.chat.id}</code>\n\n"
            "Команды:\n"
            "• /start <main_user_id> — привязка\n"
            "• /id — показать ваш chat_id\n"
            "• /status — проверить привязки\n"
            "• /bindings [page] [per_page] — список\n"
            "• /unbind <uid>, /rebind <uid> <chat_id> — админ\n"
            "• /export_bindings, /import_bindings — админ"
        )
    except Exception as e:
        logger.exception("echo error: %s", e)

# ---------- main ----------
async def main():
    try:
        try:
            from dotenv import load_dotenv  # type: ignore
        except Exception:
            def load_dotenv(*args, **kwargs):  # type: ignore
                return None
        # грузим .env в директории файла
        try:
            from pathlib import Path
            dotenv_path = Path(__file__).resolve().parent / ".env"
            load_dotenv(dotenv_path)
        except Exception:
            load_dotenv()

        token = os.getenv("ALERT_BOT_TOKEN")
        if not token:
            logger.error("ALERT_BOT_TOKEN не задан!")
            print("ОШИБКА: ALERT_BOT_TOKEN не задан! Добавьте токен в Secrets или .env")
            return

        bot = Bot(token=token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
        dp = Dispatcher()
        dp.include_router(router)

        await bot.set_my_commands([
            types.BotCommand(command="start", description="Привязать к основному боту"),
            types.BotCommand(command="id", description="Показать ваш chat_id"),
            types.BotCommand(command="status", description="Проверить привязки"),
            types.BotCommand(command="bindings", description="Список привязок"),
            types.BotCommand(command="unbind", description="(admin) Удалить привязку"),
            types.BotCommand(command="rebind", description="(admin) Прописать привязку"),
            types.BotCommand(command="export_bindings", description="(admin) Экспорт привязок"),
            types.BotCommand(command="import_bindings", description="(admin) Импорт привязок"),
        ])

        logger.info("Alert-бот (ultra) запущен")
        await dp.start_polling(bot)

    except Exception as e:
        logger.exception("Критическая ошибка: %s", e)
        print(f"КРИТИЧЕСКАЯ ОШИБКА: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Alert-бот остановлен")
        print("Alert-бот остановлен")
    except Exception as e:
        logger.exception("Неожиданная ошибка: %s", e)
        print(f"НЕОЖИДАННАЯ ОШИБКА: {e}")
