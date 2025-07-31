# -*- coding: utf-8 -*-
"""
Avito Monitor Bot (aiogram 3.x)
— v4.3 (fixed+kf+429) — стабильная версия
   • Исправлены регулярки (реальные \d, \s и т.д.)
   • Переводы строк теперь настоящие \n (больше нет <br> и "Unsupported start tag \"br\"")
   • Устойчивый приём ключей (и «Ключ: …», и просто UUID)
   • Мягкий бэкофф для HTTP 429/403 (Retry-After + экспоненциальный backoff + джиттер)
   • Подправлены таймауты aiohttp
"""

import os
import re
import time
import asyncio
import html
import base64
import json
import aiohttp
from avito_anti429_ultra import patch_watcher_ultra, extend_app_ultra
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Deque, Callable, cast, Any, Set, Tuple
from collections import deque
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, urlunparse, parse_qs, parse_qsl, urlencode, unquote
import uuid
import logging

from aiogram import Bot, Dispatcher, F, Router, types
from telegram_utils import sanitize_newlines, safe_send_message
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties
from aiogram.filters import Command, StateFilter
from aiogram.fsm.state import StatesGroup, State
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.memory import MemoryStorage
from bs4 import BeautifulSoup  # type: ignore[reportMissingImports]
from bs4.element import Tag


logger = logging.getLogger(__name__)

try:
    from zoneinfo import ZoneInfo  # py>=3.9
except Exception:
    ZoneInfo = None  # type: ignore

try:
    from dotenv import load_dotenv  # type: ignore
except Exception:

    def load_dotenv(*args, **kwargs):  # type: ignore
        return None


# keep-alive (Replit/Render). Если модуля нет — no-op.
try:
    from background import keep_alive  # type: ignore
except Exception:

    def keep_alive():  # type: ignore
        return None


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# ===== ENV =====
FRESH_WINDOW_SEC = int(os.getenv("FRESH_WINDOW_SEC",
                                 "300"))  # окно «только новые»
POLL_PERIOD_SEC = int(os.getenv("POLL_PERIOD_SEC",
                                "60"))  # период опроса (сек)
SUPPORT_LINK = os.getenv("SUPPORT_LINK", "https://t.me/Multiscan_service1")
PRIME_ON_START = os.getenv("PRIME_ON_START", "1") == "1"
START_STRICT = os.getenv("START_STRICT", "1") == "1"
START_GRACE_SEC = int(os.getenv("START_GRACE_SEC", "10"))
DISPLAY_TZ_NAME = os.getenv("DISPLAY_TZ", "Europe/Moscow")
DISPLAY_TZ_OFFSET_MIN = int(os.getenv("DISPLAY_TZ_OFFSET_MIN", "180"))

# ADMIN_CHAT_ID как int (или None)
_ADMIN_STR = os.getenv("ADMIN_CHAT_ID")
ADMIN_CHAT_ID: Optional[int] = int(_ADMIN_STR) if (
    _ADMIN_STR and _ADMIN_STR.lstrip("-").isdigit()) else None

# ===== Настройки alert-бота =====
ALERT_BOT_TOKEN = os.getenv("ALERT_BOT_TOKEN")  # токен бота-оповещателя
ALERT_BOT_USERNAME = os.getenv("ALERT_BOT_USERNAME",
                               "")  # юзернейм бота-оповещателя без @
BINDINGS_FILE = os.getenv(
    "BINDINGS_FILE",
    "user_bindings.json")  # привязки main_user_id -> alert_chat_id

# ===== Файлы хранения =====
KEYS_FILE = os.getenv("KEYS_FILE", "issued_keys.json")
SENT_FILE = os.getenv(
    "SENT_FILE",
    "sent_ads.json")  # { user_id: { ad_id: ts }, "_global": {...} }
ACCOUNTS_FILE = os.getenv("ACCOUNTS_FILE",
                          "accounts.json")  # учётка пользователя
DEDUP_TTL_DAYS = int(os.getenv("DEDUP_TTL_DAYS",
                               "14"))  # сколько хранить следы
DEDUP_GLOBAL = os.getenv("DEDUP_GLOBAL", "1") == "1"  # глобальный антидубликат

# ===== Регэксп ключа (поддерживает «Ключ: …» и голый UUID где угодно в тексте) =====
KEY_RE = re.compile(
    r'(?i)(?:^|\s)(?:ключ\s*:\s*)?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:\s|$)'
)


# ===== helpers =====
def _tz():
    if ZoneInfo is not None:
        try:
            return ZoneInfo(DISPLAY_TZ_NAME)
        except Exception:
            pass
    # fallback — фиксированный сдвиг
    return timezone(timedelta(minutes=DISPLAY_TZ_OFFSET_MIN))


def _fmt_dt(ts: Optional[float]) -> str:
    if not ts:
        return "—"
    return datetime.fromtimestamp(float(ts),
                                  _tz()).strftime("%d.%m.%Y %H:%M:%S")


def _sanitize_newlines(text: str) -> str:
    """Backward compatible wrapper for :func:`telegram_utils.sanitize_newlines`."""
    return sanitize_newlines(text)
    t = (text or "")
    return t.replace("<br/>", "\n").replace("<br />",
                                            "\n").replace("<br>", "\n")


# ==== LICENSE ====
class LicenseManager:

    def __init__(self):
        self._expires: Dict[int, float] = {}  # user_id -> epoch_seconds (UTC)

    def activate_for(self, user_id: int, hours: int = 24):
        self._expires[user_id] = (time.time() + hours * 3600)

    def activate_until(self, user_id: int, expires_ts: float):
        self._expires[user_id] = float(expires_ts)

    def is_active(self, user_id: int) -> bool:
        ts = self._expires.get(user_id)
        return (ts is not None) and (ts > time.time())

    def expiry_dt(self, user_id: int) -> Optional[datetime]:
        ts = self._expires.get(user_id)
        return datetime.fromtimestamp(ts, _tz()) if ts else None


@dataclass
class SubscriberFilter:
    keywords_all: List[str] = field(default_factory=list)  # целевые
    keywords_any: List[str] = field(default_factory=list)
    keywords_stop: List[str] = field(default_factory=list)  # СТОП-слова
    price_min: Optional[int] = None
    price_max: Optional[int] = None


@dataclass
class Subscription:
    id: int
    user_id: int
    search_key: str
    url: str
    flt: SubscriberFilter = field(default_factory=SubscriberFilter)
    name: Optional[str] = None  # название
    only_new: bool = True  # «только новые»
    forward_chat_id: Optional[int] = None  # не используется
    started_ts: float = field(default_factory=lambda: time.time()
                              )  # точка отсечения «до создания слота»


def _normalize_url(url: str) -> str:
    u = urlparse(url.strip())
    if not u.scheme:
        u = u._replace(scheme="https")
    netloc = u.netloc or "www.avito.ru"
    keep: Dict[str, str] = {}
    for k, v in parse_qsl(u.query, keep_blank_values=True):
        if k.lower().startswith("utm_"):
            continue
        keep[k] = v
    query = urlencode(sorted(keep.items()))
    u2 = u._replace(netloc=netloc, query=query)
    return urlunparse(u2)


def search_key_from_url(url: str) -> str:
    return _normalize_url(url)


def is_valid_avito_url(url: str) -> bool:
    parsed = urlparse(url)
    return bool(parsed.netloc) and parsed.netloc.endswith('avito.ru')


def avito_short_url(full_url: str) -> str:
    m = re.search(r"/(\d{7,})", full_url)
    if m:
        return f"https://www.avito.ru/{m.group(1)}"
    u = urlparse(full_url)
    return urlunparse((u.scheme or "https", u.netloc
                       or "www.avito.ru", u.path, "", "", ""))


_MONTHS_RU = {
    "января": 1,
    "февраля": 2,
    "марта": 3,
    "апреля": 4,
    "мая": 5,
    "июня": 6,
    "июля": 7,
    "августа": 8,
    "сентября": 9,
    "октября": 10,
    "ноября": 11,
    "декабря": 12,
}


def _parse_avito_date(date_str: str):
    """Разбор дат из листинга Авито."""
    if not date_str:
        return None
    s = date_str.strip().lower()
    now = datetime.now()

    # Только что
    if "только что" in s:
        return now.timestamp()

    # X минут назад
    m = re.search(r"(\d+)\s*минут", s)
    if m:
        return (now - timedelta(minutes=int(m.group(1)))).timestamp()

    # Минуту назад
    if "минуту назад" in s:
        return (now - timedelta(minutes=1)).timestamp()

    # X часов назад
    m = re.search(r"(\d+)\s*час", s)
    if m:
        return (now - timedelta(hours=int(m.group(1)))).timestamp()

    # Час назад
    if "час назад" in s:
        return (now - timedelta(hours=1)).timestamp()

    # Сегодня/вчера HH:MM
    m = re.search(r"(сегодня|вчера)[,\s]+(\d{1,2}:\d{2})", s)
    if m:
        day = now.date() if m.group(1) == "сегодня" else (
            now - timedelta(days=1)).date()
        hh, mm = map(int, m.group(2).split(":"))
        return datetime(day.year, day.month, day.day, hh, mm).timestamp()

    # DD месяц HH:MM
    m = re.search(r"(\d{1,2})\s+([а-я]+)[,\s]+(\d{1,2}:\d{2})", s)
    if m:
        dd = int(m.group(1))
        mon = _MONTHS_RU.get(m.group(2))
        hh, mm = map(int, m.group(3).split(":"))
        if mon:
            return datetime(datetime.now().year, mon, dd, hh, mm).timestamp()

    # DD месяц (без времени)
    m = re.search(r"(\d{1,2})\s+([а-я]+)$", s)
    if m:
        dd = int(m.group(1))
        mon = _MONTHS_RU.get(m.group(2))
        if mon:
            return datetime(datetime.now().year, mon, dd, 0, 0).timestamp()

    return None


@dataclass
class Ad:
    ad_id: str
    url: str
    title: str = ""
    price: Optional[int] = None
    location: str = ""
    date_str: str = ""
    published_ts: Optional[float] = None
    description: str = ""
    image_url: Optional[str] = None
    seller_name: Optional[str] = None
    seller_id: Optional[str] = None
    price_badge: Optional[str] = None
    features: List[str] = field(default_factory=list)  # например: "Рассрочка"
    views: Optional[int] = None
    is_verified: bool = False


def _get_text(tag: Optional[Tag]) -> str:
    """Безопасно извлекает текст из bs4-объекта"""
    if tag is None:
        return ""
    try:
        return tag.get_text(strip=True)
    except Exception:
        return str(tag) if tag else ""


def try_extract_filters_from_url(url: str) -> SubscriberFilter:
    flt = SubscriberFilter()
    try:
        u = urlparse(url)
        qs = parse_qs(u.query)
        if "q" in qs and qs["q"]:
            qval = unquote(qs["q"][0]).strip()
            words = [w for w in re.split(r"[, \t]+", qval) if w]
            if words:
                flt.keywords_all = words

        fval = qs.get("f", [None])[0]
        if fval:
            s = fval.strip()
            pad = '=' * ((4 - len(s) % 4) % 4)
            raw = base64.urlsafe_b64decode(s + pad)
            try:
                j = json.loads(raw.decode("utf-8", errors="ignore"))
                text_parts: List[str] = []
                if isinstance(j, dict):

                    def pick(obj, keys):
                        for k in keys:
                            v = obj.get(k)
                            if isinstance(v, str) and v:
                                text_parts.append(v)

                    pick(j, ["brand", "model", "storage", "keyword", "q"])
                    if "params" in j and isinstance(j["params"], list):
                        for p in j["params"]:
                            if isinstance(p, dict):
                                pick(p, [
                                    "brand", "model", "storage", "value",
                                    "name"
                                ])
                if text_parts:
                    for token in text_parts:
                        for w in re.split(r"[,/ \t]+", str(token)):
                            w = w.strip()
                            if w and w.lower() not in [
                                    x.lower() for x in flt.keywords_all
                            ]:
                                flt.keywords_all.append(w)
            except Exception:
                pass
    except Exception:
        pass
    return flt


class Watcher:
    
    
    

    def __init__(
        self,
        search_key: str,
        url: str,
        bot: Bot,
        on_deliver: Optional[Callable[[int, Ad], None]] = None,
    ):
        self.search_key = search_key
        self.url = url
        self.bot = bot
        self.subscribers: Dict[int, Subscription] = {}
        self.task: Optional[asyncio.Task] = None
        self.seen: Dict[str, float] = {}
        self.interval_min = self.interval_max = self._interval = max(
            1.0, float(POLL_PERIOD_SEC))
        self._session: Optional["aiohttp.ClientSession"] = None
        self.on_deliver = on_deliver
        self.last_success = None             # Время последнего успешного запроса (200)
        self.last_429_start = None           # Время начала бана (429)
        self._429_intervals: List[Tuple[float, float, float]] = []  # [(start, end, duration)]
        self._ok_intervals: List[Tuple[float, float, float]] = []   # [(start, end, duration)]
        self._interval = float(POLL_PERIOD_SEC)  # Твой стандартный интервал
        patch_watcher_ultra(Watcher)


    async def start(self):
        if self.task and not self.task.done():
            return
        if PRIME_ON_START:
            await self._prime_seen(30)
        self.task = asyncio.create_task(self._run(),
                                        name=f"watch:{self.search_key}")

    async def stop(self):
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
            self.task = None
        if self._session:
            await self._session.close()
            self._session = None

    def has_subscribers(self):
        return bool(self.subscribers)

    def add_sub(self, sub: Subscription):
        self.subscribers[sub.user_id] = sub

    def remove_sub(self, user_id: int):
        self.subscribers.pop(user_id, None)

    async def _ensure_session(self):
        if self._session and not self._session.closed:
            return self._session
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        # trust_env=True чтобы можно было подложить прокси через переменные окружения
        self._session = aiohttp.ClientSession(timeout=timeout, trust_env=True)
        return self._session

    def _fmt_price(self, v: Optional[int]) -> str:
        if v is None:
            return "—"
        return f"{v:,}".replace(",", " ") + " ₽"

    async def _enrich_ad_details(self, ad: Ad):
        try:
            session = await self._ensure_session()
            headers = {
                "User-Agent":
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
                "Accept-Language": "ru,en;q=0.9",
                "Cache-Control": "no-cache",
            }
            async with session.get(ad.url, headers=headers) as r:
                if r.status != 200:
                    return
                txt = await r.text()
                soup = BeautifulSoup(txt, "html.parser")

                # Имя продавца
                for selector in (
                        '[data-marker="seller-info/name"]',
                        '[data-marker="seller-link"]',
                        '.seller-info-name',
                        '.seller-link',
                ):
                    pe = soup.select_one(selector)
                    if pe:
                        ad.seller_name = _get_text(pe)
                        break

                # ID продавца
                m = re.search(r'"ownerId"\s*:\s*"?(?P<id>\d+)"?', txt)
                if m:
                    ad.seller_id = m.group("id")

                # Бейдж цены
                for b in [
                        "Ниже рынка", "Хорошая цена", "Рыночная цена",
                        "Выше рынка"
                ]:
                    if b in txt:
                        ad.price_badge = b
                        break

                if "рассроч" in txt.lower() and "Рассрочка" not in ad.features:
                    ad.features.append("Рассрочка")

                # Верификация
                for selector in ('[data-marker="verified"]', '.verified-badge',
                                 '.is-verified'):
                    if soup.select_one(selector):
                        ad.is_verified = True
                        break

                # Просмотры
                for selector in ('[data-marker="total-views"]', '.item-views',
                                 '.views-count'):
                    t = soup.select_one(selector)
                    if t:
                        vm = re.search(r"\d+", _get_text(t))
                        if vm:
                            ad.views = int(vm.group())
                            break

        except Exception as e:
            logger.warning(f"Ошибка обогащения объявления {ad.url}: {e}")

    def _build_caption(self, ad: Ad) -> str:
        short = avito_short_url(ad.url)
        lines = [f"<b>{html.escape(ad.title)}</b>", ""]

        if ad.price is not None:
            price_line = f"💸 <b>{self._fmt_price(ad.price)}</b>"
            badge_parts: List[str] = []
            if ad.price_badge:
                badge_parts.append(f"✅ «{html.escape(ad.price_badge)}»")
            for ftr in ad.features:
                badge_parts.append(f"«{html.escape(ftr)}»")
            if badge_parts:
                price_line += " " + " ".join(badge_parts)
            lines.append(price_line)

        if ad.published_ts:
            lines.append("🗓 " + _fmt_dt(ad.published_ts))
        elif ad.date_str:
            lines.append("🗓 " + html.escape(ad.date_str))

        if ad.seller_name:
            icon = "🏪" if "магазин" in ad.seller_name.lower() else "👤"
            lines.append(f"{icon} {html.escape(ad.seller_name)}")

        if ad.seller_id:
            lines.append(f"🆔 {ad.seller_id}")

        if ad.views:
            lines.append(f"👁 {ad.views} просмотров")

        if ad.is_verified:
            lines.append("✅ Проверенный")

        lines.append("")
        lines.append(short)
        return "\n".join(lines)
    def _auto_tune_interval(self):
        # если у тебя накопилось хотя бы 3 периода без бана — считаем статистику
        if len(self._ok_intervals) >= 3:
            durations = [d[2] for d in self._ok_intervals[-10:]]  # последние 10 периодов
            avg = sum(durations) / len(durations)
            # с запасом (например, работай только 70% от этого времени)
            new_interval = max(10, min(300, avg * 0.7))
            # чтобы не прыгал резко, делай плавное приближение
            self._interval = self._interval * 0.7 + new_interval * 0.3
            logging.warning(
                f"[TUNE] Новый автоинтервал: {self._interval:.1f} сек (avg ok={avg:.1f})"
            )

    
    async def _fetch(self):
        session = await self._ensure_session()
        headers = {
            "User-Agent": "...",  # твой юзер-агент
            "Accept-Language": "ru,en;q=0.9",
            "Cache-Control": "no-cache",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        }
        max_attempts = 5
        for attempt in range(max_attempts):
            try:
                async with session.get(self.url, headers=headers) as r:
                    now = time.time()
                    if r.status == 429:
                        # Фиксируем старт бана, если впервые
                        if self.last_429_start is None:
                            self.last_429_start = now
                            # Сохраняем "чистое" время до бана, если знаем
                            if self.last_success:
                                ok_dur = now - self.last_success
                                self._ok_intervals.append((self.last_success, now, ok_dur))
                                logging.warning(f"[BAN] Работал без бана {ok_dur:.1f} сек")
                        # Динамически увеличиваем интервал если часто 429
                        self._auto_tune_interval()
                        # Твой обычный backoff
                        ra = r.headers.get("Retry-After")
                        wait = float(ra) if ra else min(60 * (2**attempt), 300)
                        await asyncio.sleep(wait)
                        continue

                    if r.status == 200:
                        # Если был бан — запоминаем длительность бана
                        if self.last_429_start is not None:
                            ban_dur = now - self.last_429_start
                            self._429_intervals.append((self.last_429_start, now, ban_dur))
                            logging.warning(f"[BAN] 429 закончился, длился {ban_dur:.1f} сек")
                            # Сохраним в файл для истории
                            with open("ban_intervals.json", "a", encoding="utf-8") as f:
                                f.write(json.dumps({
                                    "ban_start": self.last_429_start,
                                    "ban_end": now,
                                    "ban_duration": ban_dur,
                                    "url": self.url,
                                }) + "\n")
                            self.last_429_start = None
                            self._auto_tune_interval()
                        # Запоминаем время последнего успеха
                        self.last_success = now
                        return await r.text()
                    # ... остальная обработка (403, 503 и т.п.)
            except Exception as e:
                logging.error(f"Ошибка запроса: {e}")
                await asyncio.sleep(2 + attempt)
        return None

    async def _prime_seen(self, limit=30):
        html_text = await self._fetch()
        if not html_text:
            return
        for ad in self._parse_top(html_text, limit):
            self.seen[ad.ad_id] = time.time()

    def _parse_top(self, html_text: str, limit=20):
        soup = BeautifulSoup(html_text, "html.parser")

        # контейнеры списка
        for selector in ('div[data-marker="catalog-serp"]', '.catalog-serp',
                         '.items-items', '.snippet-list',
                         '[data-marker="items-list"]'):
            root = soup.select_one(selector)
            if root:
                break
        else:
            logger.warning("Не найден контейнер объявлений")
            return []

        # элементы объявлений
        items = []
        for selector in ('div[data-marker="item"]',
                         '[data-marker="catalog-serp"] > div', '.item',
                         '.snippet-horizontal', '.js-catalog-item-enum'):
            candidates = root.select(selector)
            if candidates:
                items = candidates[:limit]
                logger.info(
                    f"Найдено {len(items)} объявлений с селектором: {selector}"
                )
                break
        if not items:
            logger.warning("Не найдены элементы объявлений")
            return []

        ads: List[Ad] = []
        for item in items:
            try:
                # ссылка
                a = None
                for selector in ('a[data-marker="item-title"]', 'h3 a',
                                 '.item-title a', '.snippet-link',
                                 'a[href*="/items/"]'):
                    a = item.select_one(selector)
                    if a:
                        break
                if not a:
                    continue
                href = a.get("href") or ""
                if isinstance(href, list):
                    href = href[0] if href else ""
                url = f"https://www.avito.ru{href}" if href.startswith(
                    "/") else href

                # id
                m = re.search(r"/(\d{7,})", href or "")
                ad_id = m.group(1) if m else url

                title = _get_text(a)
                if not title:
                    continue

                # цена
                price: Optional[int] = None
                for selector in ('meta[itemprop="price"]',
                                 '[data-marker="item-price"]', '.price-text',
                                 '.snippet-price', '.price'):
                    pe = item.select_one(selector)
                    if not pe:
                        continue
                    if pe.name == 'meta':
                        content = pe.get("content", "")
                        content = content[0] if isinstance(content,
                                                           list) else content
                        if str(content).replace(" ", "").isdigit():
                            price = int(str(content).replace(" ", ""))
                            break
                    else:
                        pm = re.search(r'(\d+(?:\s+\d+)*)', _get_text(pe))
                        if pm:
                            price = int(pm.group(1).replace(' ', ''))
                            break

                # дата
                date_str = ""
                for selector in ('p[data-marker="item-date"]',
                                 '[data-marker="item-date"]', '.item-date',
                                 '.snippet-date-info', '.item-date-text'):
                    de = item.select_one(selector)
                    if de:
                        date_str = _get_text(de)
                        break
                published_ts = _parse_avito_date(date_str)

                # локация
                location = ""
                for selector in ('div[class*="geo-root"]',
                                 '[data-marker="item-address"]',
                                 '.item-address', '.snippet-location'):
                    ge = item.select_one(selector)
                    if ge:
                        location = _get_text(ge)
                        break

                # описание
                description = ""
                for selector in ('meta[itemprop="description"]',
                                 '.item-description', '.snippet-description'):
                    de = item.select_one(selector)
                    if de:
                        if de.name == 'meta':
                            description = str(de.get("content", "")).strip()
                        else:
                            description = _get_text(de)
                        break

                # картинка
                image_url = None
                for selector in ('img[src]', 'img[data-src]',
                                 '.snippet-image img', '.item-photo img'):
                    im = item.select_one(selector)
                    if im:
                        src = im.get("src") or im.get("data-src")
                        src = src[0] if isinstance(src, list) else src
                        if src:
                            if str(src).startswith("//"):
                                image_url = f"https:{src}"
                            elif str(src).startswith("/"):
                                image_url = f"https://www.avito.ru{src}"
                            else:
                                image_url = str(src)
                            break

                ads.append(
                    Ad(ad_id=ad_id or "",
                       url=url or "",
                       title=title or "",
                       price=price,
                       location=location or "",
                       date_str=date_str or "",
                       published_ts=published_ts,
                       description=description or "",
                       image_url=image_url or ""))

            except Exception as e:
                logger.warning(f"Ошибка парсинга элемента: {e}")
                continue

        logger.info(f"Спарсено {len(ads)} объявлений")
        return ads

    def _ad_text(self, ad: Ad) -> str:
        return f"{ad.title}\n{ad.description}".lower()

    def _ad_passes_filters(self, ad: Ad, sub: Subscription) -> bool:
        flt = sub.flt
        t = self._ad_text(ad)
        if flt.price_min is not None and (ad.price is None
                                          or ad.price < flt.price_min):
            return False
        if flt.price_max is not None and (ad.price is None
                                          or ad.price > flt.price_max):
            return False
        if flt.keywords_all and not all(w.lower() in t
                                        for w in flt.keywords_all):
            return False
        if flt.keywords_stop and any(w.lower() in t
                                     for w in flt.keywords_stop):
            return False
        return True

    def _bump_interval(self, found_new: bool):
        self._interval = max(self.interval_min, self._interval *
                             0.85) if found_new else min(
                                 self.interval_max, self._interval * 1.05)

    def _cleanup_seen(self, ttl=7 * 24 * 3600):
        now = time.time()
        if len(self.seen) > 20000:
            items = sorted(self.seen.items(), key=lambda kv: kv[1])
            for k, _ in items[:len(self.seen) // 2]:
                self.seen.pop(k, None)
        for k, ts in list(self.seen.items()):
            if now - ts > ttl:
                self.seen.pop(k, None)

    async def _run(self):
        app = cast(Any, self.bot).app
        lic: "LicenseManager" = app.license
        while self.has_subscribers():
            found_new = False
            html_text = await self._fetch()
            if html_text:
                now_ts = time.time()
                ads_list = []
                try:
                    ads_list = self._parse_top(html_text, limit=15)
                except Exception as e:
                    logger.exception("Ошибка парсинга Avito списка: %s", e)
                    if ADMIN_CHAT_ID is not None:
                        await safe_send_message(
                            self.bot,
                            ADMIN_CHAT_ID,
                            f"Ошибка парсинга: {e}",
                        )

                for ad in ads_list:
                    if ad.ad_id in self.seen:
                        continue

                    delivered_any = False

                    for sub in list(self.subscribers.values()):
                        if not lic.is_active(sub.user_id):
                            continue

                        if sub.only_new and (ad.published_ts is None or
                                             (now_ts - ad.published_ts)
                                             > FRESH_WINDOW_SEC):
                            continue

                        if START_STRICT and ad.published_ts is not None and ad.published_ts + START_GRACE_SEC < sub.started_ts:
                            continue

                        if not self._ad_passes_filters(ad, sub):
                            continue

                        if app.sent_was_delivered(sub.user_id, ad.ad_id):
                            continue
                        if app.dedup_global_enabled(
                        ) and app.sent_global_was_delivered(ad.ad_id):
                            continue

                        await self._enrich_ad_details(ad)
                        caption = self._build_caption(ad)

                        chat_id = app.get_alert_chat_id(sub.user_id)
                        if chat_id and await app.send_to_alert(
                                chat_id, caption, ad.image_url):
                            if app.on_deliver:
                                app.on_deliver(sub.user_id,
                                               ad)  # для ленты, если нужна
                            app.sent_mark(sub.user_id, ad.ad_id,
                                          now_ts)  # per-user
                            if app.dedup_global_enabled():
                                app.sent_global_mark(ad.ad_id,
                                                     now_ts)  # глобально
                            delivered_any = True
                            found_new = True
                        else:
                            if app.missing_alert_hint_once(sub.user_id):
                                link = app.alert_deeplink(sub.user_id)
                                kb = types.InlineKeyboardMarkup(
                                    inline_keyboard=[[
                                        types.InlineKeyboardButton(
                                            text="Подключить оповещения",
                                            url=link)
                                    ]])
                                await safe_send_message(
                                    self.bot,
                                    sub.user_id,
                                    "Чтобы получать объявления, подключите бота-оповещателя:",
                                    reply_markup=kb,
                                    disable_web_page_preview=True,
                                )

                    if delivered_any:
                        self.seen[ad.ad_id] = now_ts

            self._cleanup_seen()
            self._bump_interval(found_new)
            await asyncio.sleep(max(1.0, self._interval))


@dataclass
class FeedItem:
    ts: float
    title: str
    price: Optional[int]
    url: str
    date_str: str


class WatcherManager:

    def __init__(self, bot: Bot):
        self.bot = bot
        self.watchers: Dict[str, Watcher] = {}
        self.subs_by_user: Dict[int, List[Subscription]] = {}
        self._sub_id_seq = 1
        self.feed: Dict[int, Deque[FeedItem]] = {}
        

    def list_user_subs(self, user_id: int):
        return self.subs_by_user.get(user_id, [])

    def _next_sub_id(self):
        v = self._sub_id_seq
        self._sub_id_seq += 1
        return v

    def _on_deliver(self, user_id: int, ad: Ad):
        d = self.feed.setdefault(user_id, deque(maxlen=50))
        d.appendleft(
            FeedItem(ts=time.time(),
                     title=ad.title,
                     price=ad.price,
                     url=ad.url,
                     date_str=ad.date_str))

    async def add_subscription(
            self,
            user_id: int,
            url: str,
            flt: Optional[SubscriberFilter] = None) -> Subscription:
        if flt is None:
            flt = SubscriberFilter()
        key = search_key_from_url(url)
        sub = Subscription(id=self._next_sub_id(),
                           user_id=user_id,
                           search_key=key,
                           url=url,
                           flt=flt)
        w = self.watchers.get(key)
        if not w:
            w = Watcher(search_key=key,
                        url=url,
                        bot=self.bot,
                        on_deliver=self._on_deliver)
            self.watchers[key] = w
            await w.start()
        w.add_sub(sub)
        self.subs_by_user.setdefault(user_id, []).append(sub)
        return sub

    async def remove_subscription(self, user_id: int, sub_id: int) -> bool:
        subs = self.subs_by_user.get(user_id, [])
        for i, sub in enumerate(subs):
            if sub.id == sub_id:
                w = self.watchers.get(sub.search_key)
                if w:
                    w.remove_sub(user_id)
                    if not w.has_subscribers():
                        await w.stop()
                        self.watchers.pop(sub.search_key, None)
                subs.pop(i)
                return True
        return False

    def get_sub_by_id(self, user_id: int,
                      sub_id: int) -> Optional[Subscription]:
        for s in self.subs_by_user.get(user_id, []):
            if s.id == sub_id:
                return s
        return None

    def recent_feed(self, user_id: int, limit=10) -> List[FeedItem]:
        return list(self.feed.get(user_id, deque()))[:limit]


# === Главное меню — без «Лента», добавлен «⚙️ Аккаунт» ===
MAIN_KB = types.ReplyKeyboardMarkup(
    keyboard=[
        [
            types.KeyboardButton(text="📘 Инструкция"),
            types.KeyboardButton(text="🧭 Поиски")
        ],
        [
            types.KeyboardButton(text="🛟 Поддержка"),
            types.KeyboardButton(text="⚙️ Аккаунт")
        ],
    ],
    resize_keyboard=True,
    is_persistent=True,
    input_field_placeholder="Выберите пункт меню…",
)


# ===== Мастер добавления поиска =====
class SearchWizard(StatesGroup):
    url = State()
    price_min = State()
    price_max = State()
    name = State()


wizard_router = Router(name="wizard")


@wizard_router.message(F.text.in_(["/newsearch"]))
async def wizard_start(message: types.Message, state: FSMContext):
    await state.clear()
    await state.set_state(SearchWizard.url)
    await message.answer(
        _sanitize_newlines(
            "Шаг 1/3.\nПришлите ссылку с авито указав все фильтры на сайте  <a href='https://avito.ru'>Avito.ru</a>.\n\n"
            "‼️ <b>Обязательно укажите максимальную цену</b> в фильтрах Авито (если неважна — 100000000)."
        ),
        reply_markup=types.ReplyKeyboardRemove(),
        disable_web_page_preview=True,
    )


@wizard_router.message(SearchWizard.url, F.text.casefold() == "отмена")
@wizard_router.message(SearchWizard.url, F.text.casefold() == "назад")
@wizard_router.message(
    SearchWizard.url,
    F.text.in_(
        ["📘 Инструкция", "🛟 Поддержка", "🧭 Поиски", "⚙️ Аккаунт", "Аккаунт"]))
async def wizard_cancel_from_url(message: types.Message, state: FSMContext):
    await state.clear()
    await message.answer(
        _sanitize_newlines("Мастер прерван. Вы в главном меню."),
        reply_markup=MAIN_KB)


@wizard_router.message(SearchWizard.url)
async def wizard_got_url(message: types.Message, state: FSMContext):
    raw = (message.text or "").strip()
    m = re.search(r"https?://\S+", raw)
    url_in = m.group(0) if m else raw
    if not is_valid_avito_url(url_in):
        await message.answer(
            _sanitize_newlines(
                "Похоже, это не ссылка Авито. Вставьте корректный URL."))
        return

    url = search_key_from_url(url_in)
    guessed = try_extract_filters_from_url(url)

    await state.update_data(url=url, guessed_kw=guessed.keywords_all)
    await state.set_state(SearchWizard.price_min)
    kw_txt = f"\n\nНайдены ключевые слова: <code>{', '.join(guessed.keywords_all)}</code>" if guessed.keywords_all else ""
    await message.answer(
        _sanitize_newlines(
            "Шаг 2/3.\nМинимальная цена (или «-», если без минимума):" +
            kw_txt),
        reply_markup=types.ReplyKeyboardMarkup(
            keyboard=[[types.KeyboardButton(text="-")],
                      [types.KeyboardButton(text="Отмена")]],
            resize_keyboard=True),
    )


@wizard_router.message(SearchWizard.price_min, F.text.casefold() == "отмена")
async def wizard_cancel_min(message: types.Message, state: FSMContext):
    await state.clear()
    await message.answer(_sanitize_newlines("Мастер отменён."),
                         reply_markup=MAIN_KB)


@wizard_router.message(SearchWizard.price_min)
async def wizard_got_min(message: types.Message, state: FSMContext):
    txt = (message.text or "").strip()
    pmin = None
    if txt != "-":
        if not txt.isdigit():
            await message.answer(_sanitize_newlines("Введите число или «-»."))
            return
        pmin = int(txt)
    await state.update_data(price_min=pmin)
    await state.set_state(SearchWizard.price_max)
    await message.answer(
        _sanitize_newlines(
            "Теперь <b>максимальная цена</b> (обязательно число):"),
        reply_markup=types.ReplyKeyboardMarkup(
            keyboard=[[types.KeyboardButton(text="100000000")],
                      [types.KeyboardButton(text="Отмена")]],
            resize_keyboard=True),
    )


@wizard_router.message(SearchWizard.price_max, F.text.casefold() == "отмена")
async def wizard_cancel_max(message: types.Message, state: FSMContext):
    await state.clear()
    await message.answer(_sanitize_newlines("Мастер отменён."),
                         reply_markup=MAIN_KB)


@wizard_router.message(SearchWizard.price_max)
async def wizard_got_max(message: types.Message, state: FSMContext):
    txt = (message.text or "").strip()
    if not txt.isdigit():
        await message.answer(
            _sanitize_newlines(
                "Максимальная цена обязательна. Введите число, например 100000000."
            ))
        return
    pmax = int(txt)

    data = await state.get_data()
    url = data.get("url") or ""
    pmin = data.get("price_min")
    kw = data.get("guessed_kw") or []

    await state.update_data(price_max=pmax)

    summary = [
        "<b>Проверим настройки:</b>",
        f"• URL: {url}",
        f"• Мин. цена: {pmin if pmin is not None else '—'}",
        f"• Макс. цена: {pmax}",
        f"• Слова: {', '.join(kw) if kw else '—'}",
        "\nОтправьте название поиска (например «тест»).",
    ]
    await state.set_state(SearchWizard.name)
    await message.answer(_sanitize_newlines("\n".join(summary)),
                         disable_web_page_preview=True)


@wizard_router.message(SearchWizard.name, F.text.casefold() == "отмена")
async def wizard_cancel_name(message: types.Message, state: FSMContext):
    await state.clear()
    await message.answer(_sanitize_newlines("Мастер отменён."),
                         reply_markup=MAIN_KB)


@wizard_router.message(SearchWizard.name)
async def wizard_finish_create(message: types.Message, state: FSMContext):
    lic: LicenseManager = cast(Any, message.bot).app.license
    if not lic.is_active(message.chat.id):
        await message.answer(
            _sanitize_newlines(
                "Слот не активирован. Получите ключ у поддержки и отправьте его боту (формат «Ключ: xxxxx-…»)."
            ))
        await state.clear()
        return

    data = await state.get_data()
    url = data.get("url") or ""
    pmin = data.get("price_min")
    pmax = data.get("price_max")
    kw = data.get("guessed_kw") or []
    name = (message.text or "").strip() or None

    flt = SubscriberFilter(price_min=pmin, price_max=pmax, keywords_all=kw)
    sub = await cast(Any, message.bot).app.manager.add_subscription(
        message.chat.id, url, flt)
    sub.name = name

    await state.clear()
    await message.answer(
        _sanitize_newlines(
            "Поиск создан ✅\n"
            f"Название: <b>{html.escape(name or f'Поиск №{sub.id}')}</b>\n"
            f"URL: {url}\n" + (f"min={pmin} " if pmin is not None else "") +
            (f"max={pmax} " if pmax is not None else "") + "\n\n"
            "Как только появятся новые объявления — пришлю в бот-оповещателя."
        ),
        reply_markup=MAIN_KB,
        disable_web_page_preview=True,
    )


# ===== Поддержка =====
support_router = Router(name="support")


@support_router.message(F.text.in_(["🛟 Поддержка", "Поддержка"]))
async def support_info(message: types.Message, state: FSMContext):
    await state.clear()
    await message.answer(_sanitize_newlines(
        "По любым вопросам — техподдержка:\n👉 <a href='{}'>@Vladlmerr</a>".
        format(SUPPORT_LINK)),
                         reply_markup=MAIN_KB,
                         disable_web_page_preview=True)


# ===== Экран «Поиски» =====
def build_searches_kb(
    subs: List[Subscription],
    lic: LicenseManager,
    user_id: int,
) -> types.InlineKeyboardMarkup:
    rows: List[List[types.InlineKeyboardButton]] = []
    if lic.is_active(user_id) and not subs:
        rows.append([
            types.InlineKeyboardButton(text="Свободный слот",
                                       callback_data="slot_new")
        ])
    for s in subs:
        label = s.name or f"Поиск №{s.id}"
        rows.append([
            types.InlineKeyboardButton(text=label,
                                       callback_data=f"open_sub:{s.id}")
        ])
    rows.append([
        types.InlineKeyboardButton(text="➕ Получить слот",
                                   callback_data="get_slot")
    ])
    rows.append([
        types.InlineKeyboardButton(text="❌ Закрыть",
                                   callback_data="close_menu")
    ])
    return types.InlineKeyboardMarkup(inline_keyboard=rows)


def format_sub_panel(sub: Subscription, lic: LicenseManager) -> str:
    parts = [f"<b>{html.escape(sub.name or f'Подписка №{sub.id}')}</b>"]
    exp = lic.expiry_dt(sub.user_id)
    parts.append(
        f"\nКлюч: <code>{'активен' if lic.is_active(sub.user_id) else '—'}</code>"
    )
    if exp:
        parts.append(f"Активен до: <b>{exp.strftime('%d.%m.%Y %H:%M:%S')}</b>")
    if sub.flt.price_max is not None:
        parts.append(f"\n💰 <b>Максимальная цена:</b> {sub.flt.price_max} ₽")
    else:
        parts.append("\n💰 <b>Максимальная цена:</b> не задана")
    if sub.flt.keywords_stop:
        parts.append(
            f"❌ <b>СТОП слова:</b> {', '.join(sub.flt.keywords_stop)}")
    else:
        parts.append("❌ <b>СТОП слова:</b> ")
    if sub.flt.keywords_all:
        parts.append(
            f"✅ <b>ЦЕЛЕВЫЕ слова:</b> {', '.join(sub.flt.keywords_all)}")
    else:
        parts.append("✅ <b>ЦЕЛЕВЫЕ слова:</b> ")
    parts.append(f"\n🌐 <b>URL:</b> {sub.url}")
    parts.append("\n<b>Продвинутые фильтры</b>")
    parts.append(f"📦 Только новые: {'✅' if sub.only_new else '❌'}")
    return "\n".join(parts)


def build_sub_inline_kb(sub: Subscription) -> types.InlineKeyboardMarkup:
    rid = sub.id
    rows = [
        [
            types.InlineKeyboardButton(text="💰 Максимальная цена",
                                       callback_data=f"sub:{rid}:max")
        ],
        [
            types.InlineKeyboardButton(text="❌ СТОП слова",
                                       callback_data=f"sub:{rid}:stop"),
            types.InlineKeyboardButton(text="✅ ЦЕЛЕВЫЕ слова",
                                       callback_data=f"sub:{rid}:pos")
        ],
        [
            types.InlineKeyboardButton(
                text=f"📦 Только новые: {'✅' if sub.only_new else '❌'}",
                callback_data=f"sub:{rid}:toggle_new")
        ],
        [
            types.InlineKeyboardButton(text="🗑 Удалить",
                                       callback_data=f"sub:{rid}:delete"),
            types.InlineKeyboardButton(text="⬅️ Назад",
                                       callback_data="back_to_list")
        ],
    ]
    return types.InlineKeyboardMarkup(inline_keyboard=rows)


class EditPrice(StatesGroup):
    value = State()


class EditWords(StatesGroup):
    mode = State()
    sub_id = State()
    text = State()


searches_router = Router(name="searches")


@searches_router.message(F.text.in_(["🧭 Поиски", "Поиски"]))
async def searches_screen(message: types.Message, state: FSMContext):
    await state.clear()
    app = cast(Any, message.bot).app
    subs = app.manager.list_user_subs(message.chat.id)
    kb = build_searches_kb(subs, app.license, message.chat.id)
    await message.answer(
        _sanitize_newlines("Выберите поиск или получите новый слот:"),
        reply_markup=kb)


@searches_router.callback_query(F.data == "get_slot")
async def cb_get_slot(cq: types.CallbackQuery):
    if isinstance(cq.message, types.Message):
        await cq.message.answer(_sanitize_newlines(
            "Для покупки ключа или получения тестового доступа свяжитесь с\n"
            f"👉 <a href='{SUPPORT_LINK}'>@Vladlmerr</a>\n\n"
            "Когда получите ключ, отправьте его сюда (формат: <b>Ключ: xxxxx-…</b>)."
        ),
                                disable_web_page_preview=True)
    await cq.answer()


@searches_router.callback_query(F.data == "slot_new")
async def cb_slot_new(cq: types.CallbackQuery, state: FSMContext):
    if not isinstance(cq.message, types.Message):
        await cq.answer()
        return
    await state.clear()
    await state.set_state(SearchWizard.url)
    await cq.message.answer(
        _sanitize_newlines(
            "Шаг 1/3. Пришлите ссылку категории с <a href='https://avito.ru'>Avito.ru</a>.\n\n"
            "‼️ <b>Обязательно укажите максимальную цену</b> в фильтрах Авито (если неважна — 100000000)."
        ),
        reply_markup=types.ReplyKeyboardRemove(),
        disable_web_page_preview=True,
    )
    await cq.answer()


@searches_router.callback_query(F.data == "close_menu")
async def cb_close_menu(cq: types.CallbackQuery, state: FSMContext):
    await state.clear()
    if isinstance(cq.message, types.Message):
        try:
            await cq.message.delete()
        except Exception:
            try:
                await cq.message.edit_reply_markup(reply_markup=None)
            except Exception:
                pass
    await cq.answer("Закрыто")


@searches_router.callback_query(F.data == "back_to_list")
async def cb_back_to_list(cq: types.CallbackQuery):
    if isinstance(cq.message, types.Message):
        app = cast(Any, cq.bot).app
        subs = app.manager.list_user_subs(cq.from_user.id)
        kb = build_searches_kb(subs, app.license, cq.from_user.id)
        await cq.message.answer(
            _sanitize_newlines("Выберите поиск или получите новый слот:"),
            reply_markup=kb)
    await cq.answer()


@searches_router.callback_query(F.data.startswith("open_sub:"))
async def cb_open_sub(cq: types.CallbackQuery, state: FSMContext):
    data_str: str = cq.data or ""
    try:
        sub_id = int(data_str.split(":", 1)[1])
    except Exception:
        await cq.answer()
        return
    mng = cast(Any, cq.bot).app.manager
    sub = mng.get_sub_by_id(cq.from_user.id, sub_id)
    if not sub:
        await cq.answer("Подписка не найдена", show_alert=True)
        return
    if isinstance(cq.message, types.Message):
        lic: LicenseManager = cast(Any, cq.bot).app.license
        await cq.message.answer(format_sub_panel(sub, lic),
                                reply_markup=build_sub_inline_kb(sub),
                                disable_web_page_preview=True)
    await cq.answer()


@searches_router.callback_query(F.data.startswith("sub:"))
async def cb_sub_actions(cq: types.CallbackQuery, state: FSMContext):
    data_str: str = cq.data or ""
    m = re.match(r"sub:(\d+):(\w+)", data_str)
    if not m:
        await cq.answer()
        return
    sub_id = int(m.group(1))
    action = m.group(2)
    mng = cast(Any, cq.bot).app.manager
    sub = mng.get_sub_by_id(cq.from_user.id, sub_id)
    if not sub:
        await cq.answer("Подписка не найдена", show_alert=True)
        return

    if action == "max":
        await state.set_state(EditPrice.value)
        await state.update_data(field="max", sub_id=sub.id)
        if isinstance(cq.message, types.Message):
            await cq.message.answer(
                _sanitize_newlines(
                    "Введите новую <b>максимальную</b> цену (число). Если не важна — укажите 100000000:"
                ))
        await cq.answer()
        return

    if action in ("pos", "stop"):
        await state.set_state(EditWords.text)
        await state.update_data(mode=action, sub_id=sub.id)
        if isinstance(cq.message, types.Message):
            hint = "целевые" if action == "pos" else "СТОП"
            curr = ", ".join(sub.flt.keywords_all if action ==
                             "pos" else sub.flt.keywords_stop) or "—"
            await cq.message.answer(
                _sanitize_newlines(
                    f"Отправьте {hint} слова через запятую.\nТекущие: <code>{curr}</code>"
                ))
        await cq.answer()
        return

    if action == "toggle_new":
        sub.only_new = not sub.only_new
        if isinstance(cq.message, types.Message):
            lic: LicenseManager = cast(Any, cq.bot).app.license
            await cq.message.answer(format_sub_panel(sub, lic),
                                    reply_markup=build_sub_inline_kb(sub),
                                    disable_web_page_preview=True)
        await cq.answer("Обновлено")
        return

    if action == "delete":
        ok = await mng.remove_subscription(cq.from_user.id, sub.id)
        if isinstance(cq.message, types.Message):
            await cq.message.answer(
                _sanitize_newlines(
                    "Подписка удалена." if ok else "Не удалось удалить."))
        await cq.answer()
        return

    await cq.answer()


# ====== Применение изменений из FSM ======
@searches_router.message(EditPrice.value)
async def ui_edit_apply_max(m: types.Message, state: FSMContext):
    data = await state.get_data()
    field = data.get("field")
    raw = data.get("sub_id")
    if raw is None:
        await state.clear()
        await m.reply(_sanitize_newlines("Ошибка: нет идентификатора поиска."),
                      reply_markup=MAIN_KB)
        return
    sub_id = int(raw)

    txt = (m.text or "").strip()
    mng = cast(Any, m.bot).app.manager
    sub = mng.get_sub_by_id(m.chat.id, sub_id)
    if not sub:
        await state.clear()
        await m.reply(_sanitize_newlines("Подписка не найдена."),
                      reply_markup=MAIN_KB)
        return
    if field == "max":
        if not txt.isdigit():
            await m.reply(
                _sanitize_newlines(
                    "Максимальная цена должна быть числом, например 100000000."
                ))
            return
        sub.flt.price_max = int(txt)
    await state.clear()
    lic: LicenseManager = cast(Any, m.bot).app.license
    await m.reply(_sanitize_newlines("Готово.\n" + format_sub_panel(sub, lic)),
                  reply_markup=MAIN_KB,
                  disable_web_page_preview=True)


@searches_router.message(EditWords.text)
async def ui_edit_words_apply(m: types.Message, state: FSMContext):
    data = await state.get_data()
    mode = (data.get("mode") or "pos")
    raw = data.get("sub_id")
    if raw is None:
        await state.clear()
        await m.reply(_sanitize_newlines("Ошибка: нет идентификатора поиска."),
                      reply_markup=MAIN_KB)
        return
    sub_id = int(raw)

    mng = cast(Any, m.bot).app.manager
    sub = mng.get_sub_by_id(m.chat.id, sub_id)
    if not sub:
        await state.clear()
        await m.reply(_sanitize_newlines("Подписка не найдена."),
                      reply_markup=MAIN_KB)
        return
    words = [
        w.strip() for w in (m.text or "").replace(";", ",").split(",")
        if w.strip()
    ]
    if mode == "pos":
        sub.flt.keywords_all = words
    else:
        sub.flt.keywords_stop = words
    await state.clear()
    lic: LicenseManager = cast(Any, m.bot).app.license
    await m.reply(_sanitize_newlines("Обновлено.\n" +
                                     format_sub_panel(sub, lic)),
                  reply_markup=MAIN_KB,
                  disable_web_page_preview=True)


# ===== Приём ключа (устойчивый) =====
key_router = Router(name="keys")


async def _accept_key_impl(m: types.Message, state: FSMContext):
    app = cast(Any, m.bot).app
    lic: LicenseManager = app.license

    txt = (m.text or "").strip()
    m_uuid = KEY_RE.search(txt)  # ищем UUID в любом месте
    if not m_uuid:
        return

    key_value = m_uuid.group(1)
    try:
        uuid.UUID(key_value)
    except Exception:
        await m.reply(_sanitize_newlines("Ключ недействителен."))
        return

    res = app.redeem_key(key_value)
    if not res:
        await state.clear()
        await m.reply(
            _sanitize_newlines("Ключ недействителен или уже использован."))
        return

    hours, expires_ts = res  # expires_ts формируется в момент активации
    logger.info(f"User {m.chat.id} activated key: {key_value}")
    await state.clear()
    lic.activate_until(m.chat.id, expires_ts)
    exp_str = _fmt_dt(expires_ts)

    # учёт аккаунта
    app.account_register_if_needed(m.chat.id)
    app.account_add_key(m.chat.id, key_value, hours, expires_ts)

    # Кнопка для привязки alert-бота
    deeplink = app.alert_deeplink(m.chat.id)
    kb = types.InlineKeyboardMarkup(inline_keyboard=[
        [
            types.InlineKeyboardButton(
                text="Подключить оповещения (alert-бот)", url=deeplink)
        ],
        [
            types.InlineKeyboardButton(text="Создать поиск (Свободный слот)",
                                       callback_data="slot_new")
        ],
    ])

    await m.reply(
        _sanitize_newlines(
            f"Ключ принят ✅\nСлот активен до: <b>{exp_str}</b>\n\n"
            "1) Нажмите кнопку ниже и запустите бота-оповещателя (для привязки).\n"
            "2) Затем вернитесь и создайте поиск."),
        disable_web_page_preview=True,
        reply_markup=kb,
    )


# Матчим как «Ключ: …», так и просто UUID
@key_router.message(F.text.regexp(KEY_RE))
async def accept_key_regexp(m: types.Message, state: FSMContext):
    await _accept_key_impl(m, state)






# ===== Аккаунт =====
account_router = Router(name="account")


def account_panel_text(app: Any, user_id: int) -> str:
    lic: LicenseManager = app.license
    acc = app.account_get(user_id)
    subs = app.manager.list_user_subs(user_id)
    exp_dt = lic.expiry_dt(user_id)

    key_txt = "—"
    if acc and acc.get("keys"):
        now = time.time()
        current = None
        for k in sorted(acc["keys"],
                        key=lambda x: x.get("activated", 0),
                        reverse=True):
            if float(k.get("expires", 0) or 0) > now:
                current = k
                break
        if not current:
            current = sorted(acc["keys"],
                             key=lambda x: x.get("activated", 0),
                             reverse=True)[0]
        key_txt = current.get("key", "—")[:36]

    lines = [
        "<b>Аккаунт</b>",
        f"👤 <b>ID:</b> <code>{user_id}</code>",
        f"📅 <b>Дата регистрации:</b> {_fmt_dt((acc or {}).get('registered')) if acc else '—'}",
        "",
        f"🔑 <b>Ключ:</b> <code>{key_txt}</code>",
        f"⏳ <b>Действителен до:</b> {exp_dt.strftime('%d.%m.%Y %H:%M:%S') if exp_dt else '—'}",
        f"🧭 <b>Поисков:</b> {len(subs) if subs else 0}" +
        ("" if subs else " (не создан)"),
    ]
    return "\n".join(lines)


def build_account_kb() -> types.InlineKeyboardMarkup:
    return types.InlineKeyboardMarkup(inline_keyboard=[
        [
            types.InlineKeyboardButton(text="Показать истекшие ключи",
                                       callback_data="account:expired")
        ],
        [types.InlineKeyboardButton(text="Продлить", url=SUPPORT_LINK)],
        [
            types.InlineKeyboardButton(text="❌ Закрыть",
                                       callback_data="account:close")
        ],
    ])


@account_router.message(F.text.in_(["⚙️ Аккаунт", "Аккаунт", "/account"]))
async def account_show(m: types.Message, state: FSMContext):
    app = cast(Any, m.bot).app
    app.account_register_if_needed(m.chat.id)
    txt = account_panel_text(app, m.chat.id)
    await m.answer(txt, reply_markup=MAIN_KB)
    await m.answer(" ", reply_markup=build_account_kb())


@account_router.callback_query(F.data == "account:close")
async def account_close(cq: types.CallbackQuery):
    if isinstance(cq.message, types.Message):
        try:
            await cq.message.delete()
        except Exception:
            pass
    await cq.answer()


@account_router.callback_query(F.data == "account:expired")
async def account_expired(cq: types.CallbackQuery):
    app = cast(Any, cq.bot).app
    acc = app.account_get(cq.from_user.id) or {}
    items = []
    now = time.time()
    for k in (acc.get("keys") or []):
        exp_ts = float(k.get("expires") or 0)
        if exp_ts and exp_ts < now:
            items.append(
                f"• <code>{k.get('key','')}</code> — истёк {_fmt_dt(exp_ts)}")
    text = "Истёкших ключей не найдено." if not items else "<b>Истёкшие ключи:</b>\n" + "\n".join(
        items)
    if isinstance(cq.message, types.Message):
        await cq.message.answer(_sanitize_newlines(text))
    await cq.answer()


# ===== Главное приложение =====
class App:

    def __init__(self, token: str):
        # Загружаем переменные окружения, чтобы значения из .env были
        # доступны даже если константы в начале файла уже считаны до
        # вызова load_dotenv() в main(). Это позволяет корректно
        # использовать такие переменные, как ALERT_BOT_TOKEN и BINDINGS_FILE.
        try:
            # Загружаем .env из каталога текущего файла, чтобы использовать
            # переменные окружения даже если бот запускается из другого
            # каталога. Если модуль dotenv не установлен, загружать не
            # удастся, но os.getenv() всё равно вернёт то, что есть в
            # окружении.
            from pathlib import Path
            dotenv_path = Path(__file__).resolve().parent / ".env"
            load_dotenv(dotenv_path)
        except Exception:
            # попытка последнего шанса — загрузить .env без явного пути
            try:
                load_dotenv()
            except Exception:
                pass

        # Инициализация бота
        self.bot = Bot(token=token,
                       default=DefaultBotProperties(parse_mode=ParseMode.HTML))
        cast(Any, self.bot).app = self
        self.dp = Dispatcher(storage=MemoryStorage())
        self.manager = WatcherManager(self.bot)
        self.license = LicenseManager()

        # alert
        # Используем переменные окружения, если они заданы. В противном
        # случае — значения констант, определённых при импорте.
        self.alert_token: Optional[str] = os.getenv(
            "ALERT_BOT_TOKEN", ALERT_BOT_TOKEN)
        self.alert_username: str = os.getenv(
            "ALERT_BOT_USERNAME", ALERT_BOT_USERNAME or "")
        # bindings file: пытаемся взять из окружения, затем из константы
        self.bindings_file: str = os.getenv(
            "BINDINGS_FILE", BINDINGS_FILE)
        self._alert_warned: Set[int] = set()

        # storage
        self.keys_file: str = os.getenv("KEYS_FILE", KEYS_FILE)
        self.sent_file: str = os.getenv("SENT_FILE", SENT_FILE)
        self.accounts_file: str = os.getenv("ACCOUNTS_FILE", ACCOUNTS_FILE)

        # для ленты (если захотите показывать последние карточки)
        self.on_deliver = self.manager._on_deliver

        self._register()

    # ===== работа с привязками main_user_id -> alert_chat_id
    def _load_bindings(self) -> Dict[str, int]:
        """
        Загрузка привязок main_user_id → alert_chat_id.

        Основной бот и бот‑оповещатель должны использовать один и тот же файл
        привязок. Однако имя файла может задаваться через переменную
        окружения BINDINGS_FILE или оставаться значением по умолчанию
        (``user_bindings.json``). В некоторых старых версиях настроек файл
        назывался ``data/bindings.json``. Чтобы избежать ситуации, когда
        основной бот ищет привязки в одном месте, а оповещатель сохраняет
        их в другом, функция пытается прочитать данные из нескольких
        возможных расположений: сначала из ``self.bindings_file``, затем из
        ``user_bindings.json`` (если это не то же самое), и, наконец, из
        ``data/bindings.json``. Первое найденное корректное содержимое
        возвращается.
        """
        candidates = []
        # основной путь из переменной окружения/константы
        if self.bindings_file:
            candidates.append(self.bindings_file)
        # если основной путь не user_bindings.json, добавляем его как
        # альтернативу. Это позволяет читать старые файлы, даже если
        # переменная BINDINGS_FILE указывает на другой путь.
        if self.bindings_file != "user_bindings.json":
            candidates.append("user_bindings.json")
        # Добавляем потенциальный устаревший путь в data/
        if self.bindings_file != "data/bindings.json":
            candidates.append(os.path.join("data", "bindings.json"))

        for path in candidates:
            try:
                if not os.path.exists(path):
                    continue
                with open(path, "r", encoding="utf-8") as f:
                    raw = f.read().strip()
                    if not raw:
                        continue
                    data = json.loads(raw) or {}
                    return {str(k): int(v) for k, v in data.items()}
            except Exception:
                # Пропускаем некорректные файлы
                continue
        # Ничего не нашли
        return {}

    def _save_bindings(self, data: Dict[str, int]) -> None:
        os.makedirs(os.path.dirname(self.bindings_file) or ".", exist_ok=True)
        with open(self.bindings_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def get_alert_chat_id(self, main_user_id: int) -> Optional[int]:
        b = self._load_bindings()
        val = b.get(str(main_user_id))
        return int(val) if val else None

    def alert_deeplink(self, main_user_id: int) -> str:
        uname = self.alert_username or "<УКАЖИТЕ_ALERT_BOT_USERNAME>"
        return f"https://t.me/{uname}?start={main_user_id}"

    def missing_alert_hint_once(self, user_id: int) -> bool:
        if user_id in self._alert_warned:
            return False
        self._alert_warned.add(user_id)
        return True

    async def send_to_alert(self, alert_chat_id: int, caption: str,
                            image_url: Optional[str]) -> bool:
        """Отправка в alert-бота через его Bot API. Без <br>, только \n."""
        if not self.alert_token:
            return False
        api = f"https://api.telegram.org/bot{self.alert_token}"
        safe_caption = _sanitize_newlines(caption)
        try:
            timeout = aiohttp.ClientTimeout(total=20)
            async with aiohttp.ClientSession(timeout=timeout) as s:
                if image_url:
                    form = aiohttp.FormData()
                    form.add_field("chat_id", str(alert_chat_id))
                    form.add_field("caption", safe_caption)
                    form.add_field("parse_mode", "HTML")
                    form.add_field("photo", image_url)
                    async with s.post(f"{api}/sendPhoto", data=form) as r:
                        return (r.status == 200)
                else:
                    payload = {
                        "chat_id": alert_chat_id,
                        "text": safe_caption,
                        "parse_mode": "HTML",
                        "disable_web_page_preview": True
                    }
                    async with s.post(f"{api}/sendMessage", json=payload) as r:
                        return (r.status == 200)
        except Exception:
            return False

    # ===== ключи =====
    def _load_keys(self) -> Dict[str, Dict[str, Any]]:
        if not os.path.exists(self.keys_file):
            return {}
        try:
            with open(self.keys_file, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
                return {str(k): dict(v) for k, v in data.items()}
        except Exception:
            return {}

    def _save_keys(self, data: Dict[str, Dict[str, Any]]) -> None:
        os.makedirs(os.path.dirname(self.keys_file) or ".", exist_ok=True)
        with open(self.keys_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def issue_key(self, hours: int = 24, uses: int = 1) -> str:
        data = self._load_keys()
        k = str(uuid.uuid4())
        data[k] = {
            "hours": int(hours),
            "uses_left": int(uses),
            "created": time.time()
        }
        self._save_keys(data)
        return k

    def redeem_key(self, key: str) -> Optional[tuple[int, float]]:
        """
        Возвращает (hours, expires_ts). ВАЖНО: expires_ts формируется в МОМЕНТ АКТИВАЦИИ,
        то есть «сейчас + hours*3600», независимо от времени выдачи ключа.
        """
        data = self._load_keys()
        rec = data.get(key)
        if not rec:
            return None
        left = int(rec.get("uses_left", 0))
        if left <= 0:
            return None
        hours = int(rec.get("hours", 24))
        expires_ts = time.time() + hours * 3600
        rec["uses_left"] = left - 1
        data[key] = rec
        self._save_keys(data)
        return hours, float(expires_ts)

    # ===== антидубликаты per-user + global =====
    def _load_sent(self) -> Dict[str, Dict[str, float]]:
        if not os.path.exists(self.sent_file):
            return {}
        try:
            with open(self.sent_file, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
                out: Dict[str, Dict[str, float]] = {}
                for uk, mp in data.items():
                    if isinstance(mp, dict):
                        out[str(uk)] = {
                            str(aid): float(ts)
                            for aid, ts in mp.items()
                        }
                return out
        except Exception:
            return {}

    def _save_sent(self, data: Dict[str, Dict[str, float]]) -> None:
        os.makedirs(os.path.dirname(self.sent_file) or ".", exist_ok=True)
        with open(self.sent_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def _cleanup_sent_locked(self, data: Dict[str, Dict[str, float]]) -> None:
        cutoff = time.time() - DEDUP_TTL_DAYS * 86400
        for uk in list(data.keys()):
            inner = data.get(uk, {})
            for ad_id in list(inner.keys()):
                if inner[ad_id] < cutoff:
                    del inner[ad_id]
            if not inner:
                del data[uk]

    def sent_was_delivered(self, user_id: int, ad_id: str) -> bool:
        data = self._load_sent()
        inner = data.get(str(user_id), {})
        return ad_id in inner

    def sent_mark(self,
                  user_id: int,
                  ad_id: str,
                  ts: Optional[float] = None) -> None:
        data = self._load_sent()
        inner = data.get(str(user_id), {})
        inner[ad_id] = float(ts or time.time())
        data.setdefault(str(user_id), {}).update(inner)
        self._cleanup_sent_locked(data)
        self._save_sent(data)

    def dedup_global_enabled(self) -> bool:
        return DEDUP_GLOBAL

    def sent_global_was_delivered(self, ad_id: str) -> bool:
        data = self._load_sent()
        inner = data.get("_global", {})
        return ad_id in inner

    def sent_global_mark(self, ad_id: str, ts: Optional[float] = None) -> None:
        data = self._load_sent()
        inner = data.setdefault("_global", {})
        inner[ad_id] = float(ts or time.time())
        self._cleanup_sent_locked(data)
        self._save_sent(data)

    # ===== аккаунты =====
    def _load_accounts(self) -> Dict[str, Dict[str, Any]]:
        if not os.path.exists(self.accounts_file):
            return {}
        try:
            with open(self.accounts_file, "r", encoding="utf-8") as f:
                return json.load(f) or {}
        except Exception:
            return {}

    def _save_accounts(self, data: Dict[str, Dict[str, Any]]) -> None:
        os.makedirs(os.path.dirname(self.accounts_file) or ".", exist_ok=True)
        with open(self.accounts_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def account_register_if_needed(self, user_id: int) -> None:
        data = self._load_accounts()
        u = data.get(str(user_id))
        if not u:
            data[str(user_id)] = {"registered": time.time(), "keys": []}
            self._save_accounts(data)

    def account_add_key(self, user_id: int, key_value: str, hours: int,
                        exp_ts: Optional[float]):
        data = self._load_accounts()
        u = data.setdefault(str(user_id), {
            "registered": time.time(),
            "keys": []
        })
        u.setdefault("keys", []).append({
            "key": key_value,
            "activated": time.time(),
            "hours": int(hours),
            "expires": float(exp_ts or 0.0),
        })
        self._save_accounts(data)

    def account_get(self, user_id: int) -> Optional[Dict[str, Any]]:
        return self._load_accounts().get(str(user_id))

    def _register(self):
        # Регистрируем key_router ПЕРВЫМ — чтобы сообщения с ключами обрабатывались гарантированно
        self.dp.include_router(key_router)
        self.dp.include_router(wizard_router)
        self.dp.include_router(support_router)
        self.dp.include_router(searches_router)
        self.dp.include_router(account_router)
        extend_app_ultra(self)


        @self.dp.message(Command("test_alert"), StateFilter("*"))
        async def test_alert(m: types.Message, state: FSMContext):
            await state.clear()
            if ADMIN_CHAT_ID is None or m.chat.id != ADMIN_CHAT_ID:
                await m.reply(
                    _sanitize_newlines("Команда доступна только админу."))
                return
            chat_id = self.get_alert_chat_id(m.chat.id)
            if not chat_id:
                await m.reply(
                    _sanitize_newlines(
                        "Alert binding не найден. Нажмите кнопку привязки после активации ключа."
                    ))
                return
            ok = await self.send_to_alert(
                chat_id,
                _sanitize_newlines("Тестовое сообщение из основного бота ✅"),
                None)
            await m.reply(
                _sanitize_newlines(
                    "Отправлено." if ok else
                    "Не удалось отправить (проверь токен ALERT_BOT_TOKEN и привязку)."
                ))

        @self.dp.message(F.text == "Назад", StateFilter("*"))
        async def back_btn(m: types.Message, state: FSMContext):
            await state.clear()
            await m.answer(_sanitize_newlines("Главное меню."),
                           reply_markup=MAIN_KB)

        @self.dp.message(F.text.in_(["📘 Инструкция", "Инструкция", "/help"]), StateFilter("*"))
        async def help_cmd(m: types.Message, state: FSMContext):
            await state.clear()
            self.account_register_if_needed(m.chat.id)
            await m.answer(_sanitize_newlines(
                "📘 <b>Инструкция</b>\n"
                "1) Получите ключ у поддержки.\n"
                "2) Отправьте: <code>Ключ: xxxxx-…</code> — активируется слот.\n"
                "3) Подключите alert-бота по кнопке в ответе на ключ.\n"
                "4) Создайте поиск (Свободный слот) — объявления придут в alert-бот."
            ),
                           reply_markup=MAIN_KB,
                           disable_web_page_preview=True)

        @self.dp.message(Command("start"), StateFilter("*"))
        async def start_cmd(m: types.Message, state: FSMContext):
            await state.clear()
            self.account_register_if_needed(m.chat.id)
            await m.answer(
                _sanitize_newlines(
                    "Я пришлю вам <b>только что опубликованные</b> объявления по вашим фильтрам.\n\n"
                    "• Активируйте доступ: отправьте ключ (формат «Ключ: …»)\n"
                    "• Подключите бота-оповещателя по кнопке в ответе на ключ\n"
                    "• Мастер: <code>/newsearch</code>\n"
                    "• Экран слотов: «🧭 Поиски»\n"
                    "• Аккаунт: «⚙️ Аккаунт»"),
                reply_markup=MAIN_KB,
                disable_web_page_preview=True,
            )

        @self.dp.message(Command("add"), StateFilter("*"))
        async def add_cmd(m: types.Message, state: FSMContext):
            await state.clear()
            self.account_register_if_needed(m.chat.id)
            lic: LicenseManager = self.license
            if not lic.is_active(m.chat.id):
                await m.reply(
                    _sanitize_newlines(
                        "Слот не активирован. Получите ключ у поддержки и отправьте его боту (формат «Ключ: …»)."
                    ))
                return
            txt = (m.text or "")
            parts = txt.split(maxsplit=2)
            if len(parts) < 2:
                await m.reply(
                    _sanitize_newlines(
                        "Укажите ссылку после /add. Пример:\n/add https://www.avito.ru/... max=100000000,min=10000"
                    ))
                return
            url = parts[1].strip()
            params = parts[2].strip() if len(parts) >= 3 else ""
            flt = try_extract_filters_from_url(url)
            if params:
                p = params.replace(" ", "")
                for token in p.split(","):
                    if not token:
                        continue
                    if token.startswith("kw="):
                        kws = token[3:].replace(";", ",").replace("|", ",")
                        flt.keywords_all = [w for w in kws.split(",") if w]
                    elif token.startswith("min="):
                        try:
                            flt.price_min = int(token[4:])
                        except Exception:
                            pass
                    elif token.startswith("max="):
                        try:
                            flt.price_max = int(token[4:])
                        except Exception:
                            pass
            if flt.price_max is None:
                await m.reply(
                    _sanitize_newlines(
                        "⚠️ Укажите максимальную цену (параметр <code>max=</code>) или воспользуйтесь мастером «/newsearch»."
                    ))
                return
            sub = await self.manager.add_subscription(m.chat.id, url, flt)
            await m.reply(
                _sanitize_newlines(
                    f"Подписка добавлена: <b>{sub.id}</b>\nСсылка: {url}\n"
                    "Карточки будут приходить в бот-оповещатель."))

        @self.dp.message(Command("list"), StateFilter("*"))
        async def list_cmd(m: types.Message, state: FSMContext):
            await state.clear()
            self.account_register_if_needed(m.chat.id)
            subs = self.manager.list_user_subs(m.chat.id)
            if not subs:
                await m.reply(
                    _sanitize_newlines("У вас нет активных подписок."))
                return
            lines = ["Ваши подписки:"]
            for s in subs:
                desc = []
                if s.name:
                    desc.append(f"name={s.name}")
                if s.flt.keywords_all:
                    desc.append(f"kw={','.join(s.flt.keywords_all)}")
                if s.flt.keywords_stop:
                    desc.append(f"stop={','.join(s.flt.keywords_stop)}")
                if s.flt.price_min is not None:
                    desc.append(f"min={s.flt.price_min}")
                if s.flt.price_max is not None:
                    desc.append(f"max={s.flt.price_max}")
                lines.append(f"{s.id}: {s.url} " +
                             (f"({' ; '.join(desc)})" if desc else ""))
            lines.append(
                "\nПодсказка: карточки приходят в бот-оповещатель после привязки."
            )
            await m.reply(_sanitize_newlines("\n".join(lines)),
                          disable_web_page_preview=True)

        @self.dp.message(Command("remove"), StateFilter("*"))
        async def remove_cmd(m: types.Message, state: FSMContext):
            await state.clear()
            self.account_register_if_needed(m.chat.id)
            parts = (m.text or "").split(maxsplit=1)
            if len(parts) < 2 or not parts[1].strip().isdigit():
                await m.reply(_sanitize_newlines("Укажите ID: /remove 3"))
                return
            ok = await self.manager.remove_subscription(
                m.chat.id, int(parts[1].strip()))
            await m.reply(
                _sanitize_newlines(
                    "Удалено." if ok else "Подписка не найдена."))

        @self.dp.message(Command("genkey"), StateFilter("*"))
        async def genkey_cmd(m: types.Message, state: FSMContext):
            await state.clear()
            if ADMIN_CHAT_ID is None or m.chat.id != ADMIN_CHAT_ID:
                await m.reply(
                    _sanitize_newlines("Команда доступна только админу."))
                return
            parts = (m.text or "").split()
            hours = int(
                parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 24
            uses = int(
                parts[2]) if len(parts) >= 3 and parts[2].isdigit() else 1
            key = self.issue_key(hours=hours, uses=uses)
            await m.reply(
                _sanitize_newlines(
                    "Сгенерирован ключ ✅\n"
                    f"Ключ: <code>{key}</code>\n"
                    f"Срок: {hours} ч\n"
                    f"Использований: {uses}\n\n"
                    "Отправьте пользователю в виде: <b>Ключ: </b><code>значение</code>"
                ))

        @self.dp.message(Command("diag"), StateFilter("*"))
        async def diag_cmd(m: types.Message, state: FSMContext):
            await state.clear()
            if ADMIN_CHAT_ID is None or m.chat.id != ADMIN_CHAT_ID:
                await m.reply(
                    _sanitize_newlines("Команда доступна только админу."))
                return
            lic = "✅" if self.license.is_active(m.chat.id) else "❌"
            bind = self.get_alert_chat_id(m.chat.id)
            subs = self.manager.list_user_subs(m.chat.id)
            watchers = list(self.manager.watchers.keys())
            lines = [
                "<b>Диагностика</b>",
                f"Лицензия: {lic}",
                f"Alert binding: {'✅ '+str(bind) if bind else '❌'}",
                f"Подписок у этого юзера: {len(subs)}",
                f"Активных вотчеров: {len(watchers)}",
            ]
            if watchers:
                lines.append("Ключи вотчеров:")
                for k in watchers:
                    lines.append("• " + html.escape(k)[:80])
            await m.reply(_sanitize_newlines("\n".join(lines)),
                          disable_web_page_preview=True)

        @self.dp.message(Command("dedup_clear"), StateFilter("*"))
        async def dedup_clear_cmd(m: types.Message, state: FSMContext):
            await state.clear()
            if ADMIN_CHAT_ID is None or m.chat.id != ADMIN_CHAT_ID:
                await m.reply(
                    _sanitize_newlines("Команда доступна только админу."))
                return
            parts = (m.text or "").split(maxsplit=1)
            target = parts[1].strip().lower() if len(parts) > 1 else ""
            data = self._load_sent()
            if not target or target == "all":
                data = {}
                self._save_sent(data)
                await m.reply(
                    _sanitize_newlines(
                        "Антидубликат очищен полностью (per-user и global)."))
                return
            if target == "global":
                if "_global" in data:
                    del data["_global"]
                self._save_sent(data)
                await m.reply(
                    _sanitize_newlines("Глобальный антидубликат очищен."))
                return
            if target.isdigit():
                if target in data:
                    del data[target]
                    self._save_sent(data)
                    await m.reply(
                        _sanitize_newlines(
                            f"Антидубликат очищен для user_id={target}."))
                else:
                    await m.reply(
                        _sanitize_newlines(
                            f"Для user_id={target} записей не было."))
                return
            await m.reply(
                _sanitize_newlines(
                    "Формат: /dedup_clear [all|global|<user_id>]"))

    async def setup_menu(self):
        await self.bot.set_my_commands([
            types.BotCommand(command="start", description="Начать работу"),
            types.BotCommand(command="add",
                             description="Добавить ссылку для мониторинга"),
            types.BotCommand(command="list",
                             description="Список ваших подписок"),
            types.BotCommand(command="remove",
                             description="Удалить подписку по ID"),
            types.BotCommand(command="newsearch",
                             description="Мастер подбора фильтров"),
            types.BotCommand(command="account", description="⚙️ Аккаунт"),
            types.BotCommand(command="genkey",
                             description="(админ) Выдать ключ"),
            types.BotCommand(command="diag",
                             description="(админ) Диагностика"),
            types.BotCommand(command="dedup_clear",
                             description="(админ) Очистка антидубликата"),
        ])


# ===== main =====
async def main():
    load_dotenv()
    keep_alive()  # no-op если нет
    token = os.getenv("BOT_TOKEN")
    if not token:
        raise RuntimeError("BOT_TOKEN отсутствует в .env/Secrets")
    app = App(token)
    await app.setup_menu()
    await app.dp.start_polling(app.bot)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass
