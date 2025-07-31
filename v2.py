# -*- coding: utf-8 -*-
"""
Avito Monitor Bot (aiogram 3.x) — версия с доработками под Replit и UX:
- Экран «Поиски» со слотами (inline).
- «Получить слот» -> сообщение с @Multiscan_service1.
- Поддержка — как на скрине (сообщение со ссылкой).
- Мастер: выходы на шаге URL, запрос имени поиска.
- Кнопка «Назад» возвращает в меню и чистит FSM.
- Попытка авторазбора ссылок: q= и (best-effort) f=.
"""
import os 
import re
import time 
import asyncio
import html
import base64
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Deque, Callable, cast, Any
from collections import deque
from datetime import datetime, timedelta
from urllib.parse import urlparse, urlunparse, parse_qs, parse_qsl, urlencode, unquote

from aiogram import Bot, Dispatcher, F, Router, types
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties
from aiogram.filters import Command
from aiogram.fsm.state import StatesGroup, State
from aiogram.fsm.context import FSMContext
from aiogram.fsm.storage.memory import MemoryStorage
from telegram_utils import safe_send_message, safe_send_photo

from dotenv import load_dotenv  # type: ignore[reportMissingImports]

import aiohttp
from bs4 import BeautifulSoup  # type: ignore[reportMissingImports]
from bs4.element import Tag

# keep-alive для Replit (фоновый Flask-сервер)
from background import keep_alive

FRESH_WINDOW_SEC = int(os.getenv("FRESH_WINDOW_SEC", "180"))
PRIME_ON_START = os.getenv("PRIME_ON_START", "0") == "1"

# ADMIN_CHAT_ID как int (или None)
_ADMIN_STR = os.getenv("ADMIN_CHAT_ID")
ADMIN_CHAT_ID: Optional[int] = int(_ADMIN_STR) if (_ADMIN_STR and _ADMIN_STR.lstrip("-").isdigit()) else None


@dataclass
class SubscriberFilter:
    keywords_all: List[str] = field(default_factory=list)
    keywords_any: List[str] = field(default_factory=list)
    price_min: Optional[int] = None
    price_max: Optional[int] = None


@dataclass
class Subscription:
    id: int
    user_id: int
    search_key: str
    url: str
    flt: SubscriberFilter = field(default_factory=SubscriberFilter)
    name: Optional[str] = None  # имя поиска, показывается в «Поисках»


def _normalize_url(url: str) -> str:
    u = urlparse(url.strip())
    if not u.scheme:
        u = u._replace(scheme="https")
    netloc = u.netloc or "www.avito.ru"
    keep = {}
    for k, v in parse_qsl(u.query, keep_blank_values=True):
        # выбрасываем utm_*
        if k.lower().startswith("utm_"):
            continue
        keep[k] = v
    query = urlencode(sorted(keep.items()))
    u2 = u._replace(netloc=netloc, query=query)
    return urlunparse(u2)


def search_key_from_url(url: str) -> str:
    return _normalize_url(url)


_MONTHS_RU = {
    "января": 1, "февраля": 2, "марта": 3, "апреля": 4, "мая": 5, "июня": 6,
    "июля": 7, "августа": 8, "сентября": 9, "октября": 10, "ноября": 11, "декабря": 12,
}


def _parse_avito_date(date_str: str):
    if not date_str:
        return None
    s = date_str.strip().lower()
    now = datetime.now()
    if "только что" in s:
        return now.timestamp()
    m = re.search(r"(\d+)\s*минут", s)
    if m:
        return (now - timedelta(minutes=int(m.group(1)))).timestamp()
    if "минуту назад" in s:
        return (now - timedelta(minutes=1)).timestamp()
    m = re.search(r"(\d+)\s*час", s)
    if m:
        return (now - timedelta(hours=int(m.group(1)))).timestamp()
    if "час назад" in s:
        return (now - timedelta(hours=1)).timestamp()
    m = re.search(r"(сегодня|вчера)[,\s]+(\d{1,2}:\d{2})", s)
    if m:
        day = now.date() if m.group(1) == "сегодня" else (now - timedelta(days=1)).date()
        hh, mm = map(int, m.group(2).split(":"))
        return datetime(day.year, day.month, day.day, hh, mm).timestamp()
    m = re.search(r"(\d{1,2})\s+([а-я]+)[,\s]+(\d{1,2}:\d{2})", s)
    if m:
        dd = int(m.group(1)) 
        mon = _MONTHS_RU.get(m.group(2)) 
        hh, mm = map(int, m.group(3).split(":"))
        if mon:
            return datetime(datetime.now().year, mon, dd, hh, mm).timestamp()
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


# ===== ХЕЛПЕРЫ ДЛЯ bs4/pyright =====
def _attr_to_str(v: object) -> str:
    if isinstance(v, str):
        return v
    if isinstance(v, (list, tuple)) and v and isinstance(v[0], str):
        return v[0]
    return ""


def _get_text(tag: Optional[Tag]) -> str:
    return tag.get_text(strip=True) if isinstance(tag, Tag) else ""


# ===== Попытка распарсить фильтры из ссылки Авито =====
def try_extract_filters_from_url(url: str) -> SubscriberFilter:
    """
    Best-effort: достаём q= (ключевые слова); пробуем раскодировать f= (если окажется JSON).
    Если ничего не получилось — просто вернём пустой фильтр.
    """
    flt = SubscriberFilter()
    try:
        u = urlparse(url)
        qs = parse_qs(u.query)
        # q=iphone 13 256
        if "q" in qs and qs["q"]:
            qval = unquote(qs["q"][0]).strip()
            # ключевые слова через пробел/запятую
            words = [w for w in re.split(r"[,\s]+", qval) if w]
            if words:
                flt.keywords_all = words

        # f=... — в Avito это неофициальный формат; иногда это JSON внутри base64-url
        fval = qs.get("f", [None])[0]
        if fval:
            s = fval.strip()
            # выравниваем base64-url паддинг
            pad = '=' * ((4 - len(s) % 4) % 4)
            raw = base64.urlsafe_b64decode(s + pad)
            # пытаемся распарсить как JSON
            try:
                j = json.loads(raw.decode("utf-8", errors="ignore"))
                # эвристики — ищем brand / storage / model / keywords
                text_parts: List[str] = []
                if isinstance(j, dict):
                    def pick(obj, keys):
                        for k in keys:
                            v = obj.get(k)
                            if isinstance(v, str) and v:
                                text_parts.append(v)
                    pick(j, ["brand", "model", "storage", "keyword", "q"])
                    # иногда это список критериев
                    if "params" in j and isinstance(j["params"], list):
                        for p in j["params"]:
                            if isinstance(p, dict):
                                pick(p, ["brand", "model", "storage", "value", "name"])
                if text_parts:
                    for token in text_parts:
                        for w in re.split(r"[,\s/]+", str(token)):
                            w = w.strip()
                            if w and w.lower() not in [x.lower() for x in flt.keywords_all]:
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
        self.interval_min = 0.30
        self.interval_max = 0.85
        self._interval = 0.45
        self._session: Optional[aiohttp.ClientSession] = None
        self.on_deliver = on_deliver

    async def start(self):
        if self.task and not self.task.done():
            return
        if PRIME_ON_START:
            await self._prime_seen(20)
        self.task = asyncio.create_task(self._run(), name=f"watch:{self.search_key}")

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

    async def _ensure_session(self) -> aiohttp.ClientSession:
        if self._session and not self._session.closed:
            return self._session
        self._session = aiohttp.ClientSession()
        return self._session

    def _fmt_price(self, v: Optional[int]) -> str:
        if v is None:
            return "—"
        return f"{v:,}".replace(",", " ") + " ₽"

    async def _enrich_ad_details(self, ad: Ad):
        try:
            session: aiohttp.ClientSession = await self._ensure_session()
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
                "Accept-Language": "ru,en;q=0.9",
                "Cache-Control": "no-cache",
            }
            async with session.get(ad.url, headers=headers, timeout=aiohttp.ClientTimeout(total=7.5)) as r:
                if r.status != 200:
                    return
                txt = await r.text()
                soup: BeautifulSoup = BeautifulSoup(txt, "html.parser")
                name_pe = soup.find(attrs={"data-marker": "seller-info/name"}) or soup.find(attrs={"data-marker": "seller-link"})
                if isinstance(name_pe, Tag):
                    ad.seller_name = _get_text(name_pe)
                m = re.search(r'"ownerId"\s*:\s*"?(?P<id>\d+)"?', txt)
                if m:
                    ad.seller_id = m.group("id")
                for b in ["Ниже рынка", "Хорошая цена", "Рыночная цена", "Выше рынка"]:
                    if b in txt:
                        ad.price_badge = b
                        break
                if not ad.image_url:
                    og = soup.find("meta", {"property": "og:image"})
                    if isinstance(og, Tag):
                        src = _attr_to_str(cast(Optional[str], og.get("content")))
                        if src:
                            ad.image_url = src
        except Exception:
            pass

    def _build_caption(self, ad: Ad) -> str:
        lines = [f"<b>{html.escape(ad.title)}</b>", ""]
        if ad.price is not None:
            price_line = f"💰 <b>{self._fmt_price(ad.price)}</b>"
            if ad.price_badge:
                price_line += f" ✅ <b>«{html.escape(ad.price_badge)}»</b>"
            lines.append(price_line)
        if ad.published_ts:
            lines.append("📅 " + datetime.fromtimestamp(ad.published_ts).strftime("%d.%m.%Y %H:%M:%S"))
        elif ad.date_str:
            lines.append("📅 " + html.escape(ad.date_str))
        if ad.seller_name:
            lines.append(f"👤 {html.escape(ad.seller_name)}")
        if ad.ad_id:
            lines.append(f"🆔 {ad.ad_id}")
        lines.append("")
        lines.append(ad.url)
        return "\n".join(lines)

    async def _fetch(self):
        session: aiohttp.ClientSession = await self._ensure_session()
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
            "Accept-Language": "ru,en;q=0.9",
            "Cache-Control": "no-cache",
        }
        try:
            async with session.get(self.url, headers=headers, timeout=aiohttp.ClientTimeout(total=7.5)) as r:
                if r.status == 200:
                    return await r.text()
        except Exception:
            return None
        return None

    async def _prime_seen(self, limit=20):
        html_text = await self._fetch()
        if not html_text:
            return
        for ad in self._parse_top(html_text, limit):
            self.seen[ad.ad_id] = time.time()

    def _parse_top(self, html_text: str, limit=20):
        soup: BeautifulSoup = BeautifulSoup(html_text, "html.parser")
        root_pe = soup.find("div", {"data-marker": "catalog-serp"})
        if not isinstance(root_pe, Tag):
            return []
        root: Tag = cast(Tag, root_pe)
        items_pe = root.find_all("div", {"data-marker": "item"}, limit=limit)
        items: List[Tag] = [cast(Tag, it) for it in items_pe if isinstance(it, Tag)]

        ads: List[Ad] = []
        for item in items:
            a_pe = item.find("a", {"data-marker": "item-title"})
            a: Optional[Tag] = cast(Tag, a_pe) if isinstance(a_pe, Tag) else None
            if not a:
                continue
            href = _attr_to_str(a.get("href"))
            url = ("https://www.avito.ru" + href) if href.startswith("/") else href
            m = re.search(r"/(\d{7,})", href or "")
            ad_id = m.group(1) if m else url
            title = _get_text(a)

            # Цена
            price: Optional[int] = None
            pr = item.find("meta", {"itemprop": "price"})
            if isinstance(pr, Tag):
                content = _attr_to_str(pr.get("content"))
                if content.isdigit():
                    try:
                        price = int(content)
                    except Exception:
                        price = None

            # Дата
            date_tag_pe = item.find("p", {"data-marker": "item-date"})
            date_tag: Optional[Tag] = cast(Tag, date_tag_pe) if isinstance(date_tag_pe, Tag) else None
            date_str = _get_text(date_tag)
            published_ts = _parse_avito_date(date_str)

            # Локация
            geo_div_pe = item.select_one("div[class^=geo-root-]")
            geo_div: Optional[Tag] = cast(Tag, geo_div_pe) if isinstance(geo_div_pe, Tag) else None
            location = _get_text(geo_div)

            # Описание
            desc_meta = item.find("meta", {"itemprop": "description"})
            description = _attr_to_str(desc_meta.get("content")).strip() if isinstance(desc_meta, Tag) else ""

            # Фото (если доступно в выдаче)
            img_pe = item.find("img")
            image_url = None
            if isinstance(img_pe, Tag):
                _src = _attr_to_str(img_pe.get("src")) or _attr_to_str(img_pe.get("data-src"))
                if _src:
                    image_url = ("https:" + _src) if _src.startswith("//") else _src

            ads.append(Ad(
                ad_id=ad_id, url=url, title=title, price=price,
                location=location, date_str=date_str, published_ts=published_ts,
                description=description, image_url=image_url
            ))
        return ads

    def _ad_passes_filters(self, ad: Ad, sub: Subscription) -> bool:
        flt = sub.flt
        if flt.price_min is not None and (ad.price is None or ad.price < flt.price_min):
            return False
        if flt.price_max is not None and (ad.price is None or ad.price > flt.price_max):
            return False
        t = f"{ad.title}\n{ad.description}".lower()
        return all(w.lower() in t for w in flt.keywords_all) if flt.keywords_all else True

    def _bump_interval(self, found_new: bool):
        self._interval = max(self.interval_min, self._interval * 0.7) if found_new else min(self.interval_max, self._interval * 1.1)

    def _cleanup_seen(self, ttl=7 * 24 * 3600):
        now = time.time()
        if len(self.seen) > 20000:
            items = sorted(self.seen.items(), key=lambda kv: kv[1])
            for k, _ in items[: len(items) // 2]:
                self.seen.pop(k, None)
        for k, ts in list(self.seen.items()):
            if now - ts > ttl:
                self.seen.pop(k, None)

    async def _run(self):
        while self.has_subscribers():
            found_new = False
            html_text = await self._fetch()
            if html_text:
                for ad in self._parse_top(html_text, limit=12):
                    if ad.ad_id in self.seen:
                        continue
                    now_ts = time.time()
                    if ad.published_ts is not None and (now_ts - ad.published_ts) > FRESH_WINDOW_SEC:
                        self.seen[ad.ad_id] = now_ts
                        continue
                    self.seen[ad.ad_id] = now_ts
                    for sub in list(self.subscribers.values()):
                        if not self._ad_passes_filters(ad, sub):
                            continue
                        await self._enrich_ad_details(ad)
                        caption = self._build_caption(ad)
                        if ad.image_url:
                            await safe_send_photo(
                                self.bot,
                                sub.user_id,
                                ad.image_url,
                                caption=caption,
                                disable_notification=False,
                            )
                        else:
                            await safe_send_message(
                                self.bot,
                                sub.user_id,
                                caption,
                                disable_web_page_preview=True,
                            )
                        if self.on_deliver:
                            self.on_deliver(sub.user_id, ad)
                        found_new = True
            self._cleanup_seen()
            self._bump_interval(found_new)
            await asyncio.sleep(max(0.25, self._interval))


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
        d.appendleft(FeedItem(ts=time.time(), title=ad.title, price=ad.price, url=ad.url, date_str=ad.date_str))

    async def add_subscription(self, user_id: int, url: str, flt: Optional[SubscriberFilter] = None) -> Subscription:
        if flt is None:
            flt = SubscriberFilter()
        key = search_key_from_url(url)
        sub = Subscription(id=self._next_sub_id(), user_id=user_id, search_key=key, url=url, flt=flt)
        w = self.watchers.get(key)
        if not w:
            w = Watcher(search_key=key, url=url, bot=self.bot, on_deliver=self._on_deliver)
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

    def get_sub_by_id(self, user_id: int, sub_id: int) -> Optional[Subscription]:
        for s in self.subs_by_user.get(user_id, []):
            if s.id == sub_id:
                return s
        return None

    def recent_feed(self, user_id: int, limit=10) -> List[FeedItem]:
        return list(self.feed.get(user_id, deque()))[:limit]


MAIN_KB = types.ReplyKeyboardMarkup(
    keyboard=[
        [types.KeyboardButton(text="📘 Инструкция"), types.KeyboardButton(text="🧭 Поиски")],
        [types.KeyboardButton(text="🛟 Поддержка"), types.KeyboardButton(text="🗂 Лента")],
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
    confirm = State()
    name = State()  # новое: имя поиска


wizard_router = Router(name="wizard")

# Мастер теперь стартует ТОЛЬКО по /newsearch, а не по «🧭 Поиски»
@wizard_router.message(F.text.in_(["/newsearch"]))
async def wizard_start(message: types.Message, state: FSMContext):
    await state.clear()
    await state.set_state(SearchWizard.url)
    await message.answer(
        "Шаг 1/3.\nПришлите ссылку категории с сайта <a href='https://avito.ru'>Avito.ru</a>.\n\n"
        "‼️ <b>Обязательно укажите максимальную цену</b> в фильтрах Авито перед копированием ссылки. "
        "Если верхняя граница не важна — поставьте <code>100000000</code>.",
        reply_markup=types.ReplyKeyboardRemove(),
        disable_web_page_preview=True,
    )

# Выходы из мастера прямо на шаге URL
@wizard_router.message(SearchWizard.url, F.text.casefold() == "отмена")
@wizard_router.message(SearchWizard.url, F.text.casefold() == "назад")
@wizard_router.message(SearchWizard.url, F.text.in_(["🗂 Лента", "Лента", "📘 Инструкция", "🛟 Поддержка", "🧭 Поиски"]))
async def wizard_cancel_from_url(message: types.Message, state: FSMContext):
    await state.clear()
    await message.answer("Мастер прерван. Вы в главном меню.", reply_markup=MAIN_KB)

@wizard_router.message(SearchWizard.url)
async def wizard_got_url(message: types.Message, state: FSMContext):
    raw = (message.text or "").strip()
    # вытаскиваем первую ссылку из текста, если пользователь прислал «с рассказом»
    m = re.search(r"https?://\S+", raw)
    url_in = m.group(0) if m else raw
    if "avito.ru" not in url_in:
        await message.answer("Похоже, это не ссылка Авито. Вставьте корректный URL.")
        return

    url = search_key_from_url(url_in)
    # автозаполнение фильтров из URL (best-effort)
    guessed = try_extract_filters_from_url(url)

    await state.update_data(url=url, guessed_kw=guessed.keywords_all)
    await state.set_state(SearchWizard.price_min)
    kw_txt = f"\n\nНайдены ключевые слова из ссылки: <code>{', '.join(guessed.keywords_all)}</code>" if guessed.keywords_all else ""
    await message.answer(
        "Шаг 2/3.\nМинимальная цена (или «-», если без минимума):" + kw_txt,
        reply_markup=types.ReplyKeyboardMarkup(
            keyboard=[[types.KeyboardButton(text="-")], [types.KeyboardButton(text="Отмена")]],
            resize_keyboard=True
        ),
    )

@wizard_router.message(SearchWizard.price_min, F.text.casefold() == "отмена")
async def wizard_cancel_min(message: types.Message, state: FSMContext):
    await state.clear()
    await message.answer("Мастер отменён.", reply_markup=MAIN_KB)

@wizard_router.message(SearchWizard.price_min)
async def wizard_got_min(message: types.Message, state: FSMContext):
    txt = (message.text or "").strip()
    pmin = None
    if txt != "-":
        if not txt.isdigit():
            await message.answer("Введите число или «-».")
            return
        pmin = int(txt)
    await state.update_data(price_min=pmin)
    await state.set_state(SearchWizard.price_max)
    await message.answer(
        "Теперь <b>максимальная цена</b> (обязательно число):",
        reply_markup=types.ReplyKeyboardMarkup(
            keyboard=[[types.KeyboardButton(text="100000000")], [types.KeyboardButton(text="Отмена")]],
            resize_keyboard=True
        ),
    )

@wizard_router.message(SearchWizard.price_max, F.text.casefold() == "отмена")
async def wizard_cancel_max(message: types.Message, state: FSMContext):
    await state.clear()
    await message.answer("Мастер отменён.", reply_markup=MAIN_KB)

@wizard_router.message(SearchWizard.price_max)
async def wizard_got_max(message: types.Message, state: FSMContext):
    txt = (message.text or "").strip()
    if not txt.isdigit():
        await message.answer("Максимальная цена обязательна. Введите число, например 100000000.")
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
    await message.answer("\n".join(summary), disable_web_page_preview=True)

@wizard_router.message(SearchWizard.name, F.text.casefold() == "отмена")
async def wizard_cancel_name(message: types.Message, state: FSMContext):
    await state.clear()
    await message.answer("Мастер отменён.", reply_markup=MAIN_KB)

@wizard_router.message(SearchWizard.name)
async def wizard_finish_create(message: types.Message, state: FSMContext):
    data = await state.get_data()
    url = data.get("url") or ""
    pmin = data.get("price_min")
    pmax = data.get("price_max")
    kw = data.get("guessed_kw") or []
    name = (message.text or "").strip() or None

    flt = SubscriberFilter(price_min=pmin, price_max=pmax, keywords_all=kw)
    sub = await cast(Any, message.bot).app.manager.add_subscription(message.chat.id, url, flt)
    sub.name = name

    await state.clear()
    await message.answer(
        "Поиск создан ✅\n"
        f"Название: <b>{html.escape(name or f'Поиск №{sub.id}')}</b>\n"
        f"URL: {url}\n"
        + (f"min={pmin} " if pmin is not None else "")
        + (f"max={pmax} " if pmax is not None else "") + "\n\n"
        "Для оповещений просто ждите — бот пришлёт новые объявления.",
        reply_markup=MAIN_KB,
        disable_web_page_preview=True,
    )


# ===== Поддержка (скрин 3) =====
support_router = Router(name="support")

@support_router.message(F.text.in_(["🛟 Поддержка", "Поддержка"]))
async def support_info(message: types.Message, state: FSMContext):
    await state.clear()
    await message.answer(
        "По любым вопросам или проблемам — тех. поддержка или просто хороший совет\n\n"
        "👉 <a href='https://t.me/Multiscan_service1'>@Multiscan_service1</a>",
        reply_markup=MAIN_KB,
        disable_web_page_preview=True
    )


# ===== Экран «Поиски» (слоты) =====
def build_searches_kb(subs: List[Subscription]) -> types.InlineKeyboardMarkup:
    rows: List[List[types.InlineKeyboardButton]] = []
    for s in subs:
        label = s.name or f"Поиск №{s.id}"
        rows.append([types.InlineKeyboardButton(text=label, callback_data=f"open_sub:{s.id}")])
    rows.append([types.InlineKeyboardButton(text="➕ Получить слот", callback_data="get_slot")])
    rows.append([types.InlineKeyboardButton(text="❌ Закрыть", callback_data="close_menu")])
    return types.InlineKeyboardMarkup(inline_keyboard=rows)

def format_sub_panel(sub: Subscription) -> str:
    parts = [f"<b>{html.escape(sub.name or f'Подписка №{sub.id}')}</b>"]
    if sub.flt.price_max is not None:
        parts.append(f"💰 <b>Максимальная цена:</b> {sub.flt.price_max} ₽")
    else:
        parts.append("💰 <b>Максимальная цена:</b> не задана")
    if sub.flt.price_min is not None:
        parts.append(f"💵 <b>Минимальная цена:</b> {sub.flt.price_min} ₽")
    if sub.flt.keywords_all:
        parts.append(f"✅ <b>ЦЕЛЕВЫЕ слова:</b> {', '.join(sub.flt.keywords_all)}")
    parts.append(f"\n🌐 <b>URL:</b> {sub.url}")
    parts.append("\n<b>Продвинутые фильтры</b>\n📦 Только новые: ✅")
    return "\n".join(parts)

class EditPrice(StatesGroup):
    value = State()   # в state.data хранится field=min|max и sub_id

searches_router = Router(name="searches")

@searches_router.message(F.text.in_(["🧭 Поиски", "Поиски"]))
async def searches_screen(message: types.Message, state: FSMContext):
    await state.clear()
    subs = cast(Any, message.bot).app.manager.list_user_subs(message.chat.id)
    kb = build_searches_kb(subs)
    await message.answer("Поиски", reply_markup=MAIN_KB)
    await message.answer("Выберите поиск или получите новый слот:", reply_markup=kb)



@searches_router.callback_query(F.data == "get_slot")
async def cb_get_slot(cq: types.CallbackQuery):
    # если это реальное Message — отвечаем в чат
    if isinstance(cq.message, types.Message):
        await cq.message.answer(
            "Для покупки ключа или получения тестового доступа свяжитесь с\n\n"
            "👉 <a href='https://t.me/Multiscan_service1'>@Multiscan_service1</a>.",
            disable_web_page_preview=True
        )
    # независимо от того, показали ли мы текст, просто гасим "часики" у кнопки
    await cq.answer()

@searches_router.callback_query(F.data == "close_menu")
async def cb_close_menu(cq: types.CallbackQuery):
    # аналогично — только если у нас именно Message, пробуем удалить
    if isinstance(cq.message, types.Message):
        try:
            await cq.message.delete()
        except Exception:
            pass
    await cq.answer()


@searches_router.callback_query(F.data.startswith("open_sub:"))
async def cb_open_sub(cq: types.CallbackQuery, state: FSMContext):
    # 1) Сужаем тип cq.data до str, чтобы .split() точно было доступно
    data_str: str = cq.data or ""
    try:
        sub_id = int(data_str.split(":", 1)[1])
    except Exception:
        # если вдруг не получилось распарсить — просто гасим “часики” и выходим
        await cq.answer()
        return

    # 2) Берём user_id из from_user, а не из message.chat (message может быть InaccessibleMessage/None)
    user_id = cq.from_user.id
    mng = cast(Any, cq.bot).app.manager
    sub = mng.get_sub_by_id(user_id, sub_id)
    if not sub:
        await cq.answer("Подписка не найдена", show_alert=True)
        return

    # 3) Гарантированно проверяем, что cq.message — настоящий types.Message,
    #    чтобы .answer() у него точно существовал
    if isinstance(cq.message, types.Message):
        kb = types.ReplyKeyboardMarkup(
            keyboard=[
                [types.KeyboardButton(text="Показать последние объявления")],
                [types.KeyboardButton(text="Изменить мин. цену"), types.KeyboardButton(text="Изменить макс. цену")],
                [types.KeyboardButton(text="Удалить подписку"), types.KeyboardButton(text="Назад")],
            ],
            resize_keyboard=True,
        )
        await cq.message.answer(
            format_sub_panel(sub),
            reply_markup=kb,
            disable_web_page_preview=True,
        )

    # и в любом случае га́сим “часики” на inline‑кнопке
    await cq.answer()


# ===== Меню «Лента» и действия =====
actions_router = Router(name="actions")

@actions_router.message(F.text == "Показать последние объявления")
async def feed_show(m: types.Message, state: FSMContext):
    items = cast(Any, m.bot).app.manager.recent_feed(m.chat.id, limit=5)
    if not items:
        await m.reply("Пока в ленте пусто. Как только появятся новые — они будут здесь.")
        return
    lines = ["🗂 Последние присланные объявления:"]
    for it in items:
        price_txt = f"{it.price} ₽" if it.price is not None else "—"
        dt = datetime.fromtimestamp(it.ts).strftime("%H:%M:%S")
        lines.append(f"• {it.title} — {price_txt} — {dt}\n{it.url}")
    await m.reply("\n".join(lines), disable_web_page_preview=True)

@actions_router.message(F.text == "Удалить подписку")
async def ui_remove_last(m: types.Message, state: FSMContext):
    await state.clear()
    subs = cast(Any, m.bot).app.manager.list_user_subs(m.chat.id)
    if not subs:
        await m.reply("У вас пока нет подписок.", reply_markup=MAIN_KB)
        return
    sub = subs[-1]
    ok = await cast(Any, m.bot).app.manager.remove_subscription(m.chat.id, sub.id)
    await m.reply(f"Подписка «{sub.name or sub.id}» удалена." if ok else "Не удалось удалить подписку.", reply_markup=MAIN_KB)

@actions_router.message(F.text == "Изменить мин. цену")
async def ui_edit_min(m: types.Message, state: FSMContext):
    subs = cast(Any, m.bot).app.manager.list_user_subs(m.chat.id)
    if not subs:
        await m.reply("У вас пока нет подписок.")
        return
    await state.set_state(EditPrice.value)
    await state.update_data(field="min", sub_id=subs[-1].id)
    await m.reply(
        "Введите новую <b>минимальную</b> цену или «-» чтобы убрать ограничение:",
        reply_markup=types.ReplyKeyboardMarkup(
            keyboard=[[types.KeyboardButton(text="-")],[types.KeyboardButton(text="Отмена")]],
            resize_keyboard=True
        )
    )

@actions_router.message(F.text == "Изменить макс. цену")
async def ui_edit_max(m: types.Message, state: FSMContext):
    subs = cast(Any, m.bot).app.manager.list_user_subs(m.chat.id)
    if not subs:
        await m.reply("У вас пока нет подписок.")
        return
    await state.set_state(EditPrice.value)
    await state.update_data(field="max", sub_id=subs[-1].id)
    await m.reply(
        "Введите новую <b>максимальную</b> цену (число). Если верхняя граница не важна — укажите 100000000:",
        reply_markup=types.ReplyKeyboardMarkup(
            keyboard=[[types.KeyboardButton(text="100000000")],[types.KeyboardButton(text="Отмена")]],
            resize_keyboard=True
        )
    )

@actions_router.message(EditPrice.value, F.text.casefold() == "отмена")
async def ui_edit_cancel(m: types.Message, state: FSMContext):
    await state.clear()
    await m.reply("Изменение цены отменено.", reply_markup=MAIN_KB)

@actions_router.message(EditPrice.value)
async def ui_edit_apply(m: types.Message, state: FSMContext):
    data = await state.get_data()
    field = data.get("field")
    sub_id = data.get("sub_id")
    txt = (m.text or "").strip()

    mng = cast(Any, m.bot).app.manager
    sub = mng.get_sub_by_id(m.chat.id, int(sub_id)) if sub_id is not None else None
    if not sub:
        await state.clear()
        await m.reply("Подписка не найдена.", reply_markup=MAIN_KB)
        return

    if field == "min":
        if txt == "-":
            sub.flt.price_min = None
        elif txt.isdigit():
            sub.flt.price_min = int(txt)
        else:
            await m.reply("Введите число или «-».")
            return
    else:  # field == "max"
        if not txt.isdigit():
            await m.reply("Максимальная цена должна быть числом, например 100000000.")
            return
        sub.flt.price_max = int(txt)

    await state.clear()
    await m.reply(
        "Готово. Текущие параметры:\n"
        f"• Мин: {sub.flt.price_min if sub.flt.price_min is not None else '—'}\n"
        f"• Макс: {sub.flt.price_max if sub.flt.price_max is not None else '—'}",
        reply_markup=MAIN_KB
    )

# ===== Главное приложение =====
class App:
    def __init__(self, token: str):
        self.bot = Bot(token=token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
        cast(Any, self.bot).app = self
        from typing import Any as _Any
        cast(_Any, self.bot).app = self
        self.dp = Dispatcher(storage=MemoryStorage())
        self.manager = WatcherManager(self.bot)
        self._register()

    async def setup_menu(self):
        await self.bot.set_my_commands(
            [
                types.BotCommand(command="start", description="Начать работу"),
                types.BotCommand(command="add", description="Добавить ссылку для мониторинга"),
                types.BotCommand(command="list", description="Список ваших подписок"),
                types.BotCommand(command="remove", description="Удалить подписку по ID"),
                types.BotCommand(command="feed", description="Лента присланных объявлений"),
                types.BotCommand(command="newsearch", description="Мастер подбора фильтров"),
            ]
        )

    def _register(self):
        self.dp.include_router(wizard_router)
        self.dp.include_router(support_router)
        self.dp.include_router(searches_router)
        self.dp.include_router(actions_router)

        # Назад -> главное меню (и чистим FSM)
        @self.dp.message(F.text == "Назад")
        async def back_btn(m: types.Message, state: FSMContext):
            await state.clear()
            await m.answer("Главное меню.", reply_markup=MAIN_KB)

        # Инструкция
        @self.dp.message(F.text.in_(["📘 Инструкция", "Инструкция", "/help"]))
        async def help_cmd(m: types.Message):
            await m.answer(
                "📘 <b>Инструкция по настройке</b>\n\n"
                "1. Свяжитесь с поддержкой 👉 @Multiscan_service1 и получите Ваш уникальный ключ.\n"
                "   Один ключ позволяет создавать один поиск в системе.\n\n"
                "2. Отправьте ключ в этом чате — активируется возможность создать новый поиск.\n\n"
                "3. Скопируйте ссылку Авито с нужным поиском:\n"
                "   • Настройте фильтры на сайте Авито (категория, регион, ключевые слова и т.п.)\n"
                "   • ‼️ <b>Обязательно укажите максимальную цену</b>. Если она не важна — поставьте 100000000.\n"
                "   • Скопируйте ссылку из адресной строки браузера.\n"
                "   ⁉️ Если не уверены в ссылке — напишите в поддержку 👉 @Multiscan_service1\n\n"
                "4. В боте нажмите <b>«🧭 Поиски»</b>, затем <b>«➕ Получить слот»</b>, и следуйте инструкциям.\n\n"
                "5. При запросе введите максимальную цену.\n"
                "   Это позволит менять цену позже в личном кабинете.\n\n"
                "6. Придумайте название для поиска.\n"
                "   Оно нужно, чтобы различать их, если у вас несколько.\n\n"
                "7. Бот будет присылать свежие объявления с Авито сразу после появления.\n\n"
                "🔧 Параметры поиска можно изменить в разделе <b>Поиски</b>.",
                reply_markup=MAIN_KB,
                disable_web_page_preview=True
            )

        @self.dp.message(Command("start"))
        async def start_cmd(m: types.Message):
            await m.answer(
                "Я пришлю вам <b>только что опубликованные</b> объявления по вашим фильтрам.\n\n"
                "• Быстрый старт: <code>/add https://www.avito.ru/...</code>\n"
                "• Мастер: <code>/newsearch</code>\n"
                "• Экран слотов: кнопка «🧭 Поиски»\n"
                "• Лента: <code>/feed</code> или кнопка «🗂 Лента»",
                reply_markup=MAIN_KB,
                disable_web_page_preview=True,
            )

        # Быстрый /add (оставляем)
        @self.dp.message(Command("add"))
        async def add_cmd(m: types.Message):
            txt = (m.text or "")
            parts = txt.split(maxsplit=2)
            if len(parts) < 2:
                await m.reply("Укажите ссылку после /add. Пример:\n/add https://www.avito.ru/... kw=iphone,min=10000")
                return
            url = parts[1].strip()
            params = parts[2].strip() if len(parts) >= 3 else ""
            flt = try_extract_filters_from_url(url)  # авто-добираем q=/f= из ссылки
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
                await m.reply("⚠️ Укажите максимальную цену (параметр <code>max=</code>) или воспользуйтесь мастером «/newsearch».")
                return
            sub = await cast(Any, m.bot).app.manager.add_subscription(m.chat.id, url, flt)
            await m.reply(
                f"Подписка добавлена: <b>{sub.id}</b>\nСсылка: {url}\n"
                "Подсказка: «🗂 Лента» — панель подписки; «/feed» — последние карточки."
            )

        @self.dp.message(Command("list"))
        async def list_cmd(m: types.Message):
            subs = cast(Any, m.bot).app.manager.list_user_subs(m.chat.id)
            if not subs:
                await m.reply("У вас нет активных подписок.")
                return
            lines = ["Ваши подписки:"]
            for s in subs:
                desc = []
                if s.name:
                    desc.append(f"name={s.name}")
                if s.flt.keywords_all:
                    desc.append(f"kw={','.join(s.flt.keywords_all)}")
                if s.flt.price_min is not None:
                    desc.append(f"min={s.flt.price_min}")
                if s.flt.price_max is not None:
                    desc.append(f"max={s.flt.price_max}")
                lines.append(f"{s.id}: {s.url} " + (f"({'; '.join(desc)})" if desc else ""))
            lines.append("\nПодсказка: /feed — последние присланные карточки.")
            await m.reply("\n".join(lines), disable_web_page_preview=True)

        @self.dp.message(Command("remove"))
        async def remove_cmd(m: types.Message):
            parts = (m.text or "").split(maxsplit=1)
            if len(parts) < 2 or not parts[1].strip().isdigit():
                await m.reply("Укажите ID: /remove 3")
                return
            ok = await cast(Any, m.bot).app.manager.remove_subscription(m.chat.id, int(parts[1].strip()))
            await m.reply("Удалено." if ok else "Подписка не найдена.")

        @self.dp.message(Command("feed"))
        async def feed_cmd(m: types.Message):
            items = cast(Any, m.bot).app.manager.recent_feed(m.chat.id, limit=10)
            if not items:
                await m.reply("Пока в ленте пусто. Как только появятся новые — они будут здесь.")
                return
            lines = ["🗂 Последние присланные объявления:"]
            for it in items:
                price_txt = f"{it.price} ₽" if it.price is not None else "—"
                dt = datetime.fromtimestamp(it.ts).strftime("%H:%M:%S")
                lines.append(f"• {it.title} — {price_txt} — {dt}\n{it.url}")
            await m.reply("\n".join(lines), disable_web_page_preview=True)

        # Кнопка «Лента» — показать панель по последней подписке (быстрый доступ)
        @self.dp.message(F.text.in_(["🗂 Лента", "Лента"]))
        async def feed_btn(m: types.Message):
            subs = cast(Any, m.bot).app.manager.list_user_subs(m.chat.id)
            if not subs:
                await m.reply("У вас пока нет подписок. Нажмите «🧭 Поиски», затем «➕ Получить слот», вставьте ссылку Авито и задайте цены.")
                return
            sub = subs[-1]
            kb = types.ReplyKeyboardMarkup(
                keyboard=[
                    [types.KeyboardButton(text="Показать последние объявления")],
                    [types.KeyboardButton(text="Изменить мин. цену"), types.KeyboardButton(text="Изменить макс. цену")],
                    [types.KeyboardButton(text="Удалить подписку"), types.KeyboardButton(text="Назад")],
                ],
                resize_keyboard=True,
            )
            await m.reply(format_sub_panel(sub), reply_markup=kb, disable_web_page_preview=True)


# ===== main =====
async def main():
    load_dotenv()
    keep_alive()  # Replit keep-alive
    token = os.getenv("BOT_TOKEN")
    if not token:
        raise RuntimeError("BOT_TOKEN отсутствует в .env/Secrets")
    app = App(token)
    await app.setup_menu()
    await app.dp.start_polling(app.bot)

keep_alive()
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass
