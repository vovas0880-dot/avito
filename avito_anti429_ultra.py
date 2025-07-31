# -*- coding: utf-8 -*-
"""
avito_anti429_ultra.py
======================
«Тяжёлая» интеграция для avito_monitor_bot.py с максимумом анти-429 и маскировки.

Что делает:
- Ротация HTTP/HTTPS и (опционально) SOCKS5 прокси (на каждый прокси — свой ClientSession + CookieJar).
- Оценка «здоровья» прокси (score), остуживание (cooldown) и карантин при частых фейлах.
- Фингерпринт заголовков: динамический User-Agent, Accept-Language, Sec-CH.
- Расширенная аналитика банов (EWMA + профиль по часу суток), запись JSONL.
- Адаптивный интервал опроса: 70% EWMA «жизни без бана», помноженный на профиль по часу суток.
- Пер-URL rate-limiter (token bucket), чтобы не долбить одинаковые ссылки.
- Опциональный headless-браузер (Playwright) для «подогрева» cookie раз в N минут.
- Подробные логи запросов (request_log.jsonl) и метрики (metrics.json).
- Админ-команды: /banstats, /proxystats, /forcerotate, /headlesstouch.

Интеграция (4 шага):
1) Положи файл рядом с avito_monitor_bot.py
2) Вверху avito_monitor_bot.py:
       from avito_anti429_ultra import patch_watcher_ultra, extend_app_ultra
3) Сразу ПОСЛЕ объявления класса Watcher:
       patch_watcher_ultra(Watcher)
4) В месте, где готов твой app (где есть app.dp и app.manager.watchers), вызови:
       extend_app_ultra(app)

Опциональные зависимости:
- SOCKS:  pip install aiohttp-socks
  ВНИМАНИЕ: если у тебя aiogram 3.7.0 (aiohttp~=3.9), то aiohttp-socks (aiohttp>=3.10) может конфликтовать.
  Код ниже подключает SOCKS «мягко»: если импорт не удался, будет работать только HTTP/HTTPS-прокси.
- Headless:  pip install playwright && playwright install chromium

ENV (пример):
    PROXY_LIST=http://user:pass@1.1.1.1:3128;http://2.2.2.2:8080
    SOCKS_PROXY_LIST=socks5://user:pass@3.3.3.3:1080
    PROXY_COOLDOWN_SEC=1200
    PROXY_QUARANTINE_SEC=7200
    PROXY_FAIL_LIMIT=3
    PROXY_SCORE_DECAY=0.95

    BAN_LOG_FILE=ban_intervals.jsonl
    REQUEST_LOG_FILE=request_log.jsonl
    METRICS_FILE=metrics.json
    BAN_WINDOW_SEC=1800
    MAX_BANS_PER_WINDOW=3
    HARD_PAUSE_SEC=1800
    JITTER_FRAC=0.15

    RATE_TOKEN_BUCKET=5
    RATE_REFILL_SEC=60
    RATE_MIN_INTERVAL_SEC=10
    RATE_MAX_INTERVAL_SEC=300

    HEADLESS_REFRESH=0
    HEADLESS_PERIOD_SEC=900
    HEADLESS_URLS=https://www.avito.ru/
"""

from typing import Optional, List, Dict, Tuple, Any
import os
import re
import time
import random
import json
import asyncio
from urllib.parse import urlparse

# ===== ENV =====
BAN_LOG_FILE = os.getenv("BAN_LOG_FILE", "ban_intervals.jsonl")
REQUEST_LOG_FILE = os.getenv("REQUEST_LOG_FILE", "request_log.jsonl")
METRICS_FILE = os.getenv("METRICS_FILE", "metrics.json")
BAN_WINDOW_SEC = int(os.getenv("BAN_WINDOW_SEC", "1800"))
MAX_BANS_PER_WINDOW = int(os.getenv("MAX_BANS_PER_WINDOW", "3"))
HARD_PAUSE_SEC = int(os.getenv("HARD_PAUSE_SEC", "1800"))
JITTER_FRAC = float(os.getenv("JITTER_FRAC", "0.15"))

PROXY_LIST = os.getenv("PROXY_LIST", "").strip()
SOCKS_PROXY_LIST = os.getenv("SOCKS_PROXY_LIST", "").strip()
PROXY_COOLDOWN_SEC = int(os.getenv("PROXY_COOLDOWN_SEC", "1200"))
PROXY_QUARANTINE_SEC = int(os.getenv("PROXY_QUARANTINE_SEC", "7200"))
PROXY_FAIL_LIMIT = int(os.getenv("PROXY_FAIL_LIMIT", "3"))
PROXY_SCORE_DECAY = float(os.getenv("PROXY_SCORE_DECAY", "0.95"))

RATE_TOKEN_BUCKET = int(os.getenv("RATE_TOKEN_BUCKET", "5"))
RATE_REFILL_SEC = int(os.getenv("RATE_REFILL_SEC", "60"))
RATE_MIN_INTERVAL_SEC = float(os.getenv("RATE_MIN_INTERVAL_SEC", "10"))
RATE_MAX_INTERVAL_SEC = float(os.getenv("RATE_MAX_INTERVAL_SEC", "300"))

HEADLESS_REFRESH = os.getenv("HEADLESS_REFRESH", "0") == "1"
HEADLESS_PERIOD_SEC = int(os.getenv("HEADLESS_PERIOD_SEC", "900"))
HEADLESS_URLS = [
    u for u in re.split(r"[;\n\r,\t ]+", os.getenv("HEADLESS_URLS", "https://www.avito.ru/").strip()) if u
]

# ===== UA / языки =====
DEFAULT_UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
]
ACCEPT_LANGS = [
    "ru-RU,ru;q=0.9,en;q=0.8",
    "ru,en;q=0.9",
    "ru-RU,ru;q=0.9,uk;q=0.8,en;q=0.7",
]


# ===== утилиты =====
def _now() -> float:
    return time.time()


def _jitter(base: float) -> float:
    extra = base * random.uniform(-JITTER_FRAC, JITTER_FRAC)
    return max(1.0, base + extra)


def _append_jsonl(path: str, obj: dict):
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _read_json(path: str, default: Any):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return default


def _write_json(path: str, obj: Any):
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except Exception:
        pass


# ===== Fingerprinter =====
class Fingerprinter:
    def __init__(self):
        self.ua = random.choice(DEFAULT_UA_LIST)

    def rotate(self):
        self.ua = random.choice(DEFAULT_UA_LIST)

    def headers(self) -> dict:
        al = random.choice(ACCEPT_LANGS)
        # лёгкая имитация Client Hints
        sec_ch = {
            "sec-ch-ua": '"Chromium";v="120", "Not(A:Brand";v="24"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "Windows",
        }
        h = {
            "User-Agent": self.ua,
            "Accept-Language": al,
            "Cache-Control": "no-cache",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Referer": "https://www.avito.ru/",
        }
        h.update(sec_ch)
        return h


# ===== Proxy Orchestrator =====
class ProxyOrchestrator:
    """
    На каждый прокси держит отдельный ClientSession (+CookieJar).
    Оценивает здоровье (score), остужает и отправляет в карантин при частых фейлах.
    Работает с HTTP/HTTPS прокси всегда; SOCKS используется только если установлен aiohttp-socks.
    """

    def __init__(self, http_list: str, socks_list: str, cooldown: int, quarantine: int, fail_limit: int, score_decay: float):
        self.http = self._parse(http_list)
        self.socks = self._parse(socks_list)
        self.cooldown = int(cooldown)
        self.quarantine = int(quarantine)
        self.fail_limit = int(fail_limit)
        self.score_decay = float(score_decay)

        self._cool_until: Dict[str, float] = {}
        self._quar_until: Dict[str, float] = {}
        self._fails: Dict[str, int] = {}
        self._score: Dict[str, float] = {}  # выше — лучше
        self._sessions: Dict[str, Tuple[Any, bool]] = {}  # proxy -> (session, is_socks)
        self._aiohttp = None
        self._ProxyConnector = None  # для SOCKS (опционально)

    def _parse(self, s: str) -> List[str]:
        s = (s or "").strip()
        if not s:
            return []
        return [p.strip() for p in re.split(r"[;\n\r,\t ]+", s) if p.strip()]

    async def _ensure_http(self):
        if self._aiohttp is None:
            import aiohttp
            self._aiohttp = aiohttp
        return self._aiohttp

    async def _ensure_socks(self):
        # попытка «мягкого» импорта SOCKS-коннектора
        if self._ProxyConnector is None:
            try:
                from aiohttp_socks import ProxyConnector  # type: ignore
                self._ProxyConnector = ProxyConnector
            except Exception:
                self._ProxyConnector = False
        return self._ProxyConnector

    def _available(self, p: str, now: float) -> bool:
        return now >= self._cool_until.get(p, 0.0) and now >= self._quar_until.get(p, 0.0)

    async def _make_http(self, proxy: str):
        aiohttp = await self._ensure_http()
        jar = aiohttp.CookieJar()
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        # Прокси подставляется при самом запросе через параметр proxy=
        return aiohttp.ClientSession(cookie_jar=jar, timeout=timeout, trust_env=False)

    def build_connector(self, proxy_str: str):
        """
        Построить SOCKS-коннектор. Стараемся использовать ProxyConnector.from_url,
        а при отсутствии — собрать вручную. Если aiohttp_socks не установлен, бросим исключение выше.
        """
        ProxyConnector = self._ProxyConnector
        if not ProxyConnector:
            raise RuntimeError("SOCKS ProxyConnector is not available")
        # у разных версий разные API — пробуем безопасно
        if hasattr(ProxyConnector, "from_url"):
            return ProxyConnector.from_url(proxy_str)  # type: ignore[attr-defined]
        # запасной путь
        parsed = urlparse(proxy_str)
        kwargs = dict(
            host=parsed.hostname,
            port=parsed.port,
            username=parsed.username,
            password=parsed.password,
            rdns=True,
        )
        try:
            return ProxyConnector(**kwargs)  # type: ignore[call-arg]
        except TypeError:
            # последняя попытка
            return ProxyConnector.from_url(proxy_str)  # type: ignore[attr-defined]

    async def _make_socks(self, proxy: str):
        aiohttp = await self._ensure_http()
        ProxyConnector = await self._ensure_socks()
        if not ProxyConnector:
            return None
        jar = aiohttp.CookieJar()
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        conn = self.build_connector(proxy)
        return aiohttp.ClientSession(cookie_jar=jar, timeout=timeout, connector=conn, trust_env=False)

    async def _get_or_create(self, proxy: str, is_socks: bool):
        if proxy in self._sessions:
            sess, is_s = self._sessions[proxy]
            if not sess.closed:
                return self._sessions[proxy]
        sess = await (self._make_socks(proxy) if is_socks else self._make_http(proxy))
        if sess is None:
            return None
        self._sessions[proxy] = (sess, is_socks)
        return self._sessions[proxy]

    def _weighted_choice(self, alive: List[str]) -> str:
        weights = [self._score.get(p, 0.0) + 1.0 for p in alive]
        total = sum(weights)
        pick = random.random() * total
        acc = 0.0
        for p, w in zip(alive, weights):
            acc += w
            if acc >= pick:
                return p
        return alive[-1]

    async def get(self) -> Optional[Tuple[Any, Optional[str], bool, str]]:
        """
        Возвращает (session, proxy_for_request, is_socks, proxy_key).
        Для SOCKS proxy_for_request=None (прокси в коннекторе).
        """
        now = _now()

        # сначала SOCKS, если библиотека есть и прокси указаны
        ProxyConnector = await self._ensure_socks()
        if self.socks and ProxyConnector:
            alive = [p for p in self.socks if self._available(p, now)]
            if alive:
                p = self._weighted_choice(alive)
                pair = await self._get_or_create(p, True)
                if pair:
                    sess, _ = pair
                    return (sess, None, True, p)

        # затем HTTP/HTTPS
        if self.http:
            alive = [p for p in self.http if self._available(p, now)]
            if alive:
                p = self._weighted_choice(alive)
                pair = await self._get_or_create(p, False)
                if pair:
                    sess, _ = pair
                    return (sess, p, False, p)

        return None

    def _bump_score(self, p: str, good: bool):
        cur = self._score.get(p, 0.0) * self.score_decay
        if good:
            cur += 1.0
        else:
            cur -= 1.0
        self._score[p] = max(-10.0, min(50.0, cur))

    def good(self, proxy_key: Optional[str]):
        if not proxy_key:
            return
        self._fails[proxy_key] = 0
        self._bump_score(proxy_key, True)

    def bad(self, proxy_key: Optional[str], reason: str = "err"):
        if not proxy_key:
            return
        c = self._fails.get(proxy_key, 0) + 1
        self._fails[proxy_key] = c
        self._bump_score(proxy_key, False)
        if c >= self.fail_limit:
            now = _now()
            until = self._cool_until.get(proxy_key, 0.0)
            # если уже в cooldown — отправляем в карантин
            if now < until + 1:
                self._quar_until[proxy_key] = now + self.quarantine
            else:
                self._cool_until[proxy_key] = now + self.cooldown
            self._fails[proxy_key] = 0

    async def close(self):
        for p, (sess, _) in list(self._sessions.items()):
            try:
                await sess.close()
            except Exception:
                pass
        self._sessions.clear()

    # Диагностика
    def dump_state(self) -> dict:
        now = _now()
        return {
            "http": len(self.http),
            "socks": len(self.socks),
            "cooling": {k: int(v - now) for k, v in self._cool_until.items() if v > now},
            "quarantine": {k: int(v - now) for k, v in self._quar_until.items() if v > now},
            "fails": dict(self._fails),
            "score": dict(self._score),
        }


# ===== BanBrain (EWMA + профиль по часу суток) =====
class UltraBanBrain:
    def __init__(self, log_file: str):
        self.log_file = log_file
        self.last_success: Optional[float] = None
        self.last_429_start: Optional[float] = None
        # EWMA параметры
        self.alpha = 0.3
        self.ewma_ok: Optional[float] = None  # сред. «жизнь без бана»
        self.ewma_ban: Optional[float] = None  # сред. длительность бана
        # профили по часу суток
        self.ok_by_hour = [0.0] * 24
        self.ok_cnt_hour = [0] * 24
        self.ban_by_hour = [0.0] * 24
        self.ban_cnt_hour = [0] * 24
        # статистика
        self.ok_intervals: List[Tuple[float, float, float]] = []
        self.ban_intervals: List[Tuple[float, float, float]] = []

    def _hour(self, ts: float) -> int:
        try:
            return int(time.localtime(ts).tm_hour) % 24
        except Exception:
            return 0

    def on_429(self, now: float):
        if self.last_429_start is None:
            # фиксируем предыдущий «OK» интервал
            if self.last_success is not None and now > self.last_success:
                ok_dur = now - self.last_success
                self.ok_intervals.append((self.last_success, now, ok_dur))
                # EWMA
                self.ewma_ok = ok_dur if self.ewma_ok is None else (self.alpha * ok_dur + (1 - self.alpha) * self.ewma_ok)
                h = self._hour(now)
                self.ok_by_hour[h] += ok_dur
                self.ok_cnt_hour[h] += 1
            self.last_429_start = now

    def on_200(self, now: float):
        self.last_success = now
        if self.last_429_start is not None and now > self.last_429_start:
            ban_dur = now - self.last_429_start
            self.ban_intervals.append((self.last_429_start, now, ban_dur))
            self.ewma_ban = ban_dur if self.ewma_ban is None else (self.alpha * ban_dur + (1 - self.alpha) * self.ewma_ban)
            h = self._hour(now)
            self.ban_by_hour[h] += ban_dur
            self.ban_cnt_hour[h] += 1
            _append_jsonl(self.log_file, {
                "ban_start": self.last_429_start,
                "ban_end": now,
                "ban_duration": ban_dur,
                "ts": now
            })
            self.last_429_start = None

    def suggest_interval(self, current: float) -> float:
        base = current
        if self.ewma_ok:
            base = max(RATE_MIN_INTERVAL_SEC, min(RATE_MAX_INTERVAL_SEC, 0.7 * self.ewma_ok))
        h = self._hour(_now())
        mult = 1.0
        if self.ok_cnt_hour[h] > 0:
            avg_ok_h = self.ok_by_hour[h] / max(1, self.ok_cnt_hour[h])
            if self.ewma_ok and avg_ok_h > self.ewma_ok:
                mult = 0.9
            else:
                mult = 1.1
        return max(RATE_MIN_INTERVAL_SEC, min(RATE_MAX_INTERVAL_SEC, base * mult))


# ===== RateLimiter (per-URL token bucket) =====
class RateLimiter:
    def __init__(self, capacity: int, refill_sec: int):
        self.capacity = int(capacity)
        self.refill_sec = int(refill_sec)
        self.tokens: Dict[str, Tuple[float, float]] = {}  # key -> (tokens, last_ts)

    def allow(self, key: str) -> bool:
        now = _now()
        tokens, last = self.tokens.get(key, (float(self.capacity), now))
        if now > last:
            add = (now - last) / self.refill_sec
            tokens = min(self.capacity, tokens + add)
        if tokens >= 1.0:
            tokens -= 1.0
            self.tokens[key] = (tokens, now)
            return True
        self.tokens[key] = (tokens, now)
        return False


# ===== HeadlessRefresher (playwright) =====
class HeadlessRefresher:
    def __init__(self, period_sec: int, urls: List[str]):
        self.period_sec = int(period_sec)
        self.urls = list(urls or [])
        self.next_ts = 0.0
        self.available = False
        try:
            import playwright  # noqa: F401
            self.available = True
        except Exception:
            self.available = False

    async def refresh(self):
        if not self.available or not self.urls:
            return None
        now = _now()
        if now < self.next_ts:
            return None
        self.next_ts = now + self.period_sec
        try:
            from playwright.async_api import async_playwright  # type: ignore
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()
                for u in self.urls:
                    await page.goto(u, wait_until="domcontentloaded", timeout=25000)
                    await asyncio.sleep(1.0)
                cookies = await context.cookies()
                await context.close()
                await browser.close()
                return cookies
        except Exception:
            return None


# ===== patch_watcher_ultra =====
def patch_watcher_ultra(WatcherCls):
    """Модифицирует Watcher: добавляет анти-429 логику, прокси, rate-limit, headless и т.п."""
    orig_init = WatcherCls.__init__

    def __init__(self, *args, **kwargs):
        orig_init(self, *args, **kwargs)
        self.fp = Fingerprinter()
        self.brain = UltraBanBrain(BAN_LOG_FILE)
        self.proxy = ProxyOrchestrator(
            PROXY_LIST,
            SOCKS_PROXY_LIST,
            cooldown=PROXY_COOLDOWN_SEC,
            quarantine=PROXY_QUARANTINE_SEC,
            fail_limit=PROXY_FAIL_LIMIT,
            score_decay=PROXY_SCORE_DECAY,
        )
        self.ratelimiter = RateLimiter(RATE_TOKEN_BUCKET, RATE_REFILL_SEC)
        self.cooldown_until = getattr(self, "cooldown_until", 0.0)
        self._interval = float(getattr(self, "_interval", 60.0))
        self.last_success = getattr(self, "last_success", None)
        self._req_seq = 0
        self.headless = HeadlessRefresher(HEADLESS_PERIOD_SEC, HEADLESS_URLS) if HEADLESS_REFRESH else None

    WatcherCls.__init__ = __init__

    # Заголовки
    def _headers(self) -> dict:
        return self.fp.headers()

    setattr(WatcherCls, "_headers", _headers)

    # Счётчик банов за окно
    def _bans_in_window(self, now: float, window_sec: int = BAN_WINDOW_SEC) -> int:
        return sum(1 for _, end, _ in self.brain.ban_intervals if (now - end) <= window_sec)

    setattr(WatcherCls, "_bans_in_window", _bans_in_window)

    # Глубокий cooldown, если слишком много банов
    def _maybe_enter_cooldown(self, now: float):
        if self._bans_in_window(now) >= MAX_BANS_PER_WINDOW:
            self.cooldown_until = now + HARD_PAUSE_SEC
            self.fp.rotate()

    setattr(WatcherCls, "_maybe_enter_cooldown", _maybe_enter_cooldown)

    # Лог запроса
    def _log_req(self, status: int, proxy_key: Optional[str], extra: dict | None = None):
        self._req_seq += 1
        rec = {
            "ts": _now(),
            "seq": self._req_seq,
            "url": getattr(self, "url", ""),
            "status": status,
            "interval": float(getattr(self, "_interval", 0.0)),
            "proxy": proxy_key,
        }
        if extra:
            rec.update(extra)
        _append_jsonl(REQUEST_LOG_FILE, rec)

    setattr(WatcherCls, "_log_req", _log_req)

    # _ensure_session на всякий случай, если его нет в исходном классе
    async def _ensure_session_fallback(self):
        try:
            import aiohttp
            jar = aiohttp.CookieJar()
            timeout = aiohttp.ClientTimeout(total=30, connect=10)
            return aiohttp.ClientSession(cookie_jar=jar, timeout=timeout, trust_env=False)
        except Exception:
            return None

    if not hasattr(WatcherCls, "_ensure_session"):
        setattr(WatcherCls, "_ensure_session", _ensure_session_fallback)

    # ===== собственно _fetch =====
    async def _fetch(self):
        now = _now()
        # deep cooldown
        if self.cooldown_until > now:
            await asyncio.sleep(min(60.0, self.cooldown_until - now))

        # per-URL rate limit
        key = getattr(self, "search_key", getattr(self, "url", "default"))
        while not self.ratelimiter.allow(str(key)):
            await asyncio.sleep(1.0)

        # headless-подогрев cookie (если включён)
        if self.headless is not None:
            try:
                _ = await self.headless.refresh()
            except Exception:
                pass  # cookieJar из playwright сюда не вливаем (разные форматы)

        headers = self._headers()

        # Сессия/прокси
        sess_info = await self.proxy.get()
        if sess_info:
            session, proxy_for_req, _is_socks, proxy_key = sess_info
        else:
            session = await self._ensure_session()
            proxy_for_req, _is_socks, proxy_key = None, False, None
            if session is None:
                # попытка через запасной конструктор
                session = await _ensure_session_fallback(self)

        max_attempts = 5
        for attempt in range(max_attempts):
            req = {"headers": headers}
            if proxy_for_req:
                req["proxy"] = proxy_for_req
            try:
                async with session.get(self.url, **req) as r:  # type: ignore[arg-type]
                    now = _now()
                    status = r.status

                    if status == 429:
                        self.brain.on_429(now)
                        self.proxy.bad(proxy_key, reason="429")
                        ra = r.headers.get("Retry-After")
                        wait = float(ra) if ra else min(60.0 * (2 ** attempt), 300.0)
                        wait = _jitter(wait)
                        # тюним интервал
                        self._interval = max(self._interval, min(wait, RATE_MAX_INTERVAL_SEC))
                        self._maybe_enter_cooldown(now)
                        self._interval = self.brain.suggest_interval(self._interval)
                        self._log_req(status, proxy_key, {"wait": wait})
                        await asyncio.sleep(wait)
                        continue

                    if status == 200:
                        txt = await r.text()
                        self.proxy.good(proxy_key)
                        self.brain.on_200(now)
                        self.last_success = now
                        self._interval = self.brain.suggest_interval(self._interval)
                        self._log_req(status, proxy_key)
                        return txt

                    if status in (403, 503):
                        self.proxy.bad(proxy_key, reason=str(status))
                        wait = _jitter(min(10.0 * (2 ** attempt), 180.0))
                        self._interval = max(self._interval, wait)
                        self._log_req(status, proxy_key, {"wait": wait})
                        await asyncio.sleep(wait)
                        continue

                    # другие статусы — просто лог и выход
                    self._log_req(status, proxy_key)
                    return None

            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.proxy.bad(proxy_key, reason="net")
                wait = _jitter(2 + attempt)
                self._log_req(-1, proxy_key, {"error": str(e), "wait": wait})
                await asyncio.sleep(wait)

        return None

    WatcherCls._fetch = _fetch

    # Закрытие: гасим сессии прокси
    orig_stop = WatcherCls.stop if hasattr(WatcherCls, "stop") else None

    async def stop(self):
        try:
            if getattr(self, "proxy", None):
                await self.proxy.close()
        finally:
            if orig_stop:
                await orig_stop(self)

    WatcherCls.stop = stop

    return WatcherCls


# ===== extend_app_ultra =====
def extend_app_ultra(app: Any):
    """
    Добавляет команды:
    - /banstats — сводка банов/интервалов
    - /proxystats — состояние оркестратора прокси
    - /forcerotate — смена UA и вход в cooldown для всех вотчеров (panic button)
    - /headlesstouch — форсировать headless-подогрев (если включен)

    И «тихие» хендлеры активности пользователей.
    """
    from aiogram import types
    from aiogram.filters import Command
    import html as _html
    import time as _time

    dp = app.dp

    def _is_admin(user_id: int) -> bool:
        adm = os.getenv("ADMIN_CHAT_ID")
        return bool(adm and adm.lstrip("-").isdigit() and int(adm) == int(user_id))

    @dp.message(Command("banstats"))
    async def banstats_cmd(m: types.Message):
        if not _is_admin(m.chat.id):
            await m.reply("Команда доступна только админу.")
            return
        lines = ["<b>ULTRA Баны</b>"]
        for key, w in getattr(app.manager, "watchers", {}).items():
            brain = getattr(w, "brain", None)
            if not brain:
                continue
            ok_cnt = len(brain.ok_intervals)
            ban_cnt = len(brain.ban_intervals)
            avg_ok = (sum(d for _, _, d in brain.ok_intervals[-10:]) / max(1, min(10, ok_cnt))) if ok_cnt else 0.0
            avg_ban = (sum(d for _, _, d in brain.ban_intervals[-10:]) / max(1, min(10, ban_cnt))) if ban_cnt else 0.0
            state = "⏸ cooldown" if _time.time() < float(getattr(w, "cooldown_until", 0.0)) else "▶️ active"
            lines.append(
                f"• {_html.escape(str(key))[:60]}… — {state}, interval={float(getattr(w,'_interval',0)):.1f}s, "
                f"avg_ok={avg_ok:.1f}s, avg_ban={avg_ban:.1f}s (ok={ok_cnt}, ban={ban_cnt})"
            )
        await m.reply("\n".join(lines), disable_web_page_preview=True)

    @dp.message(Command("proxystats"))
    async def proxystats_cmd(m: types.Message):
        if not _is_admin(m.chat.id):
            await m.reply("Команда доступна только админу.")
            return
        lines = ["<b>ULTRA Прокси</b>"]
        for key, w in getattr(app.manager, "watchers", {}).items():
            px = getattr(w, "proxy", None)
            if not px:
                continue
            st = px.dump_state()
            lines.append(f"• {_html.escape(str(key))[:60]}… http={st['http']} socks={st['socks']}")
            lines.append(f"  cooling={len(st['cooling'])}, quarantine={len(st['quarantine'])}, fails={len(st['fails'])}")
        await m.reply("\n".join(lines))

    @dp.message(Command("forcerotate"))
    async def forcerotate_cmd(m: types.Message):
        if not _is_admin(m.chat.id):
            await m.reply("Команда доступна только админу.")
            return
        for _, w in getattr(app.manager, "watchers", {}).items():
            try:
                w.fp.rotate()
                w.cooldown_until = _time.time() + 300  # 5 минут
            except Exception:
                pass
        await m.reply("Форс-ротация UA и 5-минутный cooldown применены.")

    @dp.message(Command("headlesstouch"))
    async def headlesstouch_cmd(m: types.Message):
        if not _is_admin(m.chat.id):
            await m.reply("Команда доступна только админу.")
            return
        done = 0
        for _, w in getattr(app.manager, "watchers", {}).items():
            hd = getattr(w, "headless", None)
            if hd:
                try:
                    res = await hd.refresh()
                    if res is not None:
                        done += 1
                except Exception:
                    pass
        await m.reply(f"Headless touch выполнен для {done} вотчеров.")

    # Тихие трекеры активности/аккаунтов
    @dp.message()
    async def _touch_all_msgs(m: types.Message):
        try:
            app.account_register_if_needed(m.chat.id)
            app.account_update_profile(m.from_user)
            app.account_touch(m.chat.id)
            bind = app.get_alert_chat_id(m.chat.id)
            if bind:
                app.account_set_binding(m.chat.id, bind)
        except Exception:
            pass

    @dp.callback_query()
    async def _touch_all_cbq(cq: types.CallbackQuery):
        try:
            uid = cq.from_user.id
            app.account_register_if_needed(uid)
            app.account_update_profile(cq.from_user)
            app.account_touch(uid)
            bind = app.get_alert_chat_id(uid)
            if bind:
                app.account_set_binding(uid, bind)
        except Exception:
            pass
