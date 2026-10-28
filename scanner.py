#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
                    SCANNER — модули сбора данных Rust PC Checker
================================================================================

Что изменено относительно предыдущей версии и почему:

  1. БРАУЗЕРЫ: раньше в отчёт попадала ПОЛНАЯ история посещений за 7 дней —
     вообще все сайты и поисковые запросы. Теперь в отчёт попадают только
     записи, совпавшие с базой доменов чит-площадок (cheat_db.json ->
     cheat_site_domains) или содержащие в заголовке страницы / URL
     ключевые слова из базы читов. Остальная история даже не покидает
     переменные процесса — не копируется в отчёт.

  2. STEAM: раньше собирались ещё и .maFile — это файлы Steam Guard
     Mobile Authenticator, фактически ключи от аккаунта. Их кража — обычный
     способ угона Steam-аккаунтов. Теперь .maFile не ищутся и не упоминаются.
     Остаются только SteamID64/имя/время последнего входа — этого достаточно
     для проверки банов и принадлежности аккаунта, без доступа к самим ключам.

  3. Все остальные модули (USN, Prefetch, BAM, Amcache, процессы, автозагрузка,
     сеть, антивирусы, Event Log) оставлены по той же логике, что и раньше —
     они и так работают через сопоставление со стоп-словами/аномалиями,
     а не через сплошной сбор. Названия читов/спуферов теперь подтягиваются
     из cheat_db.json, а не зашиты в этот файл — так базу проще расширять.

Каждый scan_* модуль явно описывает в докстринге, какие именно данные он
читает — это то, что должно показываться игроку на экране согласия перед
стартом сканирования (см. CONSENT_ITEMS в gui.py).
================================================================================
"""

import csv
import ctypes
import ctypes.wintypes  # нужно отдельным импортом — `import ctypes` не подтягивает это подмодуль
import fnmatch
import hashlib
import io
import os
import platform
import re
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import winreg
import datetime as dt
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs
import xml.etree.ElementTree as ET

from cheat_db import load_cheat_db

# ============================================================================
# КОНФИГУРАЦИЯ
# ============================================================================

SEVEN_DAYS_SEC = 7 * 24 * 3600
THREE_DAYS_SEC = 3 * 24 * 3600

EXECUTABLE_EXTS = {'.exe', '.sys', '.dll', '.bat', '.cmd', '.ps1', '.vbs'}

SUSPICIOUS_PATHS = [
    r'\temp\\', r'\tmp\\', r'\appdata\\', r'\downloads\\', r'\public\\',
    r'\users\\public\\', r'\programdata\\', r'\windows\\temp\\',
]

PREFETCH_DIR = r'C:\Windows\Prefetch'
BAM_PATH = r'SYSTEM\CurrentControlSet\Services\bam\UserSettings'
AMCACHE_PATH = r'C:\Windows\AppCompat\Programs\Amcache.hve'
AMCACHE_TEMP_HIVE = 'RUSTCHK_AMCACHE'

TARGET_DIRS = [
    os.environ.get('TEMP', ''),
    os.environ.get('APPDATA', ''),
    os.environ.get('LOCALAPPDATA', ''),
    r'C:\Windows\System32\drivers',
    r'C:\Windows\Temp',
    os.path.expanduser('~\\Downloads'),
]

STEAM_CONFIG_PATHS = [
    r'C:\Program Files (x86)\Steam\config',
    r'C:\Program Files\Steam\config',
]

BROWSERS_CHROMIUM = {
    'Chrome':  ('Google', 'Chrome', 'User Data'),
    'Edge':    ('Microsoft', 'Edge', 'User Data'),
    'Yandex':  ('Yandex', 'YandexBrowser', 'User Data'),
    'Opera':   ('Opera Software', 'Opera Stable'),
    'Brave':   ('BraveSoftware', 'Brave-Browser', 'User Data'),
    'Vivaldi': ('Vivaldi', 'User Data'),
}

AUTORUN_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
]

TARGET_EVENTS = {
    7045: "NEW_SERVICE",
    4697: "NEW_SERVICE_ALT",
    1102: "LOG_CLEARED",
    1000: "APP_CRASH",
    1001: "APP_CRASH_BUGCHECK",
}
LOG_NAMES = ['System', 'Security', 'Application']

EXEC_RE = re.compile(r'\.(exe|sys|dll|bat|cmd|ps1|vbs)$', re.IGNORECASE)
COL_FILENAME = 1
COL_REASON = 3
COL_TIMESTAMP = 4
REASON_CREATE = 0x00000001
REASON_DELETE = 0x00000002

# ============================================================================
# КОНСТАНТЫ ДЛЯ ПРОДВИНУТОГО USN-АНАЛИЗА (из внешнего скрипта)
# ============================================================================

# Перевод причин USN на русский
REASON_TRANSLATIONS = {
    "Data overwrite": "Перезапись",
    "Data extend": "Запись",
    "Data truncation": "Очистка",
    "Named data extend": "СКАЧАНО ИЗ СЕТИ (ADS)",
    "File create": "СОЗДАНИЕ",
    "File delete": "УДАЛЕНИЕ (ЗАЧИСТКА)",
    "Rename old name": "Старое имя",
    "Rename new name": "ПЕРЕИМЕНОВАНИЕ",
    "Rename: old name": "Старое имя",
    "Rename: new name": "ПЕРЕИМЕНОВАНИЕ",
    "Close": "Закрыт",
}

# Расширенные расширения для поиска (больше, чем EXECUTABLE_EXTS)
USN_CHEAT_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".asi", ".msi",
    ".lua", ".ahk", ".amc", ".mgn", ".macro", ".py", ".bat", ".cmd", ".ps1", ".vbs",
    ".zip", ".rar", ".7z",
    ".crdownload", ".part", ".opdownload",
    ".pf",
}

# Дополнительные подозрительные ключевые слова (объединяются с cheat_db.json)
USN_SUSPICIOUS_KEYWORDS = (
    "cheat", "hack", "aimbot", "esp", "wallhack", "triggerbot", "bhop",
    "inject", "loader", "xenos", "extreme", "processhacker", "cheatengine",
    "bypass", "spoofer", "hwid", "kdmapper", "drvmap", "cleaner",
    "recoil", "norecoil", "macro", "bloody", "oscar", "autoclick",
    "alkad", "ring1", "phoenix", "mason", "collapse", "evilcheat",
    "quantum", "disconnect", "monolith", "divine", "fluent",
    "satano", "fecurity", "byster", "chams", "debugcamera", "exloader",
)

# Пути, которые считаются шумом (системные обновления, кэши и т.д.)
USN_NOISE_PATH_PARTS = (
    "\\program files\\",
    "\\program files (x86)\\",
    "\\programdata\\",
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
    "\\windows\\servicing\\",
    "\\windows\\softwaredistribution\\",
    "\\microsoft.net\\",
    "\\windows defender\\",
    "\\appdata\\local\\nvidia corporation\\",
    "\\appdata\\local\\nvidia\\",
    "\\appdata\\local\\microsoft\\",
    "\\appdata\\local\\google\\chrome\\",
    "\\appdata\\local\\yandex\\",
    "\\appdata\\local\\bravesoftware\\",
    "\\appdata\\roaming\\opera software\\",
    "\\appdata\\roaming\\code\\",
    "\\appdata\\local\\programs\\microsoft vs code\\",
    "\\appdata\\local\\discord\\app-",
    "\\appdata\\local\\steam\\htmlcache\\",
    "\\appdata\\local\\package cache\\",
)

# Безопасные файлы (никогда не помечаем как подозрительные)
USN_SAFE_EXACT_FILES = {
    "mpengine.dll", "vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll",
    "concrt140.dll", "vccorlib140.dll", "ucrtbase.dll", "d3dcompiler_47.dll",
    "libcrypto-3.dll", "libssl-3.dll", "libffi-8.dll", "hidapi.dll",
    "base_library.zip", "pythonrc.py", "common.lua", "current_game.lua",
    "oawrapper.exe", "nvoawrappercache.exe", "ontology64.dll",
    "msedge.exe", "msedge.dll", "msedge.7z", "msedge.hollow.7z", "msedge.rebuilt.7z",
    "msedgewebview2.exe", "msedge_proxy.exe", "pwahelper.exe", "copilotapp.exe",
    "mscopilot.exe", "copilot_setup.exe", "old_platform_experiences_helper.exe",
    "new_platform_experiences_helper.exe", "platform_experiences_helper.exe",
}

# Безопасные Prefetch-префиксы (системные программы)
USN_SAFE_PREFETCH_PREFIXES = (
    "SVCHOST.EXE", "CONHOST.EXE", "CMD.EXE", "POWERSHELL.EXE", "FSUTIL.EXE",
    "PYTHON.EXE", "CHROME.EXE", "MSSEDGE.EXE", "EXPLORER.EXE", "SEARCHPROTOCOLHOST.EXE",
    "BACKGROUNDTASKHOST.EXE", "RUNTIMEBROKER.EXE", "TASKMGR.EXE", "DLLHOST.EXE",
    "WMIPRVSE.EXE", "CONSENT.EXE", "AUDIODG.EXE", "SPPSVC.EXE", "SC.EXE",
    "STEAM.EXE", "STEAMWEBHELPER.EXE", "DISCORD.EXE", "CODE.EXE", "MSEDGEWEBVIEW2.EXE",
)

# Целевые события для группировки с Close
USN_TARGET_EVENTS = {"File create", "File delete", "Rename new name", "Rename: new name"}

# Кэш для ParentID → путь (ускоряет повторные запросы)
_PARENT_PATH_CACHE: dict = {}

# ============================================================================
# БАЗА ЧИТОВ (загружается один раз из cheat_db.json)
# ============================================================================

_DB = load_cheat_db()
ALL_STOPWORDS = _DB["cheat_names"] + _DB["hwid_spoofer_names"]
CHEAT_SITE_DOMAINS = _DB["cheat_site_domains"]
CHEAT_SITE_URL_FRAGMENTS = _DB["cheat_site_url_fragments"]
DLC_KEYWORDS = set(_DB["dlc_keywords"])

_CHEAT_TITLE_RE = re.compile(
    r'\b(' + '|'.join(re.escape(w) for w in [
        'чит', 'софт', 'макрос', 'cheat', 'hack', 'soft', 'macro', 'aimbot',
        'wallhack', 'esp', 'spoofer',
    ]) + r')\b', re.IGNORECASE
)

# Сравнение стоп-слов — ТОЛЬКО по границам слов, не как "подстрока где угодно".
# Без этого короткое слово вроде "cyber" ловило бы cyberforum.ru, "radiance" —
# любую страницу про освещение/косметику и т.д. \b в regex не считает границей
# переход между двумя буквами/цифрами, поэтому "cyber" не совпадёт внутри
# "cyberforum", но совпадёт как отдельное слово/сегмент пути.
# Каждое стоп-слово компилируется один раз при старте — сравнение всё ещё быстрое.
_STOPWORD_PATTERNS: List[Tuple[str, "re.Pattern"]] = [
    (w, re.compile(r'(?<![a-zа-я0-9])' + re.escape(w) + r'(?![a-zа-я0-9])', re.IGNORECASE))
    for w in ALL_STOPWORDS
]

# ============================================================================
# WHITELIST
# ============================================================================

WHITELIST_PATHS: List[str] = []
WHITELIST_NAMES: List[str] = []
WHITELIST_DOMAINS: List[str] = []


def _app_dir() -> str:
    meipass = getattr(sys, "_MEIPASS", None)
    return meipass if meipass else os.path.dirname(os.path.abspath(__file__))


def load_whitelist() -> None:
    """Загружает whitelist.txt (пути/имена/домены, которые НЕ считаются подозрительными)."""
    global WHITELIST_PATHS, WHITELIST_NAMES, WHITELIST_DOMAINS

    candidates = [os.path.join(_app_dir(), 'whitelist.txt'), os.path.join(os.getcwd(), 'whitelist.txt')]
    wl_path = next((p for p in candidates if os.path.isfile(p)), None)
    if not wl_path:
        return

    section = None
    try:
        with open(wl_path, 'r', encoding='utf-8') as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith('#'):
                    if 'ПУТИ ФАЙЛОВ' in line:
                        section = 'path'
                    elif 'ИМЕНА ФАЙЛОВ' in line:
                        section = 'name'
                    elif 'ДОМЕНЫ' in line or 'КЛЮЧЕВЫЕ' in line:
                        section = 'domain'
                    continue
                if section == 'path':
                    WHITELIST_PATHS.append(line.lower())
                elif section == 'name':
                    WHITELIST_NAMES.append(line.lower())
                elif section == 'domain':
                    WHITELIST_DOMAINS.append(line.lower())
    except Exception:
        pass


def is_path_whitelisted(path: str) -> bool:
    if not WHITELIST_PATHS:
        return False
    p = path.lower().replace('/', '\\')
    return any(fnmatch.fnmatch(p, pat) for pat in WHITELIST_PATHS)


def is_name_whitelisted(name: str) -> bool:
    return bool(WHITELIST_NAMES) and name.lower() in WHITELIST_NAMES


def is_domain_whitelisted(url: str) -> bool:
    if not WHITELIST_DOMAINS:
        return False
    try:
        host = (urlparse(url).hostname or '').lower()
    except Exception:
        host = ''
    if host and any(fnmatch.fnmatch(host, pat) for pat in WHITELIST_DOMAINS):
        return True
    url_l = url.lower()
    return any('/' in pat and pat in url_l for pat in WHITELIST_DOMAINS)


# ============================================================================
# REPORT BUFFER
# ============================================================================

class ReportBuffer:
    """Собирает текстовый отчёт из событий всех модулей."""

    def __init__(self) -> None:
        self.lines: List[str] = []
        self.start_time = dt.datetime.now()
        self.stats: Dict[str, int] = defaultdict(int)
        self._write_header()

    def _write_header(self) -> None:
        try:
            hostname = socket.gethostname()
        except Exception:
            hostname = "unknown"
        try:
            username = os.getlogin()
        except Exception:
            username = os.environ.get('USERNAME', 'unknown')

        self.lines.append("=" * 70)
        self.lines.append("RUST PC CHECK REPORT v4.0")
        self.lines.append("=" * 70)
        self.lines.append(f"Generated: {self.start_time:%Y-%m-%d %H:%M:%S}")
        self.lines.append(f"Hostname: {hostname}")
        self.lines.append(f"User: {username}")
        self.lines.append(f"OS: {_detect_windows_version()}")
        self.lines.append("=" * 70)

    def section(self, title: str) -> None:
        self.lines.append("")
        self.lines.append(f"--- {title.upper()} ---")

    def event(self, trigger: str, description: str, timestamp: Optional[dt.datetime] = None) -> None:
        ts = timestamp or dt.datetime.now()
        self.lines.append(f"[{ts:%Y-%m-%d %H:%M:%S}] [{trigger}] {description}")
        self.stats[trigger] += 1

    def info(self, description: str) -> None:
        self.lines.append(f"[INFO] {description}")

    def warning(self, description: str) -> None:
        self.lines.append(f"[WARNING] {description}")

    def get_text(self) -> str:
        return "\n".join(self.lines)

    def get_stats(self) -> Dict[str, int]:
        return dict(self.stats)


# ============================================================================
# УТИЛИТЫ
# ============================================================================

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _detect_windows_version() -> str:
    """
    platform.release()/platform.version() на Windows 11 до сих пор возвращают
    "10" — Microsoft не обновила эти старые API, они определяют версию по
    номеру major, а не по сборке. Правильный способ — смотреть build number:
    >= 22000 значит Windows 11, независимо от того, что говорит platform.*.
    """
    try:
        ver = sys.getwindowsversion()
        build = ver.build
        major_name = "Windows 11" if build >= 22000 else "Windows 10"
        return f"{major_name} (build {build}, {platform.version()})"
    except Exception:
        try:
            return f"{platform.system()} {platform.release()} ({platform.version()})"
        except Exception:
            return "Windows (версия не определена)"


# ============================================================================
# ПРИВИЛЕГИИ (SeBackup/SeRestorePrivilege — нужны для LoadKey на Amcache.hve)
# ============================================================================
#
# ВАЖНО: все WinAPI-функции ниже объявлены с явными argtypes/restype.
# Без этого ctypes по умолчанию трактует возврат/аргументы как 32-битный
# int — на 64-битном Python это может незаметно обрезать HANDLE (указатель),
# из-за чего OpenProcessToken получает мусор вместо хендла процесса и тихо
# падает. Именно это и было причиной, почему привилегия не включалась в
# предыдущей версии, хотя код ошибки не показывал прямой причины.

try:
    _advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
    _kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    # BOOL в Win32 — это `typedef int BOOL` (4 байта), а НЕ C99 _Bool (1 байт).
    # ctypes.c_bool здесь технически неверный ABI-тип: на практике почти
    # всегда "прокатывает", т.к. эти функции возвращают ровно 0/1 в младшем
    # байте, но это везение, а не гарантия — используем ctypes.wintypes.BOOL
    # (алиас c_long), который соответствует реальному размеру.
    _BOOL = ctypes.wintypes.BOOL

    _kernel32.GetCurrentProcess.argtypes = []
    _kernel32.GetCurrentProcess.restype = ctypes.c_void_p

    _kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    _kernel32.CloseHandle.restype = _BOOL

    _advapi32.OpenProcessToken.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p),
    ]
    _advapi32.OpenProcessToken.restype = _BOOL

    _advapi32.LookupPrivilegeValueW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p,
    ]
    _advapi32.LookupPrivilegeValueW.restype = _BOOL

    _advapi32.AdjustTokenPrivileges.argtypes = [
        ctypes.c_void_p, _BOOL, ctypes.c_void_p,
        ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p,
    ]
    _advapi32.AdjustTokenPrivileges.restype = _BOOL

    class _LUID(ctypes.Structure):
        _fields_ = [("LowPart", ctypes.c_uint32), ("HighPart", ctypes.c_int32)]

    class _LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", _LUID), ("Attributes", ctypes.c_uint32)]

    class _TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", ctypes.c_uint32), ("Privileges", _LUID_AND_ATTRIBUTES * 1)]

    _PRIVILEGE_API_READY = True
except (ImportError, AttributeError, OSError):
    _PRIVILEGE_API_READY = False


def _enable_privileges() -> bool:
    """
    Включает SeBackupPrivilege и SeRestorePrivilege для текущего процесса.

    Это СТАНДАРТНЫЙ Windows API, антивирусы его не триггерят. Быть
    администратором недостаточно — у админского токена эти привилегии
    ЕСТЬ, но выключены по умолчанию, и Windows отказывает LoadKey с
    [WinError 1314], пока их явно не включишь через AdjustTokenPrivileges.
    Нужно независимо от источника файла (живой Amcache.hve или копия
    через VSS) — привилегия требуется самим API LoadKey.

    Returns:
        bool: True, если ОБЕ привилегии включены успешно.
    """
    if not _PRIVILEGE_API_READY:
        return False

    TOKEN_ADJUST_PRIVILEGES = 0x0020
    TOKEN_QUERY = 0x0008
    SE_PRIVILEGE_ENABLED = 0x00000002

    h_process = _kernel32.GetCurrentProcess()
    h_token = ctypes.c_void_p()
    if not _advapi32.OpenProcessToken(
        h_process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(h_token)
    ):
        return False

    try:
        enabled_count = 0
        for priv_name in ("SeBackupPrivilege", "SeRestorePrivilege"):
            luid = _LUID()
            if not _advapi32.LookupPrivilegeValueW(None, priv_name, ctypes.byref(luid)):
                continue

            tp = _TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

            ctypes.set_last_error(0)
            if _advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp), 0, None, None):
                # AdjustTokenPrivileges может вернуть True, но ничего не изменить —
                # проверяем реальный код ошибки (ERROR_NOT_ALL_ASSIGNED = 1300).
                if ctypes.get_last_error() == 0:
                    enabled_count += 1

        return enabled_count == 2
    finally:
        _kernel32.CloseHandle(h_token)


# ============================================================================
# VSS (теневая копия тома) — обход блокировки файла (НЕ привилегий)
# ============================================================================
#
# Отдельная от привилегий причина отказа: Amcache.hve/другие системные файлы
# могут быть заняты другим процессом (sharing violation, WinError 32). VSS
# создаёт согласованный снимок тома на уровне файловой системы, с которого
# можно скопировать файл, даже если его "живая" версия заблокирована. Это
# НЕ отменяет требование SeRestorePrivilege для самого LoadKey — обе причины
# отказа независимы и обе должны быть устранены.

def _create_vss_snapshot(volume: str = "C:") -> Optional[Tuple[str, str]]:
    """Создаёт теневую копию тома через WMI/PowerShell. Возвращает (shadow_id, device_path) или None."""
    script = (
        f"$r = (Get-WmiObject -List Win32_ShadowCopy).Create('{volume}\\', 'ClientAccessible'); "
        "if ($r.ReturnValue -ne 0) { exit 1 }; "
        "$sc = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $r.ShadowID }; "
        "Write-Output \"$($sc.ID)|$($sc.DeviceObject)\""
    )
    out = _run_powershell(script, timeout=60)
    if not out or '|' not in out:
        return None
    shadow_id, device_path = out.strip().split('|', 1)
    if not shadow_id or not device_path:
        return None
    return shadow_id, device_path


def _delete_vss_snapshot(shadow_id: str) -> None:
    """Удаляет теневую копию по её ID. Вызывать всегда после использования — иначе копии копятся на диске."""
    script = (
        f"$sc = Get-WmiObject Win32_ShadowCopy | Where-Object {{ $_.ID -eq '{shadow_id}' }}; "
        "if ($sc) { $sc.Delete() }"
    )
    _run_powershell(script, timeout=30)


def _copy_file_via_vss(relative_path: str, volume: str = "C:") -> Optional[str]:
    """
    Копирует файл (например, r'\\Windows\\AppCompat\\Programs\\Amcache.hve')
    через теневую копию тома — даже если "живой" файл заблокирован другим
    процессом. Возвращает путь к временной копии или None при неудаче.
    Теневая копия всегда удаляется после копирования (успешного или нет).
    """
    snapshot = _create_vss_snapshot(volume)
    if snapshot is None:
        return None
    shadow_id, device_path = snapshot

    try:
        source = device_path.rstrip('\\') + '\\' + relative_path.lstrip('\\')
        dest = os.path.join(
            tempfile.gettempdir(),
            f"vss_copy_{os.getpid()}_{int(time.time() * 1000)}_{os.path.basename(relative_path)}",
        )
        try:
            shutil.copy2(source, dest)
            return dest
        except (PermissionError, OSError, FileNotFoundError):
            return None
    finally:
        _delete_vss_snapshot(shadow_id)


def _parse_usn_time(raw: str) -> dt.datetime:
    raw = raw.strip()
    for fmt in ('%d.%m.%Y %H:%M:%S', '%Y-%m-%d %H:%M:%S', '%m/%d/%Y %H:%M:%S', '%d/%m/%Y %H:%M:%S'):
        try:
            return dt.datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return dt.datetime.min


def _filetime_to_dt(ft: int) -> Optional[dt.datetime]:
    try:
        return dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=ft // 10)
    except Exception:
        return None


def _chrome_ts_to_dt(ts_us: int) -> dt.datetime:
    CHROME_EPOCH_OFFSET = 11644473600
    try:
        return dt.datetime.utcfromtimestamp(ts_us / 1_000_000 - CHROME_EPOCH_OFFSET)
    except (OSError, ValueError, OverflowError):
        return dt.datetime.min


def _copy_locked_file(src: str) -> Optional[str]:
    if not os.path.isfile(src):
        return None
    dst = os.path.join(tempfile.gettempdir(), f"copy_{os.getpid()}_{int(time.time()*1000)}_{os.path.basename(src)}")
    try:
        shutil.copy2(src, dst)
        return dst
    except (PermissionError, OSError):
        return None


def _is_random_name(fname: str) -> bool:
    if re.match(r'^\d{5,}\.(exe|sys|dll|bat|cmd|ps1|vbs)$', fname, re.IGNORECASE):
        return True
    if re.match(r'^[a-z0-9]{10,}\.(exe|sys|dll|bat|cmd|ps1|vbs)$', fname, re.IGNORECASE):
        return True
    if re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\.(exe|dll)$', fname, re.IGNORECASE):
        return True
    return False


def _is_suspicious_path(path: str) -> bool:
    p = path.lower().replace('/', '\\')
    return any(s in p for s in SUSPICIOUS_PATHS)


def _check_stop_words(name: str) -> Optional[str]:
    """Ищет стоп-слово как отдельное слово/сегмент (см. _STOPWORD_PATTERNS), а не как
    произвольную подстроку — иначе "cyber" ловил бы "cyberforum" и подобное."""
    for word, pattern in _STOPWORD_PATTERNS:
        if pattern.search(name):
            return word
    return None


def _reg_query(key, name: str) -> Optional[str]:
    try:
        value, _ = winreg.QueryValueEx(key, name)
        return str(value) if value is not None else None
    except (FileNotFoundError, OSError):
        return None


def _get_downloads_path() -> Optional[str]:
    try:
        CSIDL_DOWNLOADS = 0x000D
        buf = ctypes.create_unicode_buffer(260)
        if ctypes.windll.shell32.SHGetFolderPathW(None, CSIDL_DOWNLOADS, None, 0, buf) == 0:
            if buf.value and os.path.isdir(buf.value):
                return buf.value
    except Exception:
        pass
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                              r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
        path, _ = winreg.QueryValueEx(key, "{374DE290-123F-4565-9164-39C4925E467B}")
        winreg.CloseKey(key)
        path = os.path.expandvars(path)
        if path and os.path.isdir(path):
            return path
    except Exception:
        pass
    return None

# ============================================================================
# МОДУЛЬ: НЕСТАНДАРТНЫЕ ДРАЙВЕРЫ (Kernel Forensics)
# ============================================================================
# Сканирует:
#   1. Драйверы, ЗАГРУЖЕННЫЕ В ПАМЯТЬ ЯДРА прямо сейчас (EnumDeviceDrivers)
#   2. Реестр HKLM\SYSTEM\CurrentControlSet\Services\* (службы типа 1 и 2)
#   3. Журнал System (EventID 7045 — установка службы, 6 — старт драйвера)
#   4. Журнал CodeIntegrity (события загрузки неподписанных драйверов)
#
# Фильтрует "шум" — стандартные драйверы из:
#   C:\Windows\System32\drivers\
#   C:\Windows\System32\DriverStore\FileRepository\
#   C:\Windows\SysWOW64\drivers\
#
# Всё остальное = красный флаг (особенно неподписанные драйверы).
# ============================================================================

DRIVERS_PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$results = @{}

$cSharp = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using Microsoft.Win32.SafeHandles;

public class classForensics {
    [DllImport("psapi.dll", SetLastError = true)]
    static extern bool EnumDeviceDrivers([Out] IntPtr[] lpImageBase, int cb, out int lpcbNeeded);

    [DllImport("psapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
    static extern int GetDeviceDriverFileName(IntPtr ImageBase, StringBuilder lpFilename, int nSize);

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

    [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
    static extern int RegOpenKeyEx(UIntPtr hKey, string subKey, int ulOptions, int samDesired, out SafeRegistryHandle hkResult);

    [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
    static extern int RegQueryInfoKey(SafeRegistryHandle hKey, StringBuilder lpClass, IntPtr lpcchClass, IntPtr lpReserved,
        IntPtr lpcSubKeys, IntPtr lpcbMaxSubKeyLen, IntPtr lpcbMaxClassLen, IntPtr lpcValues,
        IntPtr lpcbMaxValueNameLen, IntPtr lpcbMaxValueLen, IntPtr lpcbSecurityDescriptor, out long lpftLastWriteTime);

    public static List<string> GetLoadedDrivers() {
        List<string> list = new List<string>();
        int needed;
        EnumDeviceDrivers(null, 0, out needed);
        if (needed == 0) return list;
        int count = needed / IntPtr.Size;
        IntPtr[] addresses = new IntPtr[count];
        if (EnumDeviceDrivers(addresses, needed, out needed)) {
            StringBuilder sb = new StringBuilder(1024);
            foreach (var addr in addresses) {
                if (GetDeviceDriverFileName(addr, sb, sb.Capacity) > 0) list.Add(sb.ToString());
            }
        }
        return list;
    }

    public static Dictionary<string, string> GetVolumeMap() {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        StringBuilder sb = new StringBuilder(512);
        for (char c = 'A'; c <= 'Z'; c++) {
            string drive = c + ":";
            if (QueryDosDevice(drive, sb, sb.Capacity) > 0) {
                map[sb.ToString()] = drive;
            }
        }
        return map;
    }

    public static string GetRegistryKeyTime(string subKey) {
        UIntPtr HKEY_LOCAL_MACHINE = (UIntPtr)0x80000002;
        SafeRegistryHandle hKey;
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey, 0, 0x20019, out hKey) == 0) {
            long fileTime;
            if (RegQueryInfoKey(hKey, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out fileTime) == 0) {
                hKey.Dispose();
                return DateTime.FromFileTime(fileTime).ToString("yyyy-MM-dd HH:mm:ss");
            }
            hKey.Dispose();
        }
        return "";
    }
}
"@
Add-Type -TypeDefinition $cSharp -ErrorAction SilentlyContinue
$volMap = [classForensics]::GetVolumeMap()

function Normalize-Path([string]$rawPath) {
    if ([string]::IsNullOrWhiteSpace($rawPath)) { return "" }
    $p = $rawPath.Trim('"').Trim()
    $p = $p -replace '^\\\?\\', ''
    $p = $p -replace '^\\?\?\', ''
    $p = $p -replace '(?i)^\\SystemRoot', $env:SystemRoot
    $p = $p -replace '(?i)^System32', "$env:SystemRoot\System32"
    foreach ($kv in $volMap.GetEnumerator()) {
        if ($p.StartsWith($kv.Key + "\", [StringComparison]::OrdinalIgnoreCase)) {
            $p = $kv.Value + $p.Substring($kv.Key.Length)
            break
        }
    }
    return $p
}

function Is-SuspiciousPath([string]$cleanPath) {
    if ([string]::IsNullOrWhiteSpace($cleanPath)) { return $false }
    if ($cleanPath -match '(?i)^[A-Z]:\\Windows\\(System32\\drivers\\|System32\\DriverStore\\FileRepository\\|SysWOW64\\drivers\\)') {
        return $false
    }
    if ($cleanPath -notmatch '\\') { return $false }
    return $true
}

function Get-SigInfo([string]$filePath) {
    if ([string]::IsNullOrWhiteSpace($filePath)) { return "Нет подписи" }
    if (Test-Path -LiteralPath $filePath) {
        $sig = Get-AuthenticodeSignature -LiteralPath $filePath
        if ($sig) {
            if ($sig.Status -eq 'Valid') {
                $signer = $sig.SignerCertificate.GetNameInfo('SimpleName', $false)
                return "Подписан ($signer)"
            } elseif ($sig.Status -eq 'NotSigned') {
                return "Нет подписи"
            } else {
                $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.GetNameInfo('SimpleName', $false) } else { "Неизвестен" }
                return "Подпись недействительна [$($sig.Status)] ($signer)"
            }
        }
        return "Нет подписи"
    } else {
        return "Нет подписи (файл удален с диска)"
    }
}

function Add-Record([string]$name, [string]$path, [string]$time, [string]$source) {
    $key = $path.ToLower()
    $sig = Get-SigInfo $path
    if (-not $results.ContainsKey($key)) {
        $results[$key] = [PSCustomObject]@{
            Name      = $name
            Path      = $path
            Time      = $time
            Signature = $sig
            Source    = $source
        }
    } else {
        if ($time -and ($results[$key].Time -eq "Неизвестно" -or $source -match "Event")) {
            $results[$key].Time = $time
        }
        if ($results[$key].Source -notmatch $source) {
            $results[$key].Source += ", $source"
        }
    }
}

# 1. Драйверы в памяти ядра прямо сейчас
foreach ($raw in [classForensics]::GetLoadedDrivers()) {
    $clean = Normalize-Path $raw
    if (Is-SuspiciousPath $clean) {
        $fName = [System.IO.Path]::GetFileName($clean)
        $fTime = if (Test-Path -LiteralPath $clean) { (Get-Item -LiteralPath $clean -Force).CreationTime.ToString("yyyy-MM-dd HH:mm:ss") + " (создан файл)" } else { "Активен в ОЗУ (файл стерли)" }
        Add-Record $fName $clean $fTime "В памяти ядра"
    }
}

# 2. Реестр Services
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*" -ErrorAction SilentlyContinue | Where-Object { $_.Type -in @(1, 2) -and $_.ImagePath } | ForEach-Object {
    $clean = Normalize-Path $_.ImagePath
    if (Is-SuspiciousPath $clean) {
        $srvName = $_.PSChildName
        $regTime = [classForensics]::GetRegistryKeyTime("SYSTEM\CurrentControlSet\Services\$srvName")
        if (-not $regTime) { $regTime = "Неизвестно" } else { $regTime = "$regTime (реестр)" }
        Add-Record $srvName $clean $regTime "Реестр Services"
    }
}

# 3. Журнал System: EventID 7045, 6
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045, 6} -MaxEvents 5000 -ErrorAction SilentlyContinue | ForEach-Object {
    $evTime = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    if ($_.Id -eq 7045) {
        $img = ($data | Where-Object { $_.Name -eq 'ImagePath' }).'#text'
        $srv = ($data | Where-Object { $_.Name -eq 'ServiceName' }).'#text'
        $clean = Normalize-Path $img
        if (Is-SuspiciousPath $clean) {
            Add-Record $srv $clean "$evTime (Event 7045)" "Журнал System"
        }
    } elseif ($_.Id -eq 6) {
        $img = ($data | Where-Object { $_.Name -eq 'ImagePath' }).'#text'
        if (-not $img) { $img = $data.'#text' }
        $clean = Normalize-Path $img
        if (Is-SuspiciousPath $clean) {
            $fName = [System.IO.Path]::GetFileName($clean)
            Add-Record $fName $clean "$evTime (Event 6 - старт)" "Журнал System"
        }
    }
}

# 4. Журнал CodeIntegrity
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational'; Id=3001,3002,3003,3004,3010,3023,3033} -MaxEvents 3000 -ErrorAction SilentlyContinue | ForEach-Object {
    $evTime = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    $img = ($data | Where-Object { $_.Name -match 'FileName' }).'#text'
    if ($img -match '(?i)\.sys$') {
        $clean = Normalize-Path $img
        if (Is-SuspiciousPath $clean) {
            $fName = [System.IO.Path]::GetFileName($clean)
            Add-Record $fName $clean "$evTime (CodeIntegrity ID $($_.Id))" "CodeIntegrity"
        }
    }
}

$outList = $results.Values | Sort-Object Time -Descending
$outList | ConvertTo-Json -Compress
"""


def scan_drivers(report: ReportBuffer) -> list:
    """
    Сканирует нестандартные драйверы через PowerShell + C# interop.
    Ищет:
      - Драйверы в памяти ядра (EnumDeviceDrivers)
      - Службы типа 1/2 в реестре Services
      - События 7045/6 в System log
      - События CodeIntegrity (неподписанные драйверы)
    Всё, что вне стандартных путей System32rivers — помечается.
    """
    findings = []

    report.event("DRIVERS-INFO", "Запуск продвинутого анализа драйверов (C# interop)...")

    # Скрипт тяжёлый — даём 120 секунд
    stdout = _run_powershell(DRIVERS_PS_SCRIPT, timeout=120)

    if not stdout:
        report.event("DRIVERS-EMPTY", "PowerShell не вернул данных (возможно, нет прав админа)")
        return findings

    if stdout.strip() == "null" or stdout.strip() == "":
        report.event("DRIVERS-CLEAN", "Нестандартных драйверов не обнаружено ✅")
        return findings

    # Парсим JSON
    try:
        import json
        drivers = json.loads(stdout)
        if isinstance(drivers, dict):
            drivers = [drivers]
    except json.JSONDecodeError as e:
        report.event("DRIVERS-ERROR", f"Ошибка парсинга JSON: {e}")
        return findings

    if not drivers:
        report.event("DRIVERS-CLEAN", "Нестандартных драйверов не обнаружено ✅")
        return findings

    # Счётчики для статистики
    unsigned_count = 0
    invalid_sig_count = 0
    deleted_from_disk = 0
    cheat_detected = 0

    for d in drivers:
        name = d.get("Name", "Unknown")
        path = d.get("Path", "")
        time_info = d.get("Time", "Неизвестно")
        signature = d.get("Signature", "Нет подписи")
        source = d.get("Source", "")

        # Анализ подписи
        is_unsigned = "Нет подписи" in signature
        is_invalid_sig = "недействительна" in signature.lower()
        is_deleted = "удален" in signature.lower() or "Активен в ОЗУ" in time_info

        if is_unsigned:
            unsigned_count += 1
        if is_invalid_sig:
            invalid_sig_count += 1
        if is_deleted:
            deleted_from_disk += 1

        # Проверка на читы по имени драйвера
        hit = _check_stop_words(name) or _check_stop_words(path)
        flags = []
        if hit:
            flags.append(f"STOPWORD:{hit}")
            cheat_detected += 1
        if is_unsigned:
            flags.append("UNSIGNED")
        if is_invalid_sig:
            flags.append("INVALID-SIGNATURE")
        if is_deleted:
            flags.append("DELETED-FROM-DISK")

        # Категория
        if hit:
            category = "CHEAT"
        elif is_unsigned or is_invalid_sig:
            category = "SUSPICIOUS"  # Неподписанный = подозрительный даже без совпадения с базой
        else:
            category = "UNKNOWN"

        findings.append({
            "name": name,
            "path": path,
            "time": time_info,
            "signature": signature,
            "source": source,
            "category": category,
            "flags": flags,
        })

        # Запись в отчёт
        report.section(f"ДРАЙВЕР [{category}]")
        report.lines.append("[!] Обнаружен нестандартный драйвер:")
        report.lines.append(f"    Имя службы:  {name}")
        report.lines.append(f"    Путь:        {path}")
        report.lines.append(f"    Время:       {time_info}")
        report.lines.append(f"    Подпись:     {signature}")
        report.lines.append(f"    Источник:    {source}")
        if flags:
            report.lines.append(f"    Флаги:       {', '.join(flags)}")
        report.lines.append("")

    # Итоговая статистика
    report.event(
        "DRIVERS-СТАТИСТИКА",
        f"Всего нестандартных: {len(drivers)} | "
        f"Без подписи: {unsigned_count} | "
        f"Недействительная подпись: {invalid_sig_count} | "
        f"Удалены с диска (в ОЗУ): {deleted_from_disk} | "
        f"Совпадений с cheat_db: {cheat_detected}"
    )

    # Критические предупреждения
    if unsigned_count > 0:
        report.event(
            "🚨 КРИТИЧНО: НЕПОДПИСАННЫЕ ДРАЙВЕРЫ",
            f"Найдено {unsigned_count} драйверов БЕЗ цифровой подписи. "
            f"Это типичный признак kdmapper/drvmap (загрузка читов через уязвимые драйверы)."
        )

    if deleted_from_disk > 0:
        report.event(
            "⚠️ ДРАЙВЕРЫ В ОЗУ БЕЗ ФАЙЛА",
            f"Найдено {deleted_from_disk} драйверов, активных в памяти, "
            f"но удалённых с диска. Это признак runtime-загрузки чита."
        )

    return findings

# ============================================================================
# МОДУЛЬ: USN JOURNAL (продвинутый анализ с разрешением путей)
# ============================================================================

def _usn_get_recent_start_usn(drive: str = "C:", step_back_bytes: int = 80 * 1024 * 1024) -> str:
    """
    Получает стартовый USN, отступив на step_back_bytes (по умолчанию 80 МБ)
    от конца журнала. Это позволяет читать только свежие записи, не перебирая
    весь журнал целиком.
    """
    cmd = ["fsutil", "usn", "queryjournal", drive]
    creation_flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True, encoding="cp866",
            errors="replace", creationflags=creation_flags, timeout=10
        )
        hex_vals = re.findall(r"0x[0-9a-fA-F]+", res.stdout)
        if len(hex_vals) >= 3:
            first_usn = int(hex_vals[1], 16)
            next_usn = int(hex_vals[2], 16)
            start_usn = max(first_usn, next_usn - step_back_bytes)
            return hex(start_usn)
    except Exception:
        pass
    return "0"


def _usn_resolve_parent_path(drive: str, parent_id: str) -> str:
    """
    Разрешает ParentID в полный путь через fsutil file queryfilenamebyid.
    Использует кэш, чтобы не дёргать fsutil для одинаковых ID.
    """
    if not parent_id:
        return "Неизвестно"
    if parent_id in _PARENT_PATH_CACHE:
        return _PARENT_PATH_CACHE[parent_id]

    creation_flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    try:
        cmd = ["fsutil", "file", "queryfilenamebyid", drive, f"0x{parent_id}"]
        res = subprocess.run(
            cmd, capture_output=True, text=True, encoding="cp866",
            errors="replace", creationflags=creation_flags, timeout=5
        )
        out = res.stdout.strip()

        marker = "\\\\?\\"
        pos = out.find(marker)
        if pos != -1:
            path = out[pos + len(marker):].strip()
        else:
            path = "[Папка удалена или скрыта]"
    except Exception:
        path = "[Папка удалена или скрыта]"

    _PARENT_PATH_CACHE[parent_id] = path
    return path


def _usn_is_noisy_folder(folder_path: str, ext: str) -> bool:
    """Проверяет, является ли путь шумом (системные папки, кэши браузеров и т.д.)."""
    p_low = folder_path.lower()
    # Prefetch не считаем шумом, если расширение .pf
    if ext == ".pf" and "\\windows\\prefetch" in p_low:
        return False
    return any(part in p_low for part in USN_NOISE_PATH_PARTS)


def _usn_check_suspicious_name(filename: str) -> bool:
    """
    Проверяет имя файла на подозрительность.
    Объединяет:
      - Ключевые слова из USN_SUSPICIOUS_KEYWORDS (встроенные)
      - Слова из cheat_db.json (ALL_STOPWORDS)
    """
    fn_low = filename.lower()
    for kw in USN_SUSPICIOUS_KEYWORDS:
        if kw in fn_low:
            return True
    # Проверка через функцию с границами слов (чтобы "cyber" не ловил "cyberpunk")
    hit = _check_stop_words(filename)
    return hit is not None


def _usn_is_cheat_candidate(filename: str) -> bool:
    """
    Определяет, является ли файл кандидатом на чит/макрос/скрипт.
    Использует расширенный список расширений USN_CHEAT_EXTENSIONS.
    """
    if not filename:
        return False
    # Пропускаем служебные файлы
    if filename.startswith("__PSScriptPolicyTest_") or filename.startswith("~$"):
        return False
    if filename.startswith("$I") and len(filename) > 6:
        return False

    fn_low = filename.lower()
    # Точное совпадение с безопасными файлами
    if fn_low in USN_SAFE_EXACT_FILES:
        return False
    if re.match(r"^python3\d+\.dll$", fn_low):
        return False
    if "microsoftedge" in fn_low:
        return False

    _, ext = os.path.splitext(fn_low)
    
    # Prefetch: пропускаем системные программы
    if ext == ".pf":
        if filename.upper().startswith(USN_SAFE_PREFETCH_PREFIXES):
            return False
        return True

    # Остальные расширения
    return ext in USN_CHEAT_EXTENSIONS


def _usn_process_reasons(reason_raw: str, filename: str) -> tuple:
    """
    Разбирает строку Reason на отдельные флаги и переводит их.
    Особая обработка для .pf и файлов в корзине.
    """
    text_part = reason_raw.split(":", 1)[-1] if ":" in reason_raw else reason_raw
    raw_flags = [r.strip() for r in text_part.split("|")]

    important_flags = [
        REASON_TRANSLATIONS[r] for r in raw_flags
        if r in REASON_TRANSLATIONS and r != "Close"
    ]

    # Файлы в корзине ($R...)
    if filename.startswith("$R") and (
        "Rename new name" in raw_flags or "Rename: new name" in raw_flags
    ):
        return raw_flags, "В КОРЗИНУ ($Recycle.Bin)"
    
    # Prefetch: особая обработка
    if filename.lower().endswith(".pf"):
        if "File delete" in raw_flags:
            return raw_flags, "[!] ЧИСТКА PREFETCH (УДАЛЕНИЕ УЛИК)"
        if "File create" in raw_flags:
            return raw_flags, "ЗАПУСК ПРОГРАММЫ (Prefetch)"

    return raw_flags, " + ".join(important_flags)


def scan_usn_journal(report: ReportBuffer) -> list:
    """
    Продвинутый анализ USN Journal:
      - Читает только свежие записи (80 МБ от конца журнала)
      - Разрешает ParentID в полный путь к папке
      - Объединяет ключевые слова из cheat_db.json и встроенного списка
      - Специально обрабатывает .pf файлы (запуск/очистка Prefetch)
      - Детектирует очистку Prefetch как зачистку улик
      - Фильтрует шум (системные обновления, кэши браузеров)
    """
    global _PARENT_PATH_CACHE
    _PARENT_PATH_CACHE = {}  # Сбрасываем кэш для каждого запуска

    findings = []
    drive = "C:"
    max_matched = 250

    # Проверка активности журнала
    creation_flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    try:
        check = subprocess.run(
            ['fsutil', 'usn', 'queryjournal', drive],
            capture_output=True, text=True, encoding='cp866',
            errors='replace', timeout=10, creationflags=creation_flags
        )
        if check.returncode != 0 or 'Usn Journal ID' not in check.stdout:
            report.event("ПРОПУЩЕНО", "USN Journal не активен")
            return findings
    except Exception as e:
        report.event("ОШИБКА", f"Проверка журнала: {e}")
        return findings

    # Получаем стартовый USN
    start_usn = _usn_get_recent_start_usn(drive, step_back_bytes=80 * 1024 * 1024)
    report.event("USN-INFO", f"Сканирование с USN {start_usn} (свежие записи)")

    # Читаем журнал
    try:
        cmd = ["fsutil", "usn", "readjournal", drive, f"startusn={start_usn}"]
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="cp866", errors="replace",
            creationflags=creation_flags
        )

        records = []
        curr = {}
        scanned = 0

        def evaluate_record(rec: dict) -> None:
            """Оценивает одну запись журнала и добавляет в findings."""
            fn = rec.get("FileName", "")
            flags = rec.get("RawFlags", [])
            
            # Нас интересуют только группы: Close + целевое событие
            # (это фильтрует промежуточные события и берёт финальный результат)
            if not ("Close" in flags and any(e in flags for e in USN_TARGET_EVENTS)):
                return
            
            # Проверяем, является ли файл кандидатом
            if not _usn_is_cheat_candidate(fn):
                return
            
            _, ext = os.path.splitext(fn.lower())
            
            # Разрешаем ParentID в путь
            folder = _usn_resolve_parent_path(drive, rec.get("ParentID", ""))
            
            # Фильтруем шум
            if _usn_is_noisy_folder(folder, ext):
                return
            
            # Whitelist
            if is_name_whitelisted(fn) or is_path_whitelisted(folder):
                return
            
            # Проверяем на подозрительность
            is_suspicious = _usn_check_suspicious_name(fn)
            reason = rec.get("Reason", "")
            is_prefetch_clean = "ЧИСТКА PREFETCH" in reason
            is_detect = is_suspicious or is_prefetch_clean

            category = "CHEAT" if is_detect else "UNKNOWN"
            action = reason

            ts_str = rec.get("Timestamp", "N/A")
            try:
                ts = _parse_usn_time(ts_str)
            except Exception:
                ts = dt.datetime.min

            findings.append({
                "timestamp": ts_str,
                "filename": fn,
                "folder": folder,
                "reason": action,
                "category": category,
                "is_detect": is_detect,
                "dt": ts,
            })

            # Префикс для детектов
            prefix = "[! ДЕТЕКТ] " if is_detect else ""
            
            report.section(f"USN СОБЫТИЕ [{category}]")
            report.lines.append(f"[!] Запись USN Journal:")
            report.lines.append(f"    Время:      {ts_str}")
            report.lines.append(f"    Файл:       {prefix}{fn}")
            report.lines.append(f"    Папка:      {folder}")
            report.lines.append(f"    Действие:   {action}")
            report.lines.append(f"    Категория:  {category}")
            report.lines.append("")

        assert process.stdout is not None
        for line in process.stdout:
            line = line.strip()
            if not line or ":" not in line:
                continue
            
            key, val = [x.strip() for x in line.split(":", 1)]
            
            if key in ("Usn", "USN"):
                scanned += 1
                if curr:
                    evaluate_record(curr)
                curr = {"USN": val}
            elif key in ("File name", "Имя файла"):
                curr["FileName"] = val
            elif key in ("Reason", "Причина"):
                curr["RawReason"] = val
            elif key in ("Time stamp", "Метка времени"):
                curr["Timestamp"] = val
            elif key in ("File ID", "Идентификатор файла"):
                curr["FileID"] = val
            elif key in ("Parent file ID", "Идентификатор родительского файла"):
                curr["ParentID"] = val
            
            # Когда собрали все ключевые поля — обрабатываем Reason
            if "RawReason" in curr:
                raw_flags, trans_str = _usn_process_reasons(
                    curr.pop("RawReason"), 
                    curr.get("FileName", "")
                )
                curr["RawFlags"] = raw_flags
                curr["Reason"] = trans_str
        
        # Последняя запись
        if curr:
            evaluate_record(curr)

        process.terminate()
        try:
            process.wait(timeout=3)
        except Exception:
            process.kill()

        report.event("USN-СТАТИСТИКА", f"Записей проверено: {scanned:,} | Найдено: {len(findings)}")

    except subprocess.TimeoutExpired:
        process.kill()
        report.event("ТАЙМАУТ", "fsutil usn readjournal")
    except PermissionError:
        report.event("ЗАБЛОКИРОВАНО", "USN: PermissionError")
    except Exception as e:
        report.event("ОШИБКА", f"USN: {e}")

    return findings[:max_matched]


# ============================================================================
# МОДУЛЬ: PREFETCH
# ============================================================================

def scan_prefetch(report: ReportBuffer) -> list:
    """Проверяет имена файлов в C:\\Windows\\Prefetch за 7 дней на совпадение со стоп-словами."""
    findings = []
    cutoff = time.time() - SEVEN_DAYS_SEC

    if not os.path.isdir(PREFETCH_DIR):
        report.event("ПРОПУЩЕНО", "Prefetch dir not found")
        return findings

    try:
        for fname in os.listdir(PREFETCH_DIR):
            if not fname.lower().endswith('.pf') or is_name_whitelisted(fname):
                continue
            full = os.path.join(PREFETCH_DIR, fname)
            try:
                stat = os.stat(full)
            except (PermissionError, FileNotFoundError):
                continue
            if stat.st_mtime < cutoff:
                continue
            hit = _check_stop_words(fname)
            if hit:
                findings.append((dt.datetime.fromtimestamp(stat.st_mtime), fname, hit))
                report.event("PREFETCH-TRIGGER", f"{fname} | match='{hit}'")
    except PermissionError:
        report.event("ЗАБЛОКИРОВАНО", "Prefetch PermissionError")
    except Exception as e:
        report.event("ОШИБКА", f"Prefetch: {e}")

    return findings


# ============================================================================
# МОДУЛЬ: BAM
# ============================================================================

def scan_bam(report: ReportBuffer) -> list:
    """Читает имена путей из BAM (реестр) и сверяет со стоп-словами."""
    findings = []
    try:
        base_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, BAM_PATH)
        i = 0
        while True:
            try:
                sid = winreg.EnumKey(base_key, i)
                i += 1
            except OSError:
                break
            try:
                sid_key = winreg.OpenKey(base_key, sid)
                j = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(sid_key, j)
                        j += 1
                    except OSError:
                        break
                    basename = os.path.basename(name)
                    if is_name_whitelisted(basename) or is_path_whitelisted(name):
                        continue
                    hit = _check_stop_words(name)
                    if hit:
                        ts = _filetime_to_dt(data) if isinstance(data, int) else None
                        findings.append((ts, name, hit))
                        report.event("BAM-TRIGGER", f"{name} | match='{hit}'")
            except PermissionError:
                pass
    except (FileNotFoundError, PermissionError):
        report.event("ЗАБЛОКИРОВАНО", "BAM недоступен")
    except Exception as e:
        report.event("ОШИБКА", f"BAM: {e}")

    return findings


# ============================================================================
# МОДУЛЬ: AMCACHE
# ============================================================================

def scan_amcache(report: ReportBuffer) -> list:
    """Загружает Amcache.hve (через RegLoadKey) и сверяет пути/имена со стоп-словами.
    Перед загрузкой явно включает SeBackupPrivilege/SeRestorePrivilege — без этого
    LoadKey падает с [WinError 1314], даже если процесс запущен от администратора."""
    findings = []
    if not os.path.isfile(AMCACHE_PATH):
        report.event("ПРОПУЩЕНО", "Amcache.hve отсутствует")
        return findings

    if not _enable_privileges():
        report.event("INFO", "Не удалось включить SeBackup/SeRestorePrivilege — "
                              "Amcache может быть недоступен даже под администратором")

    hive_already_loaded = False
    try:
        test_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, AMCACHE_TEMP_HIVE)
        winreg.CloseKey(test_key)
        hive_already_loaded = True
    except (FileNotFoundError, OSError):
        pass

    load_success = False
    amcache_file_to_load = AMCACHE_PATH

    if not hive_already_loaded:
        try:
            winreg.LoadKey(winreg.HKEY_LOCAL_MACHINE, AMCACHE_TEMP_HIVE, AMCACHE_PATH)
            load_success = True
        except OSError as e:
            error_code = getattr(e, 'winerror', 0)

            if error_code in (32, 1314, 5):
                # 32 = файл занят другим процессом (sharing violation) — решается
                #      через VSS (снимок тома обходит блокировку живого файла).
                # 1314/5 = не хватает привилегий — VSS тут не поможет (LoadKey
                #      требует SeRestorePrivilege у процесса независимо от
                #      источника файла), но стоит попробовать на случай, если
                #      включение привилегии выше всё же частично не удалось.
                if error_code == 32:
                    report.event("INFO", "Amcache: файл занят, пробую через теневую копию (VSS)")
                else:
                    report.event("INFO", f"Amcache: [WinError {error_code}], пробую через VSS "
                                          "(если дело не в привилегиях, а в блокировке — поможет)")

                vss_copy = _copy_file_via_vss(r'\Windows\AppCompat\Programs\Amcache.hve')
                if vss_copy:
                    try:
                        winreg.LoadKey(winreg.HKEY_LOCAL_MACHINE, AMCACHE_TEMP_HIVE, vss_copy)
                        load_success = True
                        amcache_file_to_load = vss_copy
                    except OSError as e2:
                        try:
                            os.remove(vss_copy)
                        except Exception:
                            pass
                        if getattr(e2, 'winerror', 0) in (1314, 5):
                            report.event("ЗАБЛОКИРОВАНО",
                                         "Amcache: привилегии SeBackup/SeRestore не включились "
                                         "даже для копии через VSS — дело не в блокировке файла")
                            return findings

                if not load_success and error_code == 32:
                    # Последняя попытка — обычное копирование (может сработать,
                    # если файл к этому моменту уже освободился).
                    temp_amcache = os.path.join(tempfile.gettempdir(), f"amcache_copy_{os.getpid()}.hve")
                    try:
                        shutil.copy2(AMCACHE_PATH, temp_amcache)
                        winreg.LoadKey(winreg.HKEY_LOCAL_MACHINE, AMCACHE_TEMP_HIVE, temp_amcache)
                        load_success = True
                        amcache_file_to_load = temp_amcache
                    except (PermissionError, OSError):
                        try:
                            os.remove(temp_amcache)
                        except Exception:
                            pass

                if not load_success:
                    report.event("ЗАБЛОКИРОВАНО", f"Amcache: недоступен (WinError {error_code}), "
                                                    "включая попытку через VSS")
                    return findings
            else:
                report.event("ЗАБЛОКИРОВАНО", f"Amcache LoadKey: {e}")
                return findings
        except Exception as e:
            report.event("ЗАБЛОКИРОВАНО", f"Amcache: {e}")
            return findings

    if not load_success and not hive_already_loaded:
        return findings

    try:
        base = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, AMCACHE_TEMP_HIVE)
        for subpath in (r'Root\File', r'Root\InventoryApplicationFile'):
            try:
                file_key = winreg.OpenKey(base, subpath)
            except (FileNotFoundError, OSError):
                continue
            i = 0
            while True:
                try:
                    entry_name = winreg.EnumKey(file_key, i)
                    i += 1
                except OSError:
                    break
                try:
                    entry_key = winreg.OpenKey(file_key, entry_name)
                    path = _reg_query(entry_key, 'FilePath') or _reg_query(entry_key, 'LowerCaseLongPath') or ''
                    name = _reg_query(entry_key, 'Name') or ''
                    sha1 = _reg_query(entry_key, 'Sha1Hash') or _reg_query(entry_key, 'FileId') or entry_name
                    size_raw = _reg_query(entry_key, 'Size') or _reg_query(entry_key, 'FileSize')
                    size = int(size_raw) if size_raw and size_raw.isdigit() else 0

                    full_check = f"{path}\\{name}" if path and name else (path or name)
                    hit = _check_stop_words(full_check) or _check_stop_words(sha1)

                    flags = []
                    if hit:
                        flags.append(f"STOPWORD:{hit}")
                    if name and _is_random_name(name):
                        flags.append("RANDOM-NAME")
                    if 0 < size < 10 * 1024:
                        flags.append(f"SUSPECT-SIZE({size}B)")

                    if flags and not (is_path_whitelisted(full_check) or is_name_whitelisted(name)):
                        findings.append((full_check, sha1, flags))
                        report.event("AMCACHE-TRIGGER", f"{full_check} | sha1={sha1[:16]}... | flags={','.join(flags)}")

                    winreg.CloseKey(entry_key)
                except Exception:
                    continue
            winreg.CloseKey(file_key)
        winreg.CloseKey(base)
    except Exception as e:
        report.event("ОШИБКА", f"Amcache чтение: {e}")
    finally:
        if not hive_already_loaded:
            try:
                advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
                advapi32.RegUnLoadKeyW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
                advapi32.RegUnLoadKeyW.restype = ctypes.c_long
                advapi32.RegUnLoadKeyW(ctypes.c_void_p(int(winreg.HKEY_LOCAL_MACHINE)), AMCACHE_TEMP_HIVE)
            except Exception:
                pass
            if amcache_file_to_load != AMCACHE_PATH:
                try:
                    os.remove(amcache_file_to_load)
                except Exception:
                    pass

    return findings

# ============================================================================
# МОДУЛЬ: MFT (УДАЛЁННЫЕ ФАЙЛЫ)
# ============================================================================

# ============================================================================
# МОДУЛЬ: MFT (ПРЯМОЙ ПАРСИНГ СЫРОГО ДИСКА)
# ============================================================================
# Читает $MFT напрямую с \\.\C:, извлекает:
#   - Имя файла (полное, с раскрытием 8.3 через WinAPI)
#   - Полный путь к папке
#   - Размер файла
#   - Время создания
#   - Время удаления (MFT modification time)
# Фильтрует по whitelist, cheat_db и 7 дням.
# ============================================================================

def _mft_get_runs(disk, mft_start_offset: int) -> list:
    """Читает карту фрагментов MFT (Data Runs) из 0-й записи."""
    disk.seek(mft_start_offset)
    record0 = bytearray(disk.read(1024))
    if record0[:4] != b"FILE":
        return []

    # Применяем Fixup для 0-й записи
    usa_offset, usa_count = struct.unpack("<HH", record0[4:8])
    for i in range(1, usa_count):
        try:
            record0[i*512 - 2 : i*512] = record0[usa_offset + i*2 : usa_offset + (i+1)*2]
        except IndexError:
            break

    attrs_offset, = struct.unpack("<H", record0[20:22])
    curr = attrs_offset
    runs = []

    while curr + 8 <= len(record0):
        attr_type, attr_len = struct.unpack("<II", record0[curr:curr+8])
        if attr_type == 0xFFFFFFFF or attr_len == 0:
            break
        if attr_type == 0x80:  # $DATA
            try:
                run_offset, = struct.unpack("<H", record0[curr+32:curr+34])
            except struct.error:
                break
            pos = curr + run_offset
            current_lcn = 0
            while pos < curr + attr_len:
                header = record0[pos]
                if header == 0:
                    break
                pos += 1
                len_b = header & 0x0F
                off_b = (header >> 4) & 0x0F
                if len_b == 0 or off_b == 0 or pos + len_b + off_b > len(record0):
                    break
                run_len = int.from_bytes(record0[pos:pos+len_b], 'little', signed=False)
                pos += len_b
                run_off = int.from_bytes(record0[pos:pos+off_b], 'little', signed=True)
                pos += off_b
                current_lcn += run_off
                runs.append((run_len, current_lcn))
            break
        curr += attr_len
    return runs


def _mft_read_record(disk, runs, cluster_size, mft_start, record_index):
    """Читает запись MFT с учётом фрагментации диска."""
    byte_offset = record_index * 1024
    target_vcn = byte_offset // cluster_size
    offset_in_cluster = byte_offset % cluster_size

    disk_offset = None
    current_vcn = 0
    for run_len, lcn in runs:
        if current_vcn <= target_vcn < current_vcn + run_len:
            real_lcn = lcn + (target_vcn - current_vcn)
            disk_offset = (real_lcn * cluster_size) + offset_in_cluster
            break
        current_vcn += run_len

    if disk_offset is None:
        disk_offset = mft_start + byte_offset

    try:
        disk.seek(disk_offset)
        raw = bytearray(disk.read(1024))
    except (OSError, ValueError):
        return None

    if raw[:4] != b"FILE":
        return None

    usa_offset, usa_count = struct.unpack("<HH", raw[4:8])
    if usa_offset + usa_count * 2 <= 1024:
        for i in range(1, usa_count):
            try:
                raw[i*512 - 2 : i*512] = raw[usa_offset + i*2 : usa_offset + (i+1)*2]
            except (IndexError, struct.error):
                break
    return bytes(raw)


def _mft_parse_attrs(record_data: bytes) -> dict:
    """
    Извлекает из записи MFT всю нужную информацию:
    - имена файлов (атрибут 0x30)
    - времена (атрибут 0x10)
    - размер файла
    - флаг удаления
    """
    result = {
        'names': [],           # [(namespace, name), ...]
        'parent_idx': None,
        'creation_time': None,
        'mft_modification_time': None,  # Время удаления
        'modification_time': None,
        'access_time': None,
        'real_size': 0,
        'flags': 0,
        'is_directory': False,
    }

    if not record_data or record_data[:4] != b"FILE":
        return result

    # Флаг удаления: offset 22, bit 0
    try:
        result['flags'], = struct.unpack("<H", record_data[22:24])
    except struct.error:
        return result

    result['is_directory'] = bool(result['flags'] & 0x0002)

    attrs_offset, = struct.unpack("<H", record_data[20:22])
    curr = attrs_offset

    while curr + 8 <= len(record_data):
        try:
            attr_type, attr_len = struct.unpack("<II", record_data[curr:curr+8])
        except struct.error:
            break
        if attr_type == 0xFFFFFFFF or attr_len == 0 or attr_len > 1024:
            break
        if curr + attr_len > len(record_data):
            break

        non_resident = record_data[curr+8]

        # === $STANDARD_INFORMATION (0x10) — времена ===
        if attr_type == 0x10 and non_resident == 0:
            try:
                res_offset, = struct.unpack("<H", record_data[curr+20:curr+22])
                c_start = curr + res_offset
                # Creation time
                ct_raw, = struct.unpack("<Q", record_data[c_start:c_start+8])
                result['creation_time'] = _filetime_to_dt(ct_raw)
                # Modification time
                mt_raw, = struct.unpack("<Q", record_data[c_start+8:c_start+16])
                result['modification_time'] = _filetime_to_dt(mt_raw)
                # MFT modification time (время удаления для удалённых файлов)
                mft_raw, = struct.unpack("<Q", record_data[c_start+16:c_start+24])
                result['mft_modification_time'] = _filetime_to_dt(mft_raw)
                # Access time
                at_raw, = struct.unpack("<Q", record_data[c_start+24:c_start+32])
                result['access_time'] = _filetime_to_dt(at_raw)
            except (struct.error, IndexError):
                pass

        # === $FILE_NAME (0x30) — имя и размер ===
        elif attr_type == 0x30 and non_resident == 0:
            try:
                res_offset, = struct.unpack("<H", record_data[curr+20:curr+22])
                c_start = curr + res_offset

                # Parent directory reference
                raw_p, = struct.unpack("<Q", record_data[c_start:c_start+8])
                p_idx = raw_p & 0xFFFFFFFFFFFF
                if p_idx != 5:  # 5 = корневая директория (обычно пропускаем)
                    result['parent_idx'] = p_idx

                # Real size (реальный размер файла)
                real_size, = struct.unpack("<Q", record_data[c_start+0x30:c_start+0x38])
                if real_size > 0:
                    result['real_size'] = real_size

                # Имя файла
                name_len = record_data[c_start + 0x40]
                name_type = record_data[c_start + 0x41]
                name_bytes = record_data[c_start + 0x42 : c_start + 0x42 + (name_len * 2)]
                try:
                    decoded = name_bytes.decode('utf-16-le')
                    result['names'].append((name_type, decoded))
                except UnicodeDecodeError:
                    pass
            except (struct.error, IndexError):
                pass

        curr += attr_len

    return result


def _mft_pick_best_name(names: list) -> str:
    """Выбирает лучшее имя: без тильды, не DOS namespace (тип != 2), самое длинное."""
    if not names:
        return ""
    long_names = [n for t, n in names if t != 2 and '~' not in n]
    if long_names:
        return max(long_names, key=len)
    return max([n for t, n in names], key=len)


def _mft_resolve_path(drive_letter: str, path_parts: list) -> str:
    """Собирает путь и раскрывает короткие имена (GLOBAL~1 -> globalStorage) через WinAPI."""
    # Если первое звено не прочиталось, но дальше профиль и AppData — это Users
    if len(path_parts) >= 3 and path_parts[0].startswith("Unknown_MFT_"):
        if path_parts[2].lower() == "appdata" or os.path.exists(f"{drive_letter}:\\Users\\{path_parts[1]}"):
            path_parts[0] = "Users"

    raw_path = f"{drive_letter}:\\" + "\\".join(path_parts)

    # Пробуем WinAPI для раскрытия коротких имен
    buf = ctypes.create_unicode_buffer(1024)
    try:
        if ctypes.windll.kernel32.GetLongPathNameW(raw_path, buf, 1024) > 0:
            return buf.value
    except Exception:
        pass

    # Фолбэк: раскрываем хотя бы папку
    if len(path_parts) > 1:
        parent_raw = f"{drive_letter}:\\" + "\\".join(path_parts[:-1])
        try:
            if ctypes.windll.kernel32.GetLongPathNameW(parent_raw, buf, 1024) > 0:
                return buf.value + "\\" + path_parts[-1]
        except Exception:
            pass

    return raw_path


def scan_mft(report: ReportBuffer) -> list:
    """
    Сканирует сырую $MFT диска C:, находит удалённые файлы за 7 дней,
    восстанавливает полные пути, размеры, времена. Фильтрует по whitelist и базе читов.
    """
    findings = []
    cutoff = time.time() - SEVEN_DAYS_SEC
    drive = "C"

    # Счётчики для статистики
    total_records = 0
    deleted_files = 0
    executable_deleted = 0
    start_time = time.time()
    MAX_TIME = 180  # 3 минуты максимум
    MAX_FINDINGS = 500

    try:
        with open(f"\\\\.\\{drive}:", "rb") as disk:
            # === Читаем загрузочный сектор ===
            boot = disk.read(512)
            if len(boot) < 56:
                report.event("ОШИБКА", "MFT: загрузочный сектор слишком мал")
                return findings

            bps, = struct.unpack("<H", boot[11:13])  # Bytes per sector
            spc = boot[13]                             # Sectors per cluster
            cluster_size = bps * spc
            mft_cluster, = struct.unpack("<Q", boot[48:56])
            mft_start = mft_cluster * cluster_size

            # === Получаем карту фрагментов MFT ===
            runs = _mft_get_runs(disk, mft_start)
            if not runs:
                report.event("ОШИБКА", "MFT: не удалось прочитать карту фрагментов")
                return findings

            # === Оцениваем размер MFT (приблизительно) ===
            # Берём максимум из runs, чтобы понять примерное количество записей
            total_vcn = sum(run_len for run_len, _ in runs)
            estimated_records = (total_vcn * cluster_size) // 1024
            # Ограничиваем разумным максимумом (10 млн записей = ~10 ГБ MFT)
            max_records = min(estimated_records, 10_000_000)

            report.event("MFT-INFO", f"Начат прямой парсинг MFT диска {drive}:")
            report.event("MFT-INFO", f"  Размер кластера: {cluster_size} байт")
            report.event("MFT-INFO", f"  Начало MFT: кластер {mft_cluster}")
            report.event("MFT-INFO", f"  Оценочное число записей: {estimated_records:,}")

            # === Основной цикл сканирования ===
            for idx in range(0, max_records):
                # Таймаут
                if time.time() - start_time > MAX_TIME:
                    report.event("ТАЙМАУТ", f"MFT прерван по времени ({total_records:,} записей обработано)")
                    break

                # Лимит находок
                if len(findings) >= MAX_FINDINGS:
                    report.event("ЛИМИТ", f"MFT достиг лимита {MAX_FINDINGS} находок")
                    break

                # Прогресс каждые 100k записей
                if idx % 100_000 == 0 and idx > 0:
                    elapsed = time.time() - start_time
                    report.event("MFT-PROGRESS", f"Обработано {idx:,} / {max_records:,} ({elapsed:.1f}с)")

                rec = _mft_read_record(disk, runs, cluster_size, mft_start, idx)
                if not rec:
                    continue

                total_records += 1
                info = _mft_parse_attrs(rec)

                # Пропускаем каталоги
                if info['is_directory']:
                    continue

                # Пропускаем файлы, которые НЕ удалены (bit 0 = 1 значит "in use")
                if info['flags'] & 0x0001:
                    continue

                deleted_files += 1

                # Проверяем время удаления (MFT modification time)
                del_time = info['mft_modification_time']
                if del_time and del_time != dt.datetime.min:
                    if del_time.timestamp() < cutoff:
                        continue
                else:
                    continue

                # Получаем имя файла
                fname = _mft_pick_best_name(info['names'])
                if not fname:
                    continue

                # Только исполняемые файлы
                if not EXEC_RE.search(fname):
                    continue

                executable_deleted += 1

                # Whitelist по имени
                if is_name_whitelisted(fname):
                    continue

                # === Восстанавливаем полный путь ===
                path_parts = []
                curr = info['parent_idx']
                visited = set()
                while curr and curr != 5 and curr not in visited and len(visited) < 30:
                    visited.add(curr)
                    parent_rec = _mft_read_record(disk, runs, cluster_size, mft_start, curr)
                    if not parent_rec:
                        path_parts.insert(0, f"Unknown_MFT_{curr}")
                        break
                    parent_info = _mft_parse_attrs(parent_rec)
                    parent_name = _mft_pick_best_name(parent_info['names'])
                    if parent_name:
                        path_parts.insert(0, parent_name)
                    else:
                        path_parts.insert(0, f"Unknown_MFT_{curr}")
                        break
                    curr = parent_info['parent_idx']

                full_path = _mft_resolve_path(drive, path_parts + [fname]) if path_parts else f"{drive}:\\{fname}"
                folder_path = os.path.dirname(full_path) + "\\" if path_parts else f"{drive}:\\"

                # Whitelist по пути
                if is_path_whitelisted(full_path):
                    continue

                # === Анализ на читы ===
                hit = _check_stop_words(fname) or _check_stop_words(full_path)
                flags = []
                if hit:
                    flags.append(f"STOPWORD:{hit}")
                if _is_random_name(fname):
                    flags.append("RANDOM-NAME")

                category = "CHEAT" if hit else "UNKNOWN"

                # Форматирование размера
                size = info['real_size']
                size_str = f"{size:,} байт" if size > 0 else "N/A"

                # Форматирование времён
                created_str = info['creation_time'].strftime('%Y-%m-%d %H:%M:%S') if info['creation_time'] else "N/A"
                deleted_str = del_time.strftime('%Y-%m-%d %H:%M:%S') if del_time else "N/A"

                # === Запись в отчёт ===
                findings.append((fname, full_path, category, flags, size, del_time))

                report.section(f"УДАЛЁННЫЙ ФАЙЛ [{category}]")
                report.lines.append("[!] Найдена удаленная запись в MFT:")
                report.lines.append(f"    Имя файла:  {fname}")
                report.lines.append(f"    Размер:     {size_str}")
                report.lines.append(f"    Папка:      {folder_path}")
                report.lines.append(f"    Создан:     {created_str}")
                report.lines.append(f"    Удален:     {deleted_str}")
                if flags:
                    report.lines.append(f"    Флаги:      {', '.join(flags)}")
                report.lines.append("")

    except PermissionError:
        report.event("ЗАБЛОКИРОВАНО", "MFT: PermissionError (нужны права администратора)")
    except FileNotFoundError:
        report.event("ОШИБКА", f"MFT: диск {drive}: не найден")
    except OSError as e:
        report.event("ОШИБКА", f"MFT: ошибка доступа к диску — {e}")
    except Exception as e:
        report.event("ОШИБКА", f"MFT: {e}")
        import traceback
        traceback.print_exc()

    # === Итоговая статистика ===
    elapsed = time.time() - start_time
    report.event(
        "MFT-СТАТИСТИКА",
        f"Записей обработано: {total_records:,} | "
        f"Удалённых файлов всего: {deleted_files:,} | "
        f"Удалённых EXE: {executable_deleted} | "
        f"Совпадений: {len(findings)} | "
        f"Время: {elapsed:.1f}с"
    )

    return findings

# ============================================================================
# МОДУЛЬ: WINDOWS DEFENDER (включая Core Isolation и Device Security)
# ============================================================================

def scan_defender(report: ReportBuffer) -> list:
    """
    Проверяет состояние компонентов Windows Defender через WMI и реестр.
    Включает проверку:
    - Основные компоненты защиты (Real-Time, Behavior Monitor и т.д.)
    - Изоляция ядра (Core Isolation / Memory Integrity)
    - Безопасность устройства (Secure Boot, TPM, VBS, DMA Guard)
    Выводит в отчёт, какие защиты отключены.
    """
    findings = []

    script = """
    try {
        # === ОСНОВНЫЕ КОМПОНЕНТЫ DEFENDER ===
        $av = Get-CimInstance -Namespace root/Microsoft/Windows/Defender -ClassName MSFT_MpComputerStatus -ErrorAction SilentlyContinue
        if ($av) {
            Write-Output "RealTimeProtection=$($av.RealTimeProtectionEnabled)"
            Write-Output "AntivirusEnabled=$($av.AntivirusEnabled)"
            Write-Output "BehaviorMonitor=$($av.BehaviorMonitorEnabled)"
            Write-Output "OnAccessProtection=$($av.OnAccessProtectionEnabled)"
            Write-Output "Antispyware=$($av.AntispywareEnabled)"
            Write-Output "NisRealTimeProtection=$($av.NisRealTimeProtectionEnabled)"
            Write-Output "TamperProtection=$($av.TamperProtection)"
        } else {
            $sc = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
            if ($sc) {
                foreach ($p in $sc) {
                    Write-Output "Product=$($p.displayName)"
                    Write-Output "State=$($p.productState)"
                }
            } else {
                Write-Output "ERROR=NO_DEFENDER_DATA"
            }
        }

        # === ИЗОЛЯЦИЯ ЯДРА (CORE ISOLATION / MEMORY INTEGRITY) ===
        try {
            $hvci = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity" -ErrorAction SilentlyContinue
            if ($hvci) {
                Write-Output "CoreIsolation=$($hvci.Enabled)"
                Write-Output "CoreIsolationChangedInBoot=$($hvci.ChangedInBoot)"
            } else {
                Write-Output "CoreIsolation=UNKNOWN"
            }
        } catch {
            Write-Output "CoreIsolation=ERROR"
        }

        # === БЕЗОПАСНОСТЬ УСТРОЙСТВА ===
        
        # Secure Boot
        try {
            $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
            if ($secureBoot -eq $true) {
                Write-Output "SecureBoot=ENABLED"
            } elseif ($secureBoot -eq $false) {
                Write-Output "SecureBoot=DISABLED"
            } else {
                Write-Output "SecureBoot=NOT_SUPPORTED"
            }
        } catch {
            Write-Output "SecureBoot=ERROR"
        }

        # TPM (Trusted Platform Module)
        try {
            $tpm = Get-Tpm -ErrorAction SilentlyContinue
            if ($tpm) {
                Write-Output "TPMPresent=$($tpm.TpmPresent)"
                Write-Output "TPMReady=$($tpm.TpmReady)"
                Write-Output "TPMEnabled=$($tpm.TpmEnabled)"
                Write-Output "TPMActivated=$($tpm.TpmActivated)"
                Write-Output "TPMVersion=$($tpm.ManufacturerVersion)"
            } else {
                Write-Output "TPM=NOT_FOUND"
            }
        } catch {
            Write-Output "TPM=ERROR"
        }

        # VBS (Virtualization-Based Security)
        try {
            $dg = Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
            if ($dg) {
                Write-Output "VBSRunning=$($dg.VirtualizationBasedSecurityStatus)"
                Write-Output "CodeIntegrityEnforced=$($dg.CodeIntegrityPolicyEnforcementStatus)"
                Write-Output "CredentialGuard=$($dg.SecurityServicesRunning -contains 1)"
                Write-Output "HypervisorEnforcedCodeIntegrity=$($dg.SecurityServicesRunning -contains 2)"
            } else {
                Write-Output "VBS=NOT_SUPPORTED"
            }
        } catch {
            Write-Output "VBS=ERROR"
        }

        # DMA Guard
        try {
            $dmaGuard = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\FVE" -Name "EnableExternalDMAUnderLock" -ErrorAction SilentlyContinue
            if ($dmaGuard) {
                Write-Output "DMAGuard=$($dmaGuard.EnableExternalDMAUnderLock)"
            } else {
                Write-Output "DMAGuard=NOT_CONFIGURED"
            }
        } catch {
            Write-Output "DMAGuard=ERROR"
        }

        # System Guard
        try {
            $sg = Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\SystemGuard" -ErrorAction SilentlyContinue
            if ($sg) {
                Write-Output "SystemGuard=$($sg.Enabled)"
            } else {
                Write-Output "SystemGuard=UNKNOWN"
            }
        } catch {
            Write-Output "SystemGuard=ERROR"
        }

    } catch {
        Write-Output "ERROR=$($_.Exception.Message)"
    }
    """

    out = _run_powershell(script, timeout=45)
    if not out:
        report.event("ОШИБКА", "Defender: PowerShell недоступен")
        return findings

    defender_status = {}
    for line in out.strip().splitlines():
        line = line.strip()
        if '=' in line:
            key, val = line.split('=', 1)
            defender_status[key.strip()] = val.strip()

    if 'ERROR' in defender_status:
        report.event("ОШИБКА", f"Defender: {defender_status['ERROR']}")
        return findings

    # ========================================================================
    # ПРОВЕРКА ОСНОВНЫХ КОМПОНЕНТОВ DEFENDER
    # ========================================================================
    checks = {
        'RealTimeProtection': 'Защита в реальном времени',
        'AntivirusEnabled': 'Антивирус',
        'BehaviorMonitor': 'Мониторинг поведения',
        'OnAccessProtection': 'Защита при доступе к файлам',
        'Antispyware': 'Антишпион',
        'NisRealTimeProtection': 'Сетевая защита (NIS)',
        'TamperProtection': 'Защита от несанкционированного вмешательства',
    }

    disabled_components = []
    for key, name in checks.items():
        val = defender_status.get(key, '').lower()
        if val in ('false', '0', 'disabled', 'off'):
            disabled_components.append(name)
            report.event("DEFENDER-OFF", f"{name}: ОТКЛЮЧЕНА")
            findings.append((key, name, False))
        elif val in ('true', '1', 'enabled', 'on'):
            report.event("DEFENDER-OK", f"{name}: Включена")
            findings.append((key, name, True))
        else:
            report.event("DEFENDER-UNKNOWN", f"{name}: Статус не определён ({val})")

    # ========================================================================
    # ПРОВЕРКА ИЗОЛЯЦИИ ЯДРА (CORE ISOLATION)
    # ========================================================================
    core_isolation_val = defender_status.get('CoreIsolation', 'UNKNOWN').lower()
    if core_isolation_val in ('1', 'true'):
        report.event("CORE-ISOLATION-OK", "Изоляция ядра (Memory Integrity): ВКЛЮЧЕНА")
        findings.append(('CoreIsolation', 'Изоляция ядра', True))
    elif core_isolation_val in ('0', 'false'):
        report.event("CORE-ISOLATION-OFF", "Изоляция ядра (Memory Integrity): ОТКЛЮЧЕНА")
        disabled_components.append("Изоляция ядра (Memory Integrity)")
        findings.append(('CoreIsolation', 'Изоляция ядра', False))
    else:
        report.event("CORE-ISOLATION-UNKNOWN", f"Изоляция ядра: Статус не определён ({core_isolation_val})")

    # ========================================================================
    # ПРОВЕРКА БЕЗОПАСНОСТИ УСТРОЙСТВА
    # ========================================================================
    
    # Secure Boot
    secure_boot_val = defender_status.get('SecureBoot', 'ERROR').upper()
    if secure_boot_val == 'ENABLED':
        report.event("SECURE-BOOT-OK", "Secure Boot: ВКЛЮЧЕН")
        findings.append(('SecureBoot', 'Secure Boot', True))
    elif secure_boot_val == 'DISABLED':
        report.event("SECURE-BOOT-OFF", "Secure Boot: ОТКЛЮЧЕН")
        disabled_components.append("Secure Boot")
        findings.append(('SecureBoot', 'Secure Boot', False))
    elif secure_boot_val == 'NOT_SUPPORTED':
        report.event("SECURE-BOOT-NOT-SUPPORTED", "Secure Boot: Не поддерживается (Legacy BIOS?)")
        disabled_components.append("Secure Boot (не поддерживается)")
    else:
        report.event("SECURE-BOOT-ERROR", f"Secure Boot: Ошибка проверки ({secure_boot_val})")

    # TPM
    tpm_present = defender_status.get('TPMPresent', 'NOT_FOUND').lower()
    tpm_ready = defender_status.get('TPMReady', 'false').lower()
    tpm_enabled = defender_status.get('TPMEnabled', 'false').lower()
    tpm_version = defender_status.get('TPMVersion', 'N/A')

    if tpm_present in ('true', '1'):
        if tpm_ready in ('true', '1') and tpm_enabled in ('true', '1'):
            report.event("TPM-OK", f"TPM: Присутствует и активен (версия {tpm_version})")
            findings.append(('TPM', 'TPM', True))
        else:
            report.event("TPM-PARTIAL", f"TPM: Присутствует, но не готов/не активен")
            disabled_components.append("TPM (не активен)")
            findings.append(('TPM', 'TPM', False))
    else:
        report.event("TPM-MISSING", "TPM: Не обнаружен")
        disabled_components.append("TPM (отсутствует)")
        findings.append(('TPM', 'TPM', False))

    # VBS
    vbs_val = defender_status.get('VBSRunning', 'NOT_SUPPORTED').lower()
    if vbs_val in ('1', 'true', 'running'):
        report.event("VBS-OK", "VBS (Virtualization-Based Security): ВКЛЮЧЕНА")
        findings.append(('VBS', 'VBS', True))
    elif vbs_val in ('0', 'false', 'not_running'):
        report.event("VBS-OFF", "VBS (Virtualization-Based Security): ОТКЛЮЧЕНА")
        disabled_components.append("VBS")
        findings.append(('VBS', 'VBS', False))
    elif vbs_val == 'not_supported':
        report.event("VBS-NOT-SUPPORTED", "VBS: Не поддерживается")
        disabled_components.append("VBS (не поддерживается)")
    else:
        report.event("VBS-UNKNOWN", f"VBS: Статус не определён ({vbs_val})")

    # DMA Guard
    dma_val = defender_status.get('DMAGuard', 'NOT_CONFIGURED').lower()
    if dma_val in ('1', 'true'):
        report.event("DMA-GUARD-OK", "DMA Guard: ВКЛЮЧЕНА")
        findings.append(('DMAGuard', 'DMA Guard', True))
    elif dma_val in ('0', 'false'):
        report.event("DMA-GUARD-OFF", "DMA Guard: ОТКЛЮЧЕНА")
        disabled_components.append("DMA Guard")
        findings.append(('DMAGuard', 'DMA Guard', False))
    else:
        report.event("DMA-GUARD-UNKNOWN", f"DMA Guard: {dma_val}")

    # System Guard
    sg_val = defender_status.get('SystemGuard', 'UNKNOWN').lower()
    if sg_val in ('1', 'true'):
        report.event("SYSTEM-GUARD-OK", "System Guard: ВКЛЮЧЕН")
        findings.append(('SystemGuard', 'System Guard', True))
    elif sg_val in ('0', 'false'):
        report.event("SYSTEM-GUARD-OFF", "System Guard: ОТКЛЮЧЕН")
        disabled_components.append("System Guard")
        findings.append(('SystemGuard', 'System Guard', False))
    else:
        report.event("SYSTEM-GUARD-UNKNOWN", f"System Guard: {sg_val}")

    # ========================================================================
    # ИТОГОВЫЙ ОТЧЁТ ПО ОТКЛЮЧЁННЫМ КОМПОНЕНТАМ
    # ========================================================================
    if disabled_components:
        report.section("КРИТИЧНО: ОТКЛЮЧЁННЫЕ КОМПОНЕНТЫ ЗАЩИТЫ")
        report.lines.append("[!] Обнаружены отключённые или недоступные компоненты:")
        for comp in disabled_components:
            report.lines.append(f"    • {comp}")
        report.lines.append("")
        report.lines.append("    Это может указывать на:")
        report.lines.append("    1. Намеренное отключение защиты читером")
        report.lines.append("    2. Несовместимость с оборудованием (Legacy BIOS, нет TPM)")
        report.lines.append("    3. Использование виртуальной машины")
        report.lines.append("")

    # Вывод информации о продукте (если есть)
    if 'Product' in defender_status:
        report.info(f"Антивирусный продукт: {defender_status['Product']}")
    if 'State' in defender_status:
        state_code = int(defender_status['State']) if defender_status['State'].isdigit() else 0
        state = _decode_av_state(state_code)
        report.info(f"Статус антивируса: {state}")

    return findings

# ============================================================================
# МОДУЛЬ: БРАУЗЕРЫ (только совпадения, БЕЗ полной истории)
# ============================================================================

def _query_chromium_matches(db_path: str, cutoff_ts: int) -> list:
    """
    Запрашивает из Chromium-истории записи и категоризирует их.
    Полная выборка не формируется и не удерживается в памяти дольше одной строки курсора.
    """
    results = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT u.url, u.title, u.last_visit_time
                FROM urls u
                WHERE u.last_visit_time >= ?
                LIMIT 50000
            """, (cutoff_ts,))
            for url, title, ts in cur.fetchall():
                category = _is_cheat_related(url, title or '')
                if category:  # Если не None (т.е. сайт НЕ в whitelist)
                    results.append((url, title or '', _chrome_ts_to_dt(ts), category))
        except sqlite3.OperationalError:
            pass
        conn.close()
    except sqlite3.DatabaseError:
        pass
    return results

def _find_firefox_profiles() -> list:
    profiles = []
    ff_dir = os.path.join(os.environ.get('APPDATA', ''), 'Mozilla', 'Firefox', 'Profiles')
    if not os.path.isdir(ff_dir):
        return profiles
    try:
        for entry in os.listdir(ff_dir):
            places = os.path.join(ff_dir, entry, 'places.sqlite')
            if os.path.isfile(places):
                profiles.append(places)
    except PermissionError:
        pass
    return profiles


def _query_firefox_matches(db_path: str, cutoff_pr: int) -> list:
    results = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT p.url, p.title, p.last_visit_date
                FROM moz_places p
                WHERE p.last_visit_date >= ? AND p.url IS NOT NULL
                LIMIT 50000
            """, (cutoff_pr,))
            for url, title, pr_ts in cur.fetchall():
                category = _is_cheat_related(url, title or '')
                if category:  # Если не None (т.е. сайт НЕ в whitelist)
                    try:
                        ts = dt.datetime.utcfromtimestamp(pr_ts / 1_000_000)
                    except Exception:
                        ts = dt.datetime.min
                    results.append((url, title or '', ts, category))
        except sqlite3.OperationalError:
            pass
        conn.close()
    except sqlite3.DatabaseError:
        pass
    return results


def _is_google_ai_mode(url: str, host: str) -> bool:
    """
    Google "Режим ИИ" (AI Mode, параметр udm=50) вставляет в URL произвольный
    текст запроса пользователя целиком — это может быть длинный свободный
    текст (вопрос, просьба перевести что-то и т.д.), а не точечный поиск
    конкретного чита. Чем длиннее свободный текст, тем выше шанс случайного
    совпадения со словом из базы читов безо всякой связи с читерством.
    Поэтому такие запросы не сверяются по ключевым словам — только обычный
    поиск Google (без udm=50) и прямые визиты на чит-сайты.
    """
    if 'google.' not in host:
        return False
    try:
        query = parse_qs(urlparse(url).query)
    except Exception:
        return False
    return query.get('udm', [''])[0] == '50'


def _is_cheat_related(url: str, title: str) -> Optional[str]:
    """
    Категоризирует URL истории браузера.
    Returns:
        None           -> сайт в whitelist (пропускаем, не добавляем в отчет)
        "CHEAT-SITE"   -> совпадение с базой читов/спуферов
        "UNKNOWN-SITE" -> не найден ни в whitelist, ни в базе читов (подозрительный)
    """
    url_l = url.lower()
    try:
        host = (urlparse(url).hostname or '').lower()
    except Exception:
        host = ''

    # 1. Проверяем whitelist (если найден — сразу пропускаем)
    if is_domain_whitelisted(url):
        return None

    # 2. Проверяем базу читов (домены)
    if host and any(host == d or host.endswith('.' + d) for d in CHEAT_SITE_DOMAINS):
        return "CHEAT-SITE"
    
    # 3. Проверяем базу читов (фрагменты URL, например funpay.com/lots/...)
    if any(frag in url_l for frag in CHEAT_SITE_URL_FRAGMENTS):
        return "CHEAT-SITE"

    # 4. Игнорируем Google AI Mode (udm=50), так как там много случайного мусора в URL
    if _is_google_ai_mode(url, host):
        return None

    # 5. Проверяем ключевые слова в заголовке страницы
    if _CHEAT_TITLE_RE.search(title):
        return "CHEAT-SITE"

    # 6. Проверяем ключевые слова в URL (только слова длиннее 3 символов, чтобы избежать ложных срабатываний)
    if any(pattern.search(url_l) for word, pattern in _STOPWORD_PATTERNS if len(word) > 3):
        return "CHEAT-SITE"

    # 7. Если ничего не совпало, но сайт и не в whitelist — помечаем как неизвестный
    return "UNKNOWN-SITE"


def scan_browsers(report: ReportBuffer) -> dict:
    """
    Сканирует историю браузеров и возвращает записи, категоризированные как
    CHEAT-SITE или UNKNOWN-SITE. Записи, попавшие в whitelist, игнорируются.
    """
    now = time.time()
    cutoff_chromium = int((now - SEVEN_DAYS_SEC + 11644473600) * 1_000_000)
    cutoff_firefox = int((now - SEVEN_DAYS_SEC) * 1_000_000)

    localappdata = os.environ.get('LOCALAPPDATA', '')
    appdata = os.environ.get('APPDATA', '')

    matches: Dict[str, list] = {}

    for browser, path_parts in BROWSERS_CHROMIUM.items():
        for base in (localappdata, appdata):
            if not base:
                continue
            hist_path = os.path.join(base, *path_parts, 'Default', 'History')
            if not os.path.isfile(hist_path):
                ud = os.path.join(base, *path_parts)
                if not os.path.isdir(ud):
                    continue
                hist_path = None
                for profile in os.listdir(ud):
                    candidate = os.path.join(ud, profile, 'History')
                    if os.path.isfile(candidate):
                        hist_path = candidate
                        break
                if not hist_path:
                    continue

            tmp = _copy_locked_file(hist_path)
            if not tmp:
                continue
            try:
                rows = _query_chromium_matches(tmp, cutoff_chromium)
                for url, title, ts, category in rows:
                    matches.setdefault(browser, []).append((url, title, ts, category))
                    report.event(f"BROWSER-{category}", f"[{browser}] {url} | title='{title}'", ts)
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass

    for places_path in _find_firefox_profiles():
        tmp = _copy_locked_file(places_path)
        if not tmp:
            continue
        try:
            rows = _query_firefox_matches(tmp, cutoff_firefox)
            for url, title, ts, category in rows:
                matches.setdefault('Firefox', []).append((url, title, ts, category))
                report.event(f"BROWSER-{category}", f"[Firefox] {url} | title='{title}'", ts)
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass

    return matches

# ============================================================================
# МОДУЛЬ: EVENT LOGS
# ============================================================================

# ============================================================================
# МОДУЛЬ: EVENT LOGS (через win32evtlog — надёжнее чем wevtutil)
# ============================================================================

def scan_event_logs(report: ReportBuffer) -> list:
    """
    Читает журналы Windows через win32evtlog:
      - System, Security, Application
      - Считает события за 7 дней
      - Ищет конкретные EventID:
          1102 — очистка журнала (LOG_CLEARED)
          7045 — создание новой службы
          4697 — альтернативное создание службы
          1000, 1001 — краши приложений
    """
    try:
        import win32evtlog
    except ImportError:
        report.event("ОШИБКА", "win32evtlog не установлен (pip install pywin32)")
        return []

    days = 7
    cutoff_date = dt.datetime.now() - dt.timedelta(days=days)
    
    logs = ["System", "Security", "Application"]
    total_events = 0
    all_events = []

    # Целевые события
    target_event_ids = {1102, 7045, 4697, 1000, 1001}
    event_labels = {
        1102: "LOG_CLEARED",
        7045: "NEW_SERVICE",
        4697: "NEW_SERVICE_ALT",
        1000: "APP_CRASH",
        1001: "APP_CRASH_BUGCHECK",
    }

    for log_type in logs:
        try:
            hand = win32evtlog.OpenEventLog(None, log_type)
            # Читаем с конца (самые свежие события первыми)
            flags = (
                win32evtlog.EVENTLOG_BACKWARDS_READ
                | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            )

            count_total = 0
            count_target = 0
            keep_reading = True

            while keep_reading:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break

                for event in events:
                    # Останавливаемся, когда вышли за 7 дней
                    if event.TimeGenerated < cutoff_date:
                        keep_reading = False
                        break
                    
                    count_total += 1
                    eid = event.EventID & 0xFFFF  # маска для EventID
                    
                    if eid in target_event_ids:
                        count_target += 1
                        label = event_labels[eid]
                        ts = event.TimeGenerated
                        # Пытаемся получить строковое описание
                        try:
                            strings = event.StringInserts if event.StringInserts else []
                            data_str = " | ".join(str(s) for s in strings[:3]) if strings else ""
                        except Exception:
                            data_str = ""
                        
                        all_events.append((eid, label, ts, data_str))
                        report.event(label, f"EventID={eid} src={log_type} | {data_str}")

            if count_total == 0:
                report.event("EVENT-LOG-EMPTY", f"{log_type}: событий не найдено за {days} дней")
            else:
                report.event("EVENT-LOG-OK", f"{log_type}: {count_total} событий за {days} дней, из них {count_target} целевых")
            
            total_events += count_total
            win32evtlog.CloseEventLog(hand)

        except Exception as e:
            report.event("EVENT-LOG-ERROR", f"{log_type}: {e}")

    report.event("EVENT-LOGS-STATS", f"Проверено журналов: {len(logs)}, всего событий: {total_events}")
    return all_events


# ============================================================================
# МОДУЛЬ: DEEP SCAN
# ============================================================================


def scan_deep(report: ReportBuffer) -> list:
    """Сканирует TEMP и Downloads. С диагностикой."""
    cutoff = time.time() - THREE_DAYS_SEC
    findings = []
    
    TARGET_DIRS = [
        os.environ.get('TEMP', ''),
        os.path.expanduser('~\\Downloads'),
    ]

    SKIP_DIRS = {
        'node_modules', 'python', 'windowsapps', 'microsoft edge',
        'cache', 'venv', '.git', '__pycache__', 'site-packages',
        'google', 'chrome', 'firefox', 'opera', 'brave', 'vivaldi',
        'steam', 'epic games', 'origin', 'ubisoft', 'battle.net',
        'discord', 'telegram', 'whatsapp', 'zoom', 'teams',
        'microsoft', 'windows', 'packages', 'crashdumps',
        'd3dscache', 'pip', 'npm-cache', 'yarn', 'nuget',
        'jetbrains', 'visualstudio', 'code', 'unity', 'unreal engine',
        'adobe', 'autodesk', 'blender', 'gimp', 'inkscape',
        'nvidia corporation', 'amd', 'intel', 'realtek',
    }

    MAX_FILES_TO_CHECK = 15000
    files_checked = 0
    dirs_checked = 0

    for root_dir in TARGET_DIRS:
        if not root_dir or not os.path.isdir(root_dir):
            report.event("DEEP-SCAN-SKIP", f"Папка не существует: {root_dir}")
            continue
        try:
            for dirpath, dirnames, filenames in os.walk(root_dir, followlinks=False):
                dirs_checked += 1
                dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
                
                for fname in filenames:
                    if files_checked >= MAX_FILES_TO_CHECK:
                        report.event("ЛИМИТ", f"Deep Scan прерван по лимиту ({MAX_FILES_TO_CHECK} файлов)")
                        report.event("DEEP-SCAN-STATS", f"Папок: {dirs_checked}, файлов проверено: {files_checked}, найдено: {len(findings)}")
                        return findings
                    
                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in EXECUTABLE_EXTS:
                        continue
                    
                    files_checked += 1
                    full = os.path.join(dirpath, fname)
                    
                    if is_path_whitelisted(full):
                        continue
                    
                    try:
                        st = os.stat(full)
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
                    
                    if st.st_mtime < cutoff and st.st_ctime < cutoff:
                        continue
                    
                    flags = []
                    hit = _check_stop_words(fname)
                    if hit:
                        flags.append(f'STOPWORD:{hit}')
                    
                    if _is_random_name(fname):
                        flags.append('RANDOM-NAME')
                    
                    if 0 < st.st_size < 10 * 1024:
                        flags.append(f'SUSPECT-SIZE({st.st_size}B)')
                    
                    if st.st_size == 0:
                        flags.append('ZERO-BYTE')
                    
                    if flags:
                        findings.append((full, st.st_mtime, st.st_size, flags))
                        report.event("DEEP-SCAN", f"{full} | flags={','.join(flags)}")
                        
        except PermissionError:
            pass
        except Exception:
            pass

    report.event("DEEP-SCAN-STATS", f"Папок: {dirs_checked}, файлов проверено: {files_checked}, найдено: {len(findings)}")
    return findings

# ============================================================================
# МОДУЛЬ: STEAM (только SteamID/имя/время входа — БЕЗ .maFile)
# ============================================================================

def _find_vdf(name: str) -> Optional[str]:
    for base in STEAM_CONFIG_PATHS:
        p = os.path.join(base, name)
        if os.path.isfile(p):
            return p
    return None


def _parse_vdf_simple(text: str) -> dict:
    stack = [{}]
    tokens = re.findall(r'"([^"]*)"|(\{|\})', text)
    key_pending = None
    for quoted, brace in tokens:
        if brace == '{':
            new = {}
            if key_pending is not None:
                stack[-1][key_pending] = new
                key_pending = None
            stack.append(new)
        elif brace == '}':
            if len(stack) > 1:
                stack.pop()
        elif quoted:
            if key_pending is None:
                key_pending = quoted
            else:
                stack[-1][key_pending] = quoted
                key_pending = None
    return stack[0]


# ============================================================================
# МОДУЛЬ: STEAM (поиск аккаунтов + проверка банов)
# ============================================================================

# Типы банов, которые нас интересуют
BAN_TYPES = {
    'vac bans': 'VAC бан',
    'game bans': 'Игровой бан',
    'community ban': 'Бан сообщества',
    'trade ban': 'Бан торговли',
}


def _check_steam_bans(report: ReportBuffer, accounts: list) -> None:
    """Проверка Steam аккаунтов на баны. Выводит ТОЛЬКО типы банов."""
    try:
        import requests
        from bs4 import BeautifulSoup
    except ImportError:
        report.event("ОШИБКА", "Отсутствуют библиотеки 'requests' или 'beautifulsoup4'")
        return

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }

    for acc in accounts:
        steam_id = str(acc.get('steamid64', '')).strip()
        name = acc.get('personaname', 'Unknown')
        
        if not steam_id or len(steam_id) < 10:
            continue

        report.event("STEAM-CHECK", f"Проверка аккаунта: {name} ({steam_id})")
        
        try:
            url = f'https://steamid.pro/lookup/{steam_id}'
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code != 200:
                report.event("STEAM-ERROR", f"HTTP {response.status_code} для {steam_id}")
                continue
            
            soup = BeautifulSoup(response.text, 'html.parser')
            bans_found = False
            
            ban_elements = soup.find_all('td', class_='span2')
            if not ban_elements:
                ban_elements = soup.find_all('td')

            for element in ban_elements:
                ban_name = element.get_text(strip=True)
                ban_name_lower = ban_name.lower()
                
                # Фильтруем только нужные типы банов
                matched_type = None
                for key, label in BAN_TYPES.items():
                    if key in ban_name_lower:
                        matched_type = label
                        break
                
                if not matched_type:
                    continue  # Пропускаем Vanity URL, AccountID, игровое время и т.д.
                
                status_element = element.find_next_sibling('td')
                if status_element:
                    ban_status = status_element.get_text(strip=True)
                    
                    # Особое внимание на активные баны
                    if ban_status.lower() in ['none', '0', 'no', 'нет', '-']:
                        ban_status = "Отсутствует"
                    
                    # Если есть активный бан — помечаем критично
                    is_banned = any(word in ban_status.lower() for word in ['ban', 'бан', 'day', 'дн'])
                    
                    if is_banned:
                        report.event("🚨 STEAM-BANNED", f"[{name}] {matched_type}: {ban_status}")
                    else:
                        report.event("STEAM-CLEAN", f"[{name}] {matched_type}: {ban_status}")
                    
                    bans_found = True
            
            if not bans_found:
                report.event("STEAM-OK", f"Аккаунт {name}: данные о банах не найдены")
                
        except requests.exceptions.Timeout:
            report.event("STEAM-ERROR", f"Таймаут для {steam_id}")
        except requests.exceptions.RequestException as e:
            report.event("STEAM-ERROR", f"Сеть: {e}")
        except Exception as e:
            report.event("STEAM-ERROR", f"Парсинг: {e}")

def scan_steam(report: ReportBuffer) -> dict:
    """
    Читает loginusers.vdf: SteamID64, отображаемое имя, время последнего входа.
    Сразу после нахождения аккаунтов запускает проверку на баны через steamid.pro.
    .maFile НЕ ищутся и не читаются.
    """
    result = {'accounts': []}
    
    # Поиск файла loginusers.vdf
    vdf_path = None
    for base in [r'C:\Program Files (x86)\Steam\config', r'C:\Program Files\Steam\config']:
        candidate = os.path.join(base, 'loginusers.vdf')
        if os.path.isfile(candidate):
            vdf_path = candidate
            break

    if not vdf_path:
        report.event("ПРОПУЩЕНО", "loginusers.vdf не найден (Steam не установлен или не запускался)")
        return result

    try:
        with open(vdf_path, 'r', encoding='utf-8', errors='ignore') as f:
            data = _parse_vdf_simple(f.read())
        
        users = data.get('users', {})
        for steam_id, info in users.items():
            if not isinstance(info, dict):
                continue
            result['accounts'].append({
                'steamid64': steam_id,
                'personaname': info.get('Personaname', 'Unknown'),
                'last_login': info.get('LastLoginTime', '0'),
            })
        
        # Сортируем по времени последнего входа (сначала новые)
        result['accounts'].sort(key=lambda a: int(a['last_login'] or 0), reverse=True)
        
        for acc in result['accounts']:
            report.event("STEAM-ACCOUNT", f"Найден аккаунт: {acc['personaname']} (ID: {acc['steamid64']})")
            
        # === ЗАПУСК ПРОВЕРКИ БАНОВ ===
        if result['accounts']:
            report.section("ПРОВЕРКА БАНОВ STEAM (steamid.pro)")
            _check_steam_bans(report, result['accounts'])
            
    except Exception as e:
        report.event("ОШИБКА", f"Чтение loginusers.vdf: {e}")

    return result


# ============================================================================
# МОДУЛЬ: ПРОЦЕССЫ
# ============================================================================

def _run_powershell(script: str, timeout: int = 30) -> Optional[str]:
    """Запускает PowerShell-команду, возвращает stdout или None при ошибке/таймауте."""
    try:
        proc = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-Command', script],
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout,
        )
        if proc.returncode != 0:
            return None
        return proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def _list_processes_wmic() -> Optional[List[Tuple[str, str, str]]]:
    """Возвращает [(name, exec_path, pid), ...] через wmic, либо None если wmic недоступен."""
    try:
        proc = subprocess.run(
            ['wmic', 'process', 'get', 'Name,ExecutablePath,ProcessId', '/format:csv'],
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0:
        return None

    rows = []
    reader = csv.reader(io.StringIO(proc.stdout))
    next(reader, None)
    for row in reader:
        if len(row) < 4:
            continue
        rows.append((row[2].strip(), row[1].strip(), row[3].strip()))
    return rows


def _list_processes_powershell() -> Optional[List[Tuple[str, str, str]]]:
    """Фоллбэк для систем без wmic.exe (убран в современных сборках Windows):
    тот же список процессов через Get-CimInstance Win32_Process."""
    script = (
        "Get-CimInstance Win32_Process | "
        "Select-Object Name,ExecutablePath,ProcessId | "
        "ForEach-Object { \"$($_.Name)|$($_.ExecutablePath)|$($_.ProcessId)\" }"
    )
    out = _run_powershell(script)
    if out is None:
        return None
    rows = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split('|')
        if len(parts) != 3:
            continue
        name, exec_path, pid = parts
        rows.append((name.strip(), exec_path.strip(), pid.strip()))
    return rows


def scan_processes(report: ReportBuffer) -> list:
    """Список запущенных процессов сверяется со стоп-словами в имени/пути.
    Сначала пробует wmic (может отсутствовать на новых сборках Windows),
    при неудаче — PowerShell Get-CimInstance."""
    findings = []

    rows = _list_processes_wmic()
    source = "wmic"
    if rows is None:
        rows = _list_processes_powershell()
        source = "powershell"
    if rows is None:
        report.event("ОШИБКА", "Процессы: недоступны ни wmic, ни PowerShell")
        return findings

    for name, exec_path, pid in rows:
        if not name or is_name_whitelisted(name):
            continue

        hit = _check_stop_words(name) or _check_stop_words(exec_path)
        if hit:
            findings.append((name, exec_path, pid, hit))
            report.event("PROCESS-TRIGGER", f"PID={pid} | {name} | path='{exec_path}' | match='{hit}'")
        if exec_path and _is_suspicious_path(exec_path) and _is_random_name(name):
            findings.append((name, exec_path, pid, "SUSPICIOUS"))
            report.event("PROCESS-SUSPICIOUS", f"PID={pid} | {name} | path='{exec_path}'")

    if source == "powershell":
        report.event("INFO", "Процессы получены через PowerShell (wmic недоступен в этой сборке Windows)")

    return findings


# ============================================================================
# МОДУЛЬ: АВТОЗАГРУЗКА
# ============================================================================

def scan_autorun(report: ReportBuffer) -> list:
    """Проверяет ключи автозагрузки реестра (Run/RunOnce) на стоп-слова."""
    findings = []
    for hive, path in AUTORUN_KEYS:
        try:
            key = winreg.OpenKey(hive, path)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    i += 1
                except OSError:
                    break
                if is_name_whitelisted(name):
                    continue
                hit = _check_stop_words(name) or _check_stop_words(value)
                if hit:
                    findings.append((name, value, path, hit))
                    report.event("AUTORUN-TRIGGER", f"{name} = '{value}' | key='{path}' | match='{hit}'")
                if _is_suspicious_path(value):
                    findings.append((name, value, path, "SUSPICIOUS-PATH"))
                    report.event("AUTORUN-SUSPICIOUS", f"{name} = '{value}' | key='{path}'")
            winreg.CloseKey(key)
        except (FileNotFoundError, PermissionError):
            pass
        except Exception:
            pass

    return findings


# ============================================================================
# МОДУЛЬ: СЕТЬ
# ============================================================================

def scan_network(report: ReportBuffer) -> list:
    """Список активных TCP-соединений (netstat), кроме локальных адресов."""
    findings = []
    try:
        proc = subprocess.run(['netstat', '-ano', '-p', 'tcp'],
                               capture_output=True, text=True, encoding='utf-8',
                               errors='replace', timeout=30)
        if proc.returncode != 0:
            return findings
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith('Active') or line.startswith('Proto'):
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            proto, local, remote, state, pid = parts[0], parts[1], parts[2], parts[3], parts[4]
            if state != 'ESTABLISHED':
                continue
            if remote.startswith('127.') or remote.startswith('[::1]') or remote.startswith('0.0.0.0'):
                continue
            findings.append((proto, local, remote, state, pid))
            report.event("NETWORK-CONN", f"{proto} {local} -> {remote} [{state}] PID={pid}")
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        report.event("ОШИБКА", f"Сеть: {e}")

    return findings


# ============================================================================
# МОДУЛЬ: АНТИВИРУСЫ
# ============================================================================

def _decode_av_state(state_code: int) -> str:
    if state_code & 0x1000:
        return "ACTIVE"
    elif state_code & 0x2000:
        return "INACTIVE"
    return f"UNKNOWN({state_code})"


def scan_antivirus(report: ReportBuffer) -> list:
    """Список установленных антивирусов через WMI SecurityCenter2.
    Сначала пробует wmic, при недоступности (убран в современных сборках
    Windows) — PowerShell Get-CimInstance с тем же namespace."""
    findings = []

    rows: Optional[List[Tuple[str, int]]] = None
    try:
        proc = subprocess.run(
            ['wmic', '/namespace:\\\\root\\SecurityCenter2', 'path', 'AntiVirusProduct',
             'get', 'displayName,productState', '/format:csv'],
            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30
        )
        if proc.returncode == 0:
            rows = []
            reader = csv.reader(io.StringIO(proc.stdout))
            next(reader, None)
            for row in reader:
                if len(row) < 3:
                    continue
                name = row[1].strip()
                state_raw = row[2].strip()
                if not name:
                    continue
                rows.append((name, int(state_raw) if state_raw.isdigit() else 0))
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        rows = None
    except Exception as e:
        report.event("ОШИБКА", f"Антивирусы (wmic): {e}")
        rows = None

    if rows is None:
        script = (
            "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
            "Select-Object displayName,productState | "
            "ForEach-Object { \"$($_.displayName)|$($_.productState)\" }"
        )
        out = _run_powershell(script)
        if out is not None:
            rows = []
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split('|')
                if len(parts) != 2:
                    continue
                name, state_raw = parts[0].strip(), parts[1].strip()
                if name:
                    rows.append((name, int(state_raw) if state_raw.isdigit() else 0))
            report.event("INFO", "Антивирусы получены через PowerShell (wmic недоступен в этой сборке Windows)")

    if rows is None:
        report.event("ОШИБКА", "Антивирусы: недоступны ни wmic, ни PowerShell")
        return findings

    for name, state_code in rows:
        state = _decode_av_state(state_code)
        findings.append((name, state))
        report.event("ANTIVIRUS", f"{name} | state={state}")

    return findings


# ============================================================================
# АНАЛИЗ АНОМАЛИЙ
# ============================================================================

def evaluate_anomalies(prefetch, bam, deep, events, report: ReportBuffer) -> list:
    """Считает совокупные признаки: много триггеров сразу, новая служба + очистка журнала."""
    anomalies = []
    total_triggers = len(prefetch) + len(bam) + len(deep)
    if total_triggers >= 3:
        anomalies.append(('MULTIPLE-TRIGGERS', total_triggers))
        report.event("АНОМАЛИЯ", f"Суммарно триггеров: {total_triggers}")

    has_new_service = any(e[1] in ('NEW_SERVICE', 'NEW_SERVICE_ALT') for e in events)
    has_log_clear = any(e[1] == 'LOG_CLEARED' for e in events)
    if has_new_service and has_log_clear:
        anomalies.append(('SERVICE-AND-CLEANUP', True))
        report.event("АНОМАЛИЯ", "Новая служба + очистка журнала")

    return anomalies


def detect_sterile(prefetch_empty: bool, log_cleared: bool, report: ReportBuffer) -> bool:
    """Признак намеренной очистки следов: пустой Prefetch + очищенный журнал событий."""
    sterile = prefetch_empty and log_cleared
    if sterile:
        report.event("КРИТИЧНО", "Возможные следы намеренной очистки артефактов")
    return sterile


# ============================================================================
# СПИСОК МОДУЛЕЙ ДЛЯ UI (имя + описание + функция) — используется GUI
# для прогресс-бара и для экрана согласия
# ============================================================================

SCAN_MODULES = [
    ("USN Journal (диск C:)", "scan_usn_journal"),
    ("Prefetch", "scan_prefetch"),
    ("BAM (журнал активности)", "scan_bam"),
    ("Amcache", "scan_amcache"),
    ("История браузеров ", "scan_browsers"),
    ("Журналы событий Windows", "scan_event_logs"),
    ("Глубокое сканирование папок", "scan_deep"),
    ("MFT (удалённые файлы)", "scan_mft"),
    ("Windows Defender", "scan_defender"),
    ("Проверка драйверов ", "scan_drivers"),  # <-- ДОБАВЛЕНО
    ("Steam (SteamID)", "scan_steam"),
    ("Запущенные процессы", "scan_processes"),
    ("Автозагрузка", "scan_autorun"),
    ("Сетевые подключения", "scan_network"),
    ("Антивирусы", "scan_antivirus"),
]