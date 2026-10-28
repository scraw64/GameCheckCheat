#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Загрузчик базы читов/спуферов/площадок из cheat_db.json.

Вынесено в отдельный модуль, чтобы базу можно было пополнять, просто
редактируя cheat_db.json — без пересборки .exe. Если файл не найден
(например, кто-то забыл положить его рядом с .exe), используется
встроенный минимальный fallback-список, чтобы программа не падала.
"""

import json
import os
import sys
from typing import Dict, List

_FALLBACK = {
    "cheat_names": ["cheat", "hack", "aimbot", "wallhack", "inject", "чит"],
    "hwid_spoofer_names": ["hwid spoofer", "hwid changer"],
    "cheat_site_domains": ["funpay.com", "lzt.market", "plati.market"],
    "cheat_site_url_fragments": [],
    "dlc_keywords": ["dlc", "add-on", "addon", "дополнение"],
}


def _app_dir() -> str:
    # Поддержка запуска и из .py, и из собранного PyInstaller .exe
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return meipass
    return os.path.dirname(os.path.abspath(__file__))


def load_cheat_db() -> Dict[str, List[str]]:
    """
    Загружает cheat_db.json рядом со скриптом/exe или из текущей директории.

    Returns:
        dict с ключами cheat_names, hwid_spoofer_names, cheat_site_domains,
        cheat_site_url_fragments, dlc_keywords — все значения в нижнем регистре.
    """
    candidates = [
        os.path.join(_app_dir(), "cheat_db.json"),
        os.path.join(os.getcwd(), "cheat_db.json"),
    ]

    data = None
    for path in candidates:
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                break
            except Exception:
                continue

    if data is None:
        data = _FALLBACK

    result = {}
    for key in ("cheat_names", "hwid_spoofer_names", "cheat_site_domains",
                "cheat_site_url_fragments", "dlc_keywords"):
        values = data.get(key, _FALLBACK.get(key, []))
        result[key] = [str(v).lower().strip() for v in values if str(v).strip()]
    return result
