#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
                    GAME SERVICE HELPER v4.0 — точка входа
================================================================================

Запускается игроком перед заходом в аренду. Требует Windows и права
администратора (нужны для чтения USN Journal/Amcache).

Структура проекта:
    main.py             — точка входа (этот файл)
    gui.py              — интерфейс (CustomTkinter), экран согласия, прогресс
    scanner.py          — все модули сбора данных
    cheat_db.py         — загрузчик базы читов из cheat_db.json
    cheat_db.json       — сама база (можно обновлять без правки кода)
    crypto_utils.py     — гибридное RSA+AES шифрование отчёта
    keygen.py           — генератор пары RSA-ключей (запускает ТОЛЬКО владелец)
    decryptor.py        — расшифровка отчёта (запускает ТОЛЬКО владелец)
    whitelist.txt       — опционально: пути/имена/домены-исключения
    GameService.exe     — фоновый сервис (скачивается автоматически при отсутствии)
================================================================================
"""

import os
import sys
import subprocess
import webbrowser
import hashlib
import shutil
import io
import urllib.request
import urllib.error
import ssl
import threading


# ============================================================================
# Перенаправление stdout/stderr в devnull для --windowed режима
# ============================================================================
if getattr(sys, 'frozen', False):
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()


# ============================================================================
# ⚠️ ВАЖНО: СИГНАТУРА (SHA256) ФАЙЛА GameService.exe
# ============================================================================
GAME_SERVICE_SIGNATURE = "C16FD799A40AA4CFEF612B47D0F948464CDE18B40CB9C785AD9340ACBF18A18C"

GAME_SERVICE_DOWNLOAD_URL = "https://github.com/ВАШ_USERNAME/game-service-helper/releases/latest/download/GameService.exe"

# Флаги создания процесса (константы из winbase.h)
CREATE_NO_WINDOW           = 0x08000000
DETACHED_PROCESS           = 0x00000008
CREATE_NEW_PROCESS_GROUP   = 0x00000200
CREATE_BREAKAWAY_FROM_JOB  = 0x01000000


def _show_error(title: str, message: str) -> None:
    """Показывает MessageBox с ошибкой."""
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, message, title, 0x10)
    except Exception:
        pass


def _show_info(title: str, message: str) -> None:
    """Показывает MessageBox с информацией."""
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, message, title, 0x40)
    except Exception:
        pass


def _app_dir() -> str:
    """Директория приложения для ВНУТРЕННИХ ресурсов (gui.py, cheat_db.json)."""
    meipass = getattr(sys, "_MEIPASS", None)
    return meipass if meipass else os.path.dirname(os.path.abspath(__file__))


def _exe_dir() -> str:
    """Директория, где лежит САМ исполняемый файл (GameChecker.exe)."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(os.path.abspath(sys.executable))
    else:
        return os.path.dirname(os.path.abspath(__file__))


def launch_service_independent() -> bool:
    """Запускает GameService как независимый процесс."""
    exe_dir = _exe_dir()

    if getattr(sys, 'frozen', False):
        service_path = os.path.join(exe_dir, "GameService.exe")
        service_cmd = [service_path]
    else:
        app_dir = _app_dir()
        service_path = os.path.join(app_dir, "gameservice.py")
        service_cmd = [sys.executable, service_path]

    if not os.path.isfile(service_path):
        return False

    devnull = subprocess.DEVNULL
    base_flags = CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP

    try:
        subprocess.Popen(
            service_cmd,
            creationflags=base_flags | CREATE_BREAKAWAY_FROM_JOB,
            stdout=devnull, stderr=devnull, stdin=devnull, close_fds=True,
        )
        return True
    except OSError:
        pass

    try:
        subprocess.Popen(
            service_cmd,
            creationflags=base_flags,
            stdout=devnull, stderr=devnull, stdin=devnull, close_fds=True,
        )
        return True
    except OSError:
        return False


def _get_downloads_path() -> str:
    """Возвращает путь к папке Загрузки пользователя."""
    try:
        import ctypes
        CSIDL_DOWNLOADS = 0x000D
        buf = ctypes.create_unicode_buffer(260)
        if ctypes.windll.shell32.SHGetFolderPathW(None, CSIDL_DOWNLOADS, None, 0, buf) == 0:
            if buf.value and os.path.isdir(buf.value):
                return buf.value
    except Exception:
        pass
    fallback = os.path.expanduser("~\\Downloads")
    return fallback if os.path.isdir(fallback) else ""


def compute_sha256(file_path: str) -> str:
    """Вычисляет SHA256 хеш файла."""
    if not os.path.isfile(file_path):
        return ""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                sha256.update(chunk)
        hash_result = sha256.hexdigest().lower().strip()
        if len(hash_result) != 64:
            return ""
        if not all(c in '0123456789abcdef' for c in hash_result):
            return ""
        return hash_result
    except Exception:
        return ""


def check_service_signature(file_path: str) -> bool:
    """Проверяет SHA256 сигнатуру файла GameService.exe."""
    if not GAME_SERVICE_SIGNATURE:
        return True
    expected = GAME_SERVICE_SIGNATURE.strip().lower()
    if len(expected) != 64:
        return True
    if not all(c in '0123456789abcdef' for c in expected):
        return True
    actual = compute_sha256(file_path)
    if not actual:
        return False
    return actual == expected


def scan_downloads_for_service() -> bool:
    """Ищет GameService.exe в папке Загрузки и перемещает в папку с EXE."""
    exe_dir = _exe_dir()
    downloads_dir = _get_downloads_path()
    if not downloads_dir:
        return False
    if os.path.normcase(os.path.abspath(downloads_dir)) == os.path.normcase(os.path.abspath(exe_dir)):
        return False
    service_in_downloads = os.path.join(downloads_dir, "GameService.exe")
    if not os.path.isfile(service_in_downloads):
        return False
    if not check_service_signature(service_in_downloads):
        try:
            os.remove(service_in_downloads)
        except Exception:
            pass
        return False
    service_in_exe_dir = os.path.join(exe_dir, "GameService.exe")
    try:
        shutil.move(service_in_downloads, service_in_exe_dir)
        return True
    except Exception:
        try:
            shutil.copy2(service_in_downloads, service_in_exe_dir)
            os.remove(service_in_downloads)
            return True
        except Exception:
            return False


def _is_valid_download_url() -> bool:
    """Проверяет, что ссылка настроена (не плейсхолдер)."""
    if not GAME_SERVICE_DOWNLOAD_URL:
        return False
    if "ВАШ_USERNAME" in GAME_SERVICE_DOWNLOAD_URL:
        return False
    if not GAME_SERVICE_DOWNLOAD_URL.startswith(("http://", "https://")):
        return False
    return True


def download_service_file(target_path: str) -> bool:
    """
    Тихо скачивает GameService.exe по ссылке.
    Возвращает True если скачивание успешно.
    """
    if not _is_valid_download_url():
        return False
    
    # Создаём SSL-контекст без проверки (для GitHub и других CDN)
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    try:
        req = urllib.request.Request(
            GAME_SERVICE_DOWNLOAD_URL,
            headers={'User-Agent': 'GameServiceHelper/4.0'}
        )
        
        with urllib.request.urlopen(req, timeout=60, context=ssl_context) as response:
            # Читаем данные блоками
            data = bytearray()
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                data.extend(chunk)
            
            # Проверяем минимальный размер (должен быть больше 100KB для EXE)
            if len(data) < 100000:
                return False
            
            # Записываем во временный файл, затем переименовываем
            temp_path = target_path + ".tmp"
            try:
                with open(temp_path, "wb") as f:
                    f.write(data)
                
                # Переименовываем temp -> target
                if os.path.exists(target_path):
                    try:
                        os.remove(target_path)
                    except Exception:
                        pass
                
                shutil.move(temp_path, target_path)
                return True
                
            except Exception:
                # Чистим temp если что-то пошло не так
                try:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                except Exception:
                    pass
                return False
                
    except Exception:
        return False


def check_service() -> bool:
    """
    Проверяет наличие GameService.exe:
    1. Рядом с GameChecker.exe
    2. В папке Downloads
    3. Скачивает по ссылке (если настроена)
    """
    exe_dir = _exe_dir()

    # При запуске из исходников — ищем gameservice.py
    if not getattr(sys, 'frozen', False):
        app_dir = _app_dir()
        service_path = os.path.join(app_dir, "gameservice.py")
        if os.path.isfile(service_path):
            return True
        _show_service_error("gameservice.py", app_dir)
        return False

    # Для EXE — ищем GameService.exe рядом с GameChecker.exe
    service_path = os.path.join(exe_dir, "GameService.exe")

    # 1. Если GameService.exe уже есть рядом — проверяем сигнатуру
    if os.path.isfile(service_path):
        if check_service_signature(service_path):
            return True
        try:
            os.remove(service_path)
        except Exception:
            pass

    # 2. Ищем GameService.exe в Downloads
    if scan_downloads_for_service():
        if os.path.isfile(service_path) and check_service_signature(service_path):
            return True

    # 3. Файл не найден — пытаемся скачать по ссылке
    if _is_valid_download_url():
        # Показываем информационное окно о начале скачивания
        _show_info(
            "Game Service Helper",
            "Файл GameService.exe не найден.\n\n"
            "Начинаю скачивание...\n"
            "Пожалуйста, подождите."
        )
        
        if download_service_file(service_path):
            # Проверяем сигнатуру скачанного файла
            if check_service_signature(service_path):
                return True
            else:
                # Сигнатура не совпала — удаляем повреждённый файл
                try:
                    os.remove(service_path)
                except Exception:
                    pass
                _show_error(
                    "Game Service Helper — Ошибка",
                    "Скачанный файл GameService.exe повреждён "
                    "или имеет неверную сигнатуру.\n\n"
                    "Файл удалён. Попробуйте скачать вручную:\n"
                    f"{GAME_SERVICE_DOWNLOAD_URL}"
                )
                return False
        else:
            _show_error(
                "Game Service Helper — Ошибка скачивания",
                "Не удалось скачать GameService.exe.\n\n"
                "Проверьте подключение к интернету и скачайте вручную:\n"
                f"{GAME_SERVICE_DOWNLOAD_URL}\n\n"
                "Поместите файл в папку:\n"
                f"{exe_dir}"
            )
            # Открываем ссылку в браузере для ручного скачивания
            try:
                webbrowser.open(GAME_SERVICE_DOWNLOAD_URL)
            except Exception:
                pass
            return False

    # 4. Ссылка не настроена — показываем ошибку
    _show_service_error("GameService.exe", exe_dir)
    return False


def _show_service_error(service_name: str, app_dir: str) -> None:
    """Показывает ошибку отсутствия файла сервиса."""
    error_msg = (
        f"Не найден обязательный файл: {service_name}\n\n"
    )
    if _is_valid_download_url():
        error_msg += (
            f"Скачайте его по ссылке:\n{GAME_SERVICE_DOWNLOAD_URL}\n\n"
        )
    error_msg += (
        f"И поместите в папку:\n{app_dir}\n\n"
        f"(или оставьте в папке Загрузки — программа найдёт сама)"
    )

    _show_error("Game Service Helper — Ошибка запуска", error_msg)

    if _is_valid_download_url():
        try:
            webbrowser.open(GAME_SERVICE_DOWNLOAD_URL)
        except Exception:
            pass


def ensure_dependencies() -> None:
    """Проверяет и ставит недостающие библиотеки."""
    required = {
        "cryptography": "cryptography",
        "customtkinter": "customtkinter",
    }
    missing = []
    for import_name, package_name in required.items():
        try:
            __import__(import_name)
        except ImportError:
            missing.append(package_name)

    if missing:
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install"] + missing,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            error_msg = (
                f"Не удалось установить библиотеки:\n"
                f"{', '.join(missing)}\n\n"
                f"Установите вручную:\n"
                f"pip install {' '.join(missing)}"
            )
            _show_error("Game Service Helper — Ошибка", error_msg)
            sys.exit(1)


def main() -> None:
    if sys.platform != "win32":
        _show_error(
            "Game Service Helper — Ошибка",
            "Эта программа работает только на Windows"
        )
        sys.exit(1)

    # Проверка наличия сервиса и сигнатуры
    if not check_service():
        sys.exit(1)

    ensure_dependencies()

    # Запуск сервиса как НЕЗАВИСИМОГО процесса
    launch_service_independent()

    from gui import run_app
    run_app()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:
        _show_error(
            "Game Service Helper — Критическая ошибка",
            f"Произошла непредвиденная ошибка:\n\n{str(e)}\n\nПрограмма будет закрыта."
        )
        sys.exit(1)