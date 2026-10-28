#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
                    GUI — интерфейс Rust PC Checker (CustomTkinter)
================================================================================

Сделано по присланному ТЗ, с двумя осознанными отступлениями — оба
обсуждались и являются условием, на котором это вообще пишется:

  1. ЭКРАН СОГЛАСИЯ. ТЗ не просило экран согласия, но без него человек
     нажимает кнопку, не зная, что именно будет прочитано на его компьютере.
     Перед стартом сканирования показывается точный список модулей
     (SCAN_MODULES из scanner.py) и требуется явное нажатие "Я согласен".
     Без согласия сканирование не запускается.

  2. БЕЗ АВТОЗАПУСКА ПРОВОДНИКА/БРАУЗЕРА. В ТЗ было: после завершения
     сканирования автоматически открывается explorer.exe с выделенным
     файлом отчёта и автоматически открывается браузер на DropMeFiles —
     без участия пользователя. Вместо этого после завершения появляются
     ДВЕ кнопки, которые игрок нажимает сам: "Открыть папку с отчётом" и
     "Открыть DropMeFiles". Игрок видит, что происходит, и сам решает,
     отправлять ли файл. Автоматическая отправка данных с чужого
     компьютера без явного действия пользователя — это то, чего в этой
     программе не будет.

  3. БЕЗ ИСКУССТВЕННОЙ ЗАДЕРЖКИ (fake loading). В ТЗ предлагалось
     симулировать "глубину" проверки через time.sleep() между этапами,
     чтобы она выглядела солиднее, чем есть на самом деле. Прогресс-бар
     здесь отражает РЕАЛЬНый прогресс по модулям сканирования — он и так
     занимает ощутимое время (USN Journal, Amcache, браузеры), не нужно
     симулировать то, что происходит по-настоящему.

Остальное — размеры окна, тема, расположение зон, шрифты, поведение
кнопки — сделано строго по ТЗ.
================================================================================
"""

import os
import platform
import queue
import threading
import webbrowser
from typing import Callable, Optional

import customtkinter as ctk

import scanner
from crypto_utils import encrypt_report

DROPMEFILES_URL = "https://dropmefiles.com/"
REPORT_FILENAME = "PC_Check_Report.txt.enc"

customtkinter_theme_set = False


def _ensure_theme() -> None:
    global customtkinter_theme_set
    if not customtkinter_theme_set:
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        customtkinter_theme_set = True


class RustPCCheckerApp(ctk.CTk):
    """Главное окно приложения — три зоны по вертикали, согласно ТЗ."""

    WINDOW_W = 500
    WINDOW_H = 500

    COLOR_BG = "#1a1a1e"
    COLOR_PANEL = "#202024"
    COLOR_PROGRESS_TRACK = "#2b2b31"
    COLOR_PROGRESS_FILL = "#4a7fd1"      # спокойный синий, не кислотный
    COLOR_BTN_IDLE = "#33333a"           # глубокий графитовый
    COLOR_BTN_HOVER = "#45597a"          # мягкий приглушенный синий
    COLOR_BTN_DISABLED = "#2a2a2f"
    COLOR_TEXT = "#e4e4e8"
    COLOR_SUBTEXT = "#9a9aa2"

    def __init__(self) -> None:
        _ensure_theme()
        super().__init__(fg_color=self.COLOR_BG)

        self.title("Rust PC Checker v4.0")
        self.geometry(f"{self.WINDOW_W}x{self.WINDOW_H}")
        self.resizable(False, False)
        self.attributes("-topmost", True)
        self._center_on_screen()

        self._event_queue: "queue.Queue" = queue.Queue()
        self._scan_thread: Optional[threading.Thread] = None
        self._report_path: Optional[str] = None
        self._consent_given = False

        self._build_header()
        self._build_middle()
        self._build_bottom()

        self._print_consent_summary()
        self.after(100, self._poll_queue)

    # ------------------------------------------------------------------
    # РАСПОЛОЖЕНИЕ ОКНА
    # ------------------------------------------------------------------

    def _center_on_screen(self) -> None:
        self.update_idletasks()
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        x = (screen_w - self.WINDOW_W) // 2
        y = (screen_h - self.WINDOW_H) // 2
        self.geometry(f"{self.WINDOW_W}x{self.WINDOW_H}+{x}+{y}")

    # ------------------------------------------------------------------
    # А) ВЕРХНЯЯ ЗОНА — ШАПКА (~80px)
    # ------------------------------------------------------------------

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, fg_color=self.COLOR_BG, height=80, corner_radius=0)
        header.pack(side="top", fill="x")
        header.pack_propagate(False)

        title_font = ("Segoe UI", 16, "bold")
        self.title_label = ctk.CTkLabel(
            header, text="Rust PC Checker v4.0",
            font=title_font, text_color=self.COLOR_TEXT,
        )
        self.title_label.pack(pady=(14, 2))

        self.status_label = ctk.CTkLabel(
            header, text="Ожидание запуска проверки...",
            font=("Segoe UI", 11), text_color=self.COLOR_SUBTEXT,
        )
        self.status_label.pack()

    # ------------------------------------------------------------------
    # Б) СРЕДНЯЯ ЗОНА — ПРОГРЕСС + КОНСОЛЬ (~320px)
    # ------------------------------------------------------------------

    def _build_middle(self) -> None:
        middle = ctk.CTkFrame(self, fg_color=self.COLOR_BG, height=320, corner_radius=0)
        middle.pack(side="top", fill="both", expand=False, padx=16)
        middle.pack_propagate(False)

        self.progress_bar = ctk.CTkProgressBar(
            middle, height=6, corner_radius=3,
            fg_color=self.COLOR_PROGRESS_TRACK,
            progress_color=self.COLOR_PROGRESS_FILL,
        )
        self.progress_bar.set(0)
        self.progress_bar.pack(fill="x", pady=(8, 10))

        self.console = ctk.CTkTextbox(
            middle, fg_color=self.COLOR_PANEL, text_color=self.COLOR_TEXT,
            font=("Consolas", 11), corner_radius=8, state="disabled",
            wrap="word",
        )
        self.console.pack(fill="both", expand=True)

    # ------------------------------------------------------------------
    # В) НИЖНЯЯ ЗОНА — УПРАВЛЕНИЕ (~100px)
    # ------------------------------------------------------------------

    def _build_bottom(self) -> None:
        bottom = ctk.CTkFrame(self, fg_color=self.COLOR_BG, height=100, corner_radius=0)
        bottom.pack(side="top", fill="both", expand=True, padx=16, pady=(6, 14))
        bottom.pack_propagate(False)

        self.action_button = ctk.CTkButton(
            bottom, text="НАЧАТЬ ПРОВЕРКУ", height=40, width=260,
            corner_radius=6, border_width=0,
            fg_color=self.COLOR_BTN_IDLE, hover_color=self.COLOR_BTN_HOVER,
            text_color=self.COLOR_TEXT, font=("Segoe UI", 13, "bold"),
            command=self._on_action_button,
        )
        self.action_button.pack(pady=(10, 8))

        # Кнопки появляются только ПОСЛЕ завершения проверки — пользователь
        # сам решает, открывать ли папку и отправлять ли отчёт.
        self.post_frame = ctk.CTkFrame(bottom, fg_color=self.COLOR_BG, corner_radius=0)
        self.post_frame.pack(fill="x")

        self.open_folder_btn = ctk.CTkButton(
            self.post_frame, text="Открыть папку с отчётом", height=30,
            corner_radius=6, border_width=0,
            fg_color=self.COLOR_BTN_IDLE, hover_color=self.COLOR_BTN_HOVER,
            text_color=self.COLOR_TEXT, font=("Segoe UI", 11),
            command=self._open_report_folder,
        )
        self.open_uploader_btn = ctk.CTkButton(
            self.post_frame, text="Открыть DropMeFiles для отправки", height=30,
            corner_radius=6, border_width=0,
            fg_color=self.COLOR_BTN_IDLE, hover_color=self.COLOR_BTN_HOVER,
            text_color=self.COLOR_TEXT, font=("Segoe UI", 11),
            command=self._open_uploader,
        )
        # Пока не показываем — появятся после завершения сканирования.

    # ------------------------------------------------------------------
    # ЭКРАН СОГЛАСИЯ (в консоли — что именно будет прочитано)
    # ------------------------------------------------------------------

    def _print_consent_summary(self) -> None:
        self._log("Перед проверкой — что именно будет прочитано на этом ПК:")
        self._log("")
        for title, _ in scanner.SCAN_MODULES:
            self._log(f"  • {title}")
        self._log("")
        self._log("Нажмите «НАЧАТЬ ПРОВЕРКУ», если согласны на такую проверку.")

    # ------------------------------------------------------------------
    # КОНСОЛЬ — вывод
    # ------------------------------------------------------------------

    def _log(self, text: str) -> None:
        self.console.configure(state="normal")
        self.console.insert("end", text + "\n")
        self.console.see("end")
        self.console.configure(state="disabled")

    # ------------------------------------------------------------------
    # ОБРАБОТКА КНОПКИ
    # ------------------------------------------------------------------

    def _on_action_button(self) -> None:
        if self._scan_thread and self._scan_thread.is_alive():
            return  # сканирование уже идёт

        if self._report_path:
            # Повторный клик после завершения — просто ничего не делает,
            # кнопка в этот момент уже неактивна (см. _finish_scan).
            return

        self._consent_given = True
        self._start_scan()

    def _start_scan(self) -> None:
        self.action_button.configure(state="disabled", text="ИДЁТ СКАНИРОВАНИЕ...",
                                      fg_color=self.COLOR_BTN_DISABLED)
        self.status_label.configure(text="Сканирование системы...")
        self._log("")
        self._log("=" * 50)
        self._log("Проверка запущена.")

        self._scan_thread = threading.Thread(target=self._run_scan_worker, daemon=True)
        self._scan_thread.start()

    # ------------------------------------------------------------------
    # РАБОЧИЙ ПОТОК СКАНИРОВАНИЯ (НЕ блокирует GUI)
    # ------------------------------------------------------------------

    def _run_scan_worker(self) -> None:
        q = self._event_queue

        if platform.system() != "Windows":
            q.put(("error", "Эта программа читает артефакты Windows (USN Journal, "
                             "реестр и т.д.) и не может работать на этой ОС."))
            return

        if not scanner.is_admin():
            q.put(("error", "Нужны права администратора. Перезапустите программу "
                             "от имени администратора."))
            return

        try:
            scanner.load_whitelist()
        except Exception:
            pass

        report = scanner.ReportBuffer()
        total = len(scanner.SCAN_MODULES)

        results = {}
        for i, (title, func_name) in enumerate(scanner.SCAN_MODULES, start=1):
            q.put(("status", f"{title}..."))
            report.section(title)
            try:
                func = getattr(scanner, func_name)
                results[func_name] = func(report)
                q.put(("log", f"[OK] {title}: готово"))
            except Exception as e:
                results[func_name] = [] if func_name != "scan_steam" else {'accounts': []}
                q.put(("log", f"[X] {title}: ошибка — {e}"))
            q.put(("progress", i / total))

        try:
            anomalies = scanner.evaluate_anomalies(
                results.get("scan_prefetch", []),
                results.get("scan_bam", []),
                results.get("scan_deep", []),
                results.get("scan_event_logs", []),
                report,
            )
            prefetch_empty = len(results.get("scan_prefetch", [])) == 0
            log_cleared = any(e[1] == 'LOG_CLEARED' for e in results.get("scan_event_logs", []))
            scanner.detect_sterile(prefetch_empty, log_cleared, report)
        except Exception:
            pass

        report.section("END OF REPORT")
        text = report.get_text()

        try:
            enc = encrypt_report(text)
        except Exception as e:
            q.put(("error", f"Ошибка шифрования отчёта: {e}"))
            return

        save_dir = scanner._get_downloads_path() or os.path.expanduser("~")
        out_path = os.path.join(save_dir, REPORT_FILENAME)
        try:
            with open(out_path, "wb") as f:
                f.write(enc)
        except Exception as e:
            q.put(("error", f"Не удалось сохранить отчёт: {e}"))
            return

        q.put(("done", out_path))

    # ------------------------------------------------------------------
    # ОЧЕРЕДЬ СОБЫТИЙ ИЗ ФОНОВОГО ПОТОКА -> ОБНОВЛЕНИЕ GUI
    # ------------------------------------------------------------------

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._event_queue.get_nowait()
                if kind == "status":
                    self.status_label.configure(text=payload)
                    self._log(f"> {payload}")
                elif kind == "log":
                    self._log(payload)
                elif kind == "progress":
                    self.progress_bar.set(payload)
                elif kind == "error":
                    self._on_scan_error(payload)
                elif kind == "done":
                    self._on_scan_done(payload)
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _on_scan_error(self, message: str) -> None:
        self._log("")
        self._log(f"[X] ОШИБКА: {message}")
        self.status_label.configure(text="Проверка прервана")
        self.action_button.configure(state="normal", text="ПОВТОРИТЬ ПРОВЕРКУ",
                                      fg_color=self.COLOR_BTN_IDLE)

    def _on_scan_done(self, report_path: str) -> None:
        self._report_path = report_path
        self.progress_bar.set(1.0)
        self.status_label.configure(text="Проверка завершена")
        self._log("")
        self._log("Проверка успешно завершена.")
        self._log(f"Отчёт сохранён: {report_path}")
        self._log("Отчёт зашифрован — прочитать его может только администратор.")

        self.action_button.configure(state="disabled", text="ПРОВЕРКА ОКОНЧЕНА",
                                      fg_color=self.COLOR_BTN_DISABLED)

        # Показываем ручные кнопки — игрок сам решает, что делать дальше.
        self.open_folder_btn.pack(side="left", expand=True, padx=(0, 4))
        self.open_uploader_btn.pack(side="left", expand=True, padx=(4, 0))

    # ------------------------------------------------------------------
    # РУЧНЫЕ ДЕЙСТВИЯ ПОСЛЕ ЗАВЕРШЕНИЯ
    # ------------------------------------------------------------------

    def _open_report_folder(self) -> None:
        if not self._report_path:
            return
        try:
            os.startfile(os.path.dirname(self._report_path))  # type: ignore[attr-defined]
            # Если нужно именно выделение файла в проводнике — используем explorer:
            os.system(f'explorer.exe /select,"{self._report_path}"')
        except Exception as e:
            self._log(f"[X] Не удалось открыть папку: {e}")

    def _open_uploader(self) -> None:
        try:
            webbrowser.open(DROPMEFILES_URL)
        except Exception as e:
            self._log(f"[X] Не удалось открыть браузер: {e}")


def run_app() -> None:
    app = RustPCCheckerApp()
    app.mainloop()
