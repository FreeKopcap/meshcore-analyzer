"""Meshcore Analyzer — анализатор пакетов MeshCore Observer.

Version: 3.1

Changelog:
  v3.1 — Нейтральный к USB API-поллер
    - Поллер MeshCoreTel (`--api`) работает в отдельном потоке, независимо от USB
    - При потере USB скрипт ждёт переподключения порта, но продолжает обновлять исходящих соседей через API
  v3.0 — Поддержка маршрутов 2 байта на хоп (Meshcore 1.14+)
    - Константа PATH_BYTES_PER_HOP (1 или 2): режим парсинга path и TRACE
    - Парсинг path/trace_route при 2 байтах на хоп; число хопов = len(path)
    - Исходящие соседи из ответов ботов: ack@[имя] и @[имя] (оба формата)
    - MY_COMPANIONS: имена компаньонов для маршрутов без префикса репитера
    - Регулярки в extract_outgoing_neighbors поддерживают 2 и 4 hex на хоп
  v2.2 — SNR соседей из TRACE, полный debug-лог
    - Столбцы SNR→/SNR← в таблице соседей (средний SNR туда/обратно из TRACE)
    - TRACE-ответы учитываются в таблицах соседей и исходящих соседей
    - Signed SNR в TRACE (поддержка отрицательных значений)
    - API: фильтрация TRACE-пакетов (path содержит SNR, не узлы)
    - Опция -d/--debug: полный лог всех пакетов (RAW + API + TRACE)
  v2.1 — Декодирование TRACE, отладка ->OBS, точная статистика соседей
    - Декодирование DIRECT TRACE: SNR на каждом хопе и маршрут трассировки
    - Статистика соседей только по FLOOD-пакетам (DIRECT не искажают таблицу)
    - Подсветка ->OBS пакетов жёлтым + метка [OBS] в verbose
    - Отображение destination для DIRECT-пакетов в verbose
  v2.0 — Исходящие соседи через API MeshCoreTel
    - Опция --api: получение исходящих соседей из API meshcoretel.ru
      (пассивно, без отправки сообщений в каналы)
    - Опция --repeater: префикс ретранслятора для поиска через API
    - Опция --bots: поиск исходящих соседей через ответы ботов (старый метод)
    - API-опрос в отдельном потоке (не блокирует обработку серийного порта)
    - В verbose (-v) пакеты из API помечаются [API] голубым цветом
  v1.2 — Переподключение, сохранение статистики, CLI
    - Автоматическое переподключение при потере USB-соединения
    - Сохранение статистики в файл meshcore-stats.json между запусками
    - Опция --reset для сброса накопленной статистики
    - Опция -p/--port для указания серийного порта
    - Опция --hops (вместо -p/--path) для рекорда хопов
    - Фоновое чтение порта через отдельный поток (без потери пакетов)
  v1.1 — Дешифрование каналов, исходящие соседи
    - Расшифровка групповых сообщений (GRP_TXT/GRP_DATA) публичных каналов (AES-128-ECB)
    - Таблица исходящих соседей (-n) через ответы ботов в каналах
    - В verbose (-v) сообщения с исходящим path выделяются магентой
    - Столбцы ->RPT/->OBS в таблице входящих соседей вместо бесполезного SNR
    - Зависимость: pycryptodome (опционально)
  v1.0 — Первая публикация
    - Статистика по узлам (-o): RX/TX, SNR, RSSI, хопы
    - Таблица входящих соседей (-n)
    - Рекорд хопов (-p)
    - Verbose-режим (-v) с реальным временем
    - Парсинг RAW-пакетов MeshCore v1
"""

__version__ = '3.1'

import serial
import time
import sys
import os
import re
import json
import argparse
import hashlib
import threading
import queue
import urllib.request
from collections import defaultdict

try:
    from Crypto.Cipher import AES
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# ========== ANSI-коды цветов для терминального вывода ==========
GREEN = '\033[92m'
CYAN = '\033[96m'
YELLOW = '\033[93m'
RED = '\033[91m'
MAGENTA = '\033[95m'
RESET = '\033[0m'
BOLD = '\033[1m'
# ===============================================================


def is_repeater_token(token: str) -> bool:
    """Возвращает True, если токен в path относится к вашему репитеру.

    Логика:
      - начинается с REPEATER_PREFIX (обычный случай);
      - или состоит только из повторяющихся байт 0x33: 33,3333,333333,...
    """
    t = token.upper()
    if t.startswith(REPEATER_PREFIX.upper()):
        return True
    # Повторяющиеся "33" (любая длина, кратная 2)
    return len(t) >= 2 and len(t) % 2 == 0 and all(t[i:i+2] == '33' for i in range(0, len(t), 2))

# ========== КОНФИГУРАЦИЯ ==========
# Серийный порт, к которому подключена нода Meshcore.
# macOS: обычно /dev/cu.usbmodemXXXX или /dev/cu.usbserial-XXXX
# Windows: COM24, COM3 и т.д.
# PORT = '/dev/cu.usbmodemE8F60ACB1A401'    # коричневый корпус
PORT = '/dev/cu.usbmodemE8F60ACB19781'      # черный корпус
BAUDRATE = 115200

# Префикс hex-адресов ваших нод-компаньонов. Подсвечиваются зелёным в таблице.
NODE_PREFIX = '10'
# Префикс hex-адресов ваших ретрансляторов. Подсвечиваются голубым.
REPEATER_PREFIX = '33'

# Байт на хоп в маршруте (1 — текущие прошивки; 2 — режим Meshcore 1.14+).
# В логах Observer путь приходит как последовательность байт; адрес ретранслятора
# может занимать 1, 2 или 3 байта. Для вашего репитера используется ключ
# вида 33 33 33 ... (любая длина). В анализаторе хопы остаются побайтно, но
# репитер определяется по префиксу REPEATER_PREFIX ИЛИ по маске (33)+.
PATH_BYTES_PER_HOP = 1

# Виртуальный адрес для пакетов без конкретного источника (широковещательные).
BROADCAST_NODE = 'BCAST'

# Имя бота, передающего маршруты в формате "XX: Описание репитера" (паттерн 2).
PATHBOT_SENDER = 'AetherByte\U0001f916'  # AetherByte🤖

# Имена ваших компаньонов для обработки ack@[...] без префикса репитера.
MY_COMPANIONS = ['Kopcap V4️⃣', 'Kopcap 1️⃣1️⃣4️⃣']

# Интервал между циклами сбора статистики (секунды).
CYCLE_TIME = 60

# Таймаут чтения лога из серийного порта (секунды).
READ_TIMEOUT = 5

# Известные публичные каналы для расшифровки групповых сообщений.
# Ключ шифрования = SHA256(имя_канала)[:16], хеш канала = SHA256(имя_канала)[0].
KNOWN_CHANNEL_NAMES = [
    'Public',       # канал по умолчанию (без #)
    '#connections',
    '#robot',
    '#test',
    '#bot-test',
    '#server',
    '#zapad',
]
# ==================================

# Режим подробного вывода (включается через -v).
VERBOSE = False
# Режим поиска исходящих соседей через ботов в каналах (включается через --bots).
BOTS_MODE = False
# Режим отладки: подсветка и логирование пакетов, принятых observer напрямую (-d).
DEBUG_MODE = False
DEBUG_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'meshcore-debug.log')

# ========== MESHCORE PROTOCOL ==========
# Маппинг типов пакетов (payload type, биты 2-5 заголовка)
PAYLOAD_TYPES = {
    0x00: 'REQ',
    0x01: 'RESPONSE',
    0x02: 'TXT_MSG',
    0x03: 'ACK',
    0x04: 'ADVERT',
    0x05: 'GRP_TXT',
    0x06: 'GRP_DATA',
    0x07: 'ANON_REQ',
    0x08: 'PATH',
    0x09: 'TRACE',
    0x0A: 'MULTIPART',
    0x0B: 'CONTROL',
    0x0F: 'RAW_CUSTOM',
}

# Маппинг типов маршрутизации (route type, биты 0-1 заголовка)
ROUTE_TYPES = {
    0x00: 'T_FLOOD',
    0x01: 'FLOOD',
    0x02: 'DIRECT',
    0x03: 'T_DIRECT',
}
# ========================================

# ========== КЛЮЧИ КАНАЛОВ ==========
# Ключ канала = SHA256(имя)[:16], хеш канала = SHA256(ключ)[0] (двойной SHA256).
# При коллизиях хешей (напр. #server и #zapad оба дают 56) пробуем все варианты.
# Структура: channel_hash -> [(имя, AES-ключ), ...]
CHANNEL_KEYS = {}
for _ch_name in KNOWN_CHANNEL_NAMES:
    _key = hashlib.sha256(_ch_name.encode()).digest()[:16]
    _ch_hash = hashlib.sha256(_key).digest()[0]
    CHANNEL_KEYS.setdefault(_ch_hash, []).append((_ch_name, _key))
# ====================================

# Глобальный словарь статистики по каждому узлу.
# Ключ — адрес узла (строка), значение — dict со счётчиками.
stats = defaultdict(lambda: {
    'rx': 0,          # Количество принятых пакетов (RX)
    'tx': 0,          # Количество отправленных пакетов (TX)
    'errors': 0,      # Количество пакетов с score=0 (ошибочных)
    'snr_sum': 0,     # Сумма SNR для расчёта среднего
    'snr_count': 0,   # Количество замеров SNR
    'rssi_sum': 0,    # Сумма RSSI для расчёта среднего
    'rssi_count': 0,  # Количество замеров RSSI
})

# Статистика соседей: кто доставляет пакеты ретранслятору и наблюдателю.
neighbor_stats = defaultdict(lambda: {
    'total': 0,
    'snr_sum': 0,          # SNR при приёме observer (из RX-строки)
    'snr_count': 0,
    'trace_out_sum': 0,    # SNR→ (репитер → сосед, из TRACE)
    'trace_out_count': 0,
    'trace_in_sum': 0,     # SNR← (сосед → репитер, из TRACE)
    'trace_in_count': 0,
    'trace_attempts': 0,   # Попыток трассировки
    'trace_ok': 0,         # Успешных (полный ответ)
})

# Статистика исходящих соседей (из расшифрованных групповых сообщений с path).
outgoing_stats = defaultdict(lambda: {'total': 0})

# Последний определённый сосед из RAW-пакета (для корреляции с SNR из RX-строки)
_last_raw_neighbor = None

# Рекорд максимального числа хопов (dict с данными пакета или None)
max_hops_record = None

# Путь к файлу сохранения статистики (рядом со скриптом)
STATS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'meshcore-stats.json')

# API MeshCoreTel для получения пакетов от всех наблюдателей региона
MESHCORETEL_API = 'https://meshcoretel.ru/api/packets'

# ID последнего обработанного пакета из API (для инкрементальных запросов)
_api_last_id = None
# Множество обработанных хешей пакетов (дедупликация: один пакет виден многим наблюдателям)
_api_seen_hashes = set()


def save_stats():
    """Сохраняет накопленную статистику в JSON-файл."""
    data = {
        'stats': dict(stats),
        'neighbor_stats': dict(neighbor_stats),
        'outgoing_stats': dict(outgoing_stats),
        'max_hops_record': None,
    }
    if max_hops_record:
        # payload — bytes, конвертируем в hex для JSON
        r = dict(max_hops_record)
        if isinstance(r.get('payload'), (bytes, bytearray)):
            r['payload'] = r['payload'].hex()
        data['max_hops_record'] = r
    try:
        with open(STATS_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"{YELLOW}Ошибка сохранения статистики: {e}{RESET}")


def load_stats():
    """Загружает статистику из JSON-файла, если он существует."""
    global max_hops_record
    if not os.path.exists(STATS_FILE):
        return
    try:
        with open(STATS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        for node, vals in data.get('stats', {}).items():
            for k, v in vals.items():
                stats[node][k] = v
        for node, vals in data.get('neighbor_stats', {}).items():
            for k, v in vals.items():
                neighbor_stats[node][k] = v
        for node, vals in data.get('outgoing_stats', {}).items():
            for k, v in vals.items():
                outgoing_stats[node][k] = v
        r = data.get('max_hops_record')
        if r:
            # Восстанавливаем payload из hex в bytes
            if isinstance(r.get('payload'), str):
                r['payload'] = bytes.fromhex(r['payload'])
            max_hops_record = r
        total_rx = sum(d['rx'] for d in stats.values())
        print(f"Загружена статистика: {len(stats)} узлов, {total_rx} RX, "
              f"{len(neighbor_stats)} соседей, {len(outgoing_stats)} исх. соседей")
    except Exception as e:
        print(f"{YELLOW}Ошибка загрузки статистики: {e}{RESET}")


def parse_raw(hex_str):
    """Парсит сырые hex-данные пакета MeshCore и извлекает заголовок, path и метаданные.

    Формат пакета (v1):
      [header 1B][transport_codes 4B (опц.)][path_length 1B][path NB][payload]

    Header (1 байт, 0bVVPPPPRR):
      - биты 0-1: route type (FLOOD, DIRECT, TRANSPORT_*)
      - биты 2-5: payload type (ADVERT, GRP_TXT, GRP_DATA, ...)
      - биты 6-7: версия формата

    Args:
        hex_str: строка hex-данных пакета (без пробелов)

    Returns:
        dict с полями: route_type, payload_type, route_name, payload_name,
                       path_length (байт в пути), path (список хопов;
                       при PATH_BYTES_PER_HOP==2 элемент — 4 hex),
                       payload (bytes), или None при ошибке
    """
    try:
        data = bytes.fromhex(hex_str)
        if len(data) < 3:
            return None

        header = data[0]
        route_type = header & 0x03
        payload_type = (header >> 2) & 0x0F

        # Transport codes занимают 4 байта после header в TRANSPORT_* режимах
        has_transport = route_type in (0x00, 0x03)
        offset = 1 + (4 if has_transport else 0)

        if offset >= len(data):
            return None

        path_length = data[offset]
        offset += 1

        if offset + path_length > len(data):
            return None

        # Маршрут: пока парсим побайтно; прошивки могут использовать 1/2/3 байта
        # на адрес, но в логе Observer path приходит как сырые байты. В дальнейшем
        # можно группировать байты по PATH_BYTES_PER_HOP, сейчас оставляем по 1.
        path = [f"{b:02X}" for b in data[offset:offset + path_length]]
        payload = data[offset + path_length:]

        # DIRECT-пакеты: первые 6 байт payload — destination pubkey prefix
        dest = None
        if route_type in (0x02, 0x03) and len(payload) >= 6:
            dest = payload[:6].hex().upper()

        # TRACE-пакеты: path содержит SNR (×4) на каждом хопе, а не узлы;
        # маршрут трассировки — в конце payload (после dest[6] + meta[3])
        trace_route = None
        trace_snr = None
        if payload_type == 0x09 and route_type in (0x02, 0x03):
            # SNR: по одному байту на хоп
            trace_snr = [(b - 256 if b > 127 else b) / 4.0
                         for b in data[offset:offset + path_length]]
            if len(payload) > 9:
                # Маршрут трассировки — тоже побайтно; адреса могут быть 1–3 байта.
                raw_route = payload[9:]
                trace_route = [f"{b:02X}" for b in raw_route]

        return {
            'route_type': route_type,
            'payload_type': payload_type,
            'route_name': ROUTE_TYPES.get(route_type, f'?{route_type}'),
            'payload_name': PAYLOAD_TYPES.get(payload_type, f'?{payload_type}'),
            'path_length': path_length,
            'path': path,
            'payload': payload,
            'dest': dest,
            'trace_route': trace_route,
            'trace_snr': trace_snr,
        }
    except (ValueError, IndexError):
        return None


def send_cmd(ser, cmd, wait=0.5):
    """Отправляет AT-команду в серийный порт ноды Meshcore.

    Очищает входной буфер перед отправкой, чтобы не читать мусор,
    затем пишет команду с CR+LF и ждёт указанное время для ответа.

    Args:
        ser: объект serial.Serial (открытый порт)
        cmd: строка команды (например "log", "log start", "log erase")
        wait: пауза после отправки (сек), чтобы нода успела ответить
    """
    ser.reset_input_buffer()
    ser.write(f"{cmd}\r\n".encode())
    time.sleep(wait)


def read_until_eof(ser, timeout=10):
    """Читает строки из серийного порта до маркера EOF или таймаута.

    Нода Meshcore при команде "log" выводит накопленные логи и
    завершает вывод строкой, содержащей 'EOF'. Функция построчно
    собирает ответ до этого маркера.

    Args:
        ser: объект serial.Serial
        timeout: максимальное время ожидания данных (сек)

    Returns:
        list[str]: список прочитанных строк лога
    """
    lines = []
    start = time.time()
    while time.time() - start < timeout:
        if ser.in_waiting:
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            if line:
                lines.append(line)
                if 'EOF' in line:
                    break
        else:
            time.sleep(0.05)
    return lines


def extract_outgoing_neighbors(text):
    """Извлекает исходящих соседей из расшифрованного группового сообщения.

    Паттерн 1: "Found N unique path(s):" с последующими строками hex через запятую.
    Паттерн 2: Сообщения от PATHBOT_SENDER с маршрутом в формате "XX: Описание".
               Сообщения, начинающиеся с "..." — продолжения, игнорируются.

    В обоих случаях: если первый хоп/префикс совпадает с REPEATER_PREFIX,
    второй считается исходящим соседом.

    Args:
        text: расшифрованный текст сообщения

    Returns:
        list[str]: список адресов исходящих соседей (uppercase hex)
    """
    neighbors = []

    # Паттерн 1: "Found N unique path(s):" + строки "XX,YY,..." или "XXXX,YYYY,..." (1.14)
    # Один хоп = 2 hex (1 байт) или 4 hex (2 байта)
    hop_hex = r'[\da-fA-F]{2}' if PATH_BYTES_PER_HOP == 1 else r'[\da-fA-F]{4}'
    re_line = re.compile(r'^' + hop_hex + r'(,' + hop_hex + r')+$')
    parts = re.split(r'Found \d+ unique path\(s\):\s*', text)
    for part in parts[1:]:
        for line in part.split('\n'):
            line = line.strip().replace(' ', '')
            if re_line.match(line):
                hops = [h.strip().upper() for h in line.split(',')]
                if len(hops) >= 2 and is_repeater_token(hops[0]):
                    neighbors.append(hops[1])
            else:
                break

    # Паттерн 2: сообщения от PATHBOT_SENDER "XX: Описание" или "XXXX: Описание" (1.14)
    hex_prefix = r'[0-9a-fA-F]{2}' if PATH_BYTES_PER_HOP == 1 else r'[0-9a-fA-F]{4}'
    sender_prefix = PATHBOT_SENDER + ': '
    if text.startswith(sender_prefix):
        msg = text[len(sender_prefix):]
        lines = msg.split('\n')
        if lines and not lines[0].strip().startswith('...'):
            prefixes = []
            for line in lines:
                m = re.match(r'^(' + hex_prefix + r'):\s', line.strip())
                if m:
                    prefixes.append(m.group(1).upper())
            if len(prefixes) >= 2 and is_repeater_token(prefixes[0]):
                neighbors.append(prefixes[1])

    # Паттерн 3: "ack@[имя] XX,YY,..." или "@[имя] XX, YY,..." (2 или 4 hex на хоп для 1.14)
    # Если путь начинается с REPEATER_PREFIX — берём второй хоп.
    # Если нет, но имя компаньона в MY_COMPANIONS — первый хоп (репитер
    # считается дублем, компаньон услышал соседа напрямую).
    m = re.search(r'(?:ack)?@\[(.*?)\]\s+([\da-fA-F]{2,4}(?:,\s*[\da-fA-F]{2,4})+)', text)
    if m:
        name = m.group(1)
        hops = [h.strip().upper() for h in m.group(2).split(',')]
        if len(hops) >= 2 and is_repeater_token(hops[0]):
            neighbors.append(hops[1])
        elif hops and name in MY_COMPANIONS:
            neighbors.append(hops[0])

    return neighbors


def parse_line(line, stats, debug):
    """Парсит одну строку лога и обновляет статистику по узлам.

    Формат строк лога Meshcore (примеры):
      RX: "U: RX, type=6, ... SNR=10.5 RSSI=-85 ... [72->AF]"
      TX: "U: TX, type=6, ... [AF->72]"

    Из RX-строк извлекаются: SNR, RSSI, тип пакета, адрес источника/назначения.
    Из TX-строк — тип пакета и адреса.

    Пакеты без адресной пары [src->dst] считаются широковещательными (BCAST).
    Пакеты с score=0 считаются ошибочными.

    Args:
        line: строка лога
        stats: глобальный словарь статистики (defaultdict)
        debug: словарь отладочных счётчиков текущего цикла
    """
    global _last_raw_neighbor, max_hops_record
    debug['total'] += 1

    # Пропускаем служебные строки (команда log, маркер EOF, пустые)
    if not line or line.startswith('log') or 'EOF' in line:
        debug['ignored'] += 1
        return

    if VERBOSE:
        print(f"  {line}", flush=True)

    # --- Обработка входящих пакетов (RX) ---
    if 'U: RX,' in line:
        debug['rx_lines'] += 1
        if debug['rx_lines'] <= 3:
            debug.setdefault('rx_samples', []).append(line)
        try:
            # Извлекаем SNR и RSSI из строки
            if 'SNR=' in line and 'RSSI=' in line:
                snr_part = line.split('SNR=')[1].split()[0]
                rssi_part = line.split('RSSI=')[1].split()[0]
                snr = float(snr_part)
                rssi = int(rssi_part)
            else:
                debug['malformed'] += 1
                return

            # Извлекаем тип пакета (type=N)
            type_part = line.split('type=')[1].split(',')[0]
            ptype = int(type_part)

            # Извлекаем адреса отправителя и получателя из квадратных скобок [src->dst]
            src = None
            dst = None
            if '[' in line and ']' in line:
                bracket = line.split('[')[1].split(']')[0]
                if '->' in bracket:
                    src, dst = [x.strip() for x in bracket.split('->')]

            # Если источник известен — обновляем его статистику;
            # иначе относим пакет к широковещательным
            if src:
                node = stats[src]
            else:
                node = stats[BROADCAST_NODE]
                src = BROADCAST_NODE
                debug['broadcast_rx'] += 1

            # Обновляем счётчики RX и показатели качества сигнала
            node['rx'] += 1
            node['snr_sum'] += snr
            node['snr_count'] += 1
            node['rssi_sum'] += rssi
            node['rssi_count'] += 1

            # score=0 означает пакет с нулевой оценкой (повреждённый/сомнительный)
            if 'score=0' in line:
                node['errors'] += 1

            # Привязываем SNR к соседу из предыдущего RAW-пакета
            if _last_raw_neighbor:
                neighbor_stats[_last_raw_neighbor]['snr_sum'] += snr
                neighbor_stats[_last_raw_neighbor]['snr_count'] += 1
                _last_raw_neighbor = None

            if not src:
                debug['no_src_dst'] += 1

        except Exception as e:
            debug['exception'] += 1
            debug['last_exception'] = str(e)

    # --- Обработка исходящих пакетов (TX) ---
    elif 'U: TX,' in line:
        debug['tx_lines'] += 1
        try:
            type_part = line.split('type=')[1].split(',')[0]
            ptype = int(type_part)

            # Извлекаем адреса аналогично RX
            src = None
            dst = None
            if '[' in line and ']' in line:
                bracket = line.split('[')[1].split(']')[0]
                if '->' in bracket:
                    src, dst = [x.strip() for x in bracket.split('->')]

            if src:
                stats[src]['tx'] += 1
            else:
                stats[BROADCAST_NODE]['tx'] += 1
                debug['broadcast_tx'] += 1

        except Exception as e:
            debug['exception_tx'] += 1
            debug['last_exception_tx'] = str(e)

    # --- Сырые пакеты (U RAW:) — парсим заголовок и path ---
    elif 'U RAW:' in line:
        debug.setdefault('raw_lines', 0)
        debug['raw_lines'] += 1

        hex_str = line.split('U RAW:')[1].strip()
        parsed = parse_raw(hex_str)
        if parsed:
            pkt_label = f"{parsed['route_name']} {parsed['payload_name']}"
            path_str = ','.join(parsed['path']) if parsed['path'] else '-'
            hops = len(parsed['path'])

            # Расшифровка групповых сообщений
            decrypted = None
            outgoing_nbs = []
            if parsed['payload_type'] in (0x05, 0x06) and parsed['payload']:
                decrypted = decrypt_group_msg(parsed['payload'])
                if decrypted and BOTS_MODE:
                    outgoing_nbs = extract_outgoing_neighbors(decrypted['text'])
                    for out_nb in outgoing_nbs:
                        outgoing_stats[out_nb]['total'] += 1

            # Определяем соседа — кто доставил пакет ретранслятору или наблюдателю.
            # Только для FLOOD-пакетов (DIRECT маршрутизируются по заданному пути).
            _last_raw_neighbor = None
            direct_to_obs = False
            is_flood = parsed['route_type'] in (0x00, 0x01)
            if is_flood and parsed['path']:
                last = parsed['path'][-1]
                if is_repeater_token(last):
                    if len(parsed['path']) >= 2:
                        nb = parsed['path'][-2]
                        neighbor_stats[nb]['total'] += 1
                        _last_raw_neighbor = nb
                else:
                    neighbor_stats[last]['total'] += 1
                    _last_raw_neighbor = last
                    direct_to_obs = True

            # TRACE: собираем SNR→/SNR←, считаем попытки/успехи
            if parsed.get('trace_route') is not None:
                tr = parsed['trace_route']
                ts = parsed.get('trace_snr') or []
                if (len(tr) >= 3 and is_repeater_token(tr[0].upper())):
                    nb = tr[1].upper()
                    if len(ts) == 0:
                        neighbor_stats[nb]['trace_attempts'] += 1
                    if len(ts) >= 2:
                        neighbor_stats[nb]['total'] += 1
                        neighbor_stats[nb]['trace_out_sum'] += ts[1]
                        neighbor_stats[nb]['trace_out_count'] += 1
                        outgoing_stats[nb]['total'] += 1
                    if len(ts) >= len(tr):
                        neighbor_stats[nb]['trace_ok'] += 1
                        neighbor_stats[nb]['trace_in_sum'] += ts[-1]
                        neighbor_stats[nb]['trace_in_count'] += 1

            if VERBOSE:
                if outgoing_nbs:
                    color, end = f"{MAGENTA}{BOLD}", RESET
                elif direct_to_obs:
                    color, end = f"{YELLOW}{BOLD}", RESET
                else:
                    color, end = "", ""
                obs_tag = f" {YELLOW}[OBS]{RESET}{color}" if direct_to_obs else ""

                if parsed.get('trace_route') is not None:
                    route_str = '→'.join(parsed['trace_route']) if parsed['trace_route'] else '?'
                    snr_str = ','.join(f"{s:.2f}" for s in parsed['trace_snr']) if parsed['trace_snr'] else '-'
                    print(f"{CYAN}    -> {pkt_label} | route=[{route_str}] SNR=[{snr_str}]{RESET}", flush=True)
                else:
                    dest_tag = f" -> {parsed['dest']}" if parsed.get('dest') else ""
                    print(f"{color}    -> {pkt_label} | hops={hops} path=[{path_str}]{dest_tag}{obs_tag}{end}", flush=True)
                if decrypted:
                    text = decrypted['text']
                    if ': ' in text:
                        sender, body = text.split(': ', 1)
                        print(f"{color}       {decrypted['channel']}: {sender}:{end}", flush=True)
                        for tl in body.split('\n'):
                            print(f"{color}       {tl}{end}", flush=True)
                    else:
                        print(f"{color}       {decrypted['channel']}: {text}{end}", flush=True)
                if outgoing_nbs:
                    print(f"{MAGENTA}       ^^^ бот: исходящий сосед: {','.join(outgoing_nbs)}{RESET}", flush=True)

            if DEBUG_MODE:
                pkt_time = line.split(' U RAW:')[0].strip() if ' U RAW:' in line else '?'
                dest_info = f" -> {parsed['dest']}" if parsed.get('dest') else ""
                obs_info = " [OBS]" if direct_to_obs else ""
                dec_info = ""
                if decrypted:
                    dec_info = f" | {decrypted['channel']}: {decrypted['text']}"
                if parsed.get('trace_snr') is not None:
                    route_str = '→'.join(parsed['trace_route']) if parsed.get('trace_route') else '?'
                    snr_str = ','.join(f"{s:.2f}" for s in parsed['trace_snr']) if parsed['trace_snr'] else '-'
                    log_line = f"{pkt_time} | {pkt_label} | route=[{route_str}] SNR=[{snr_str}]\n"
                else:
                    log_line = f"{pkt_time} | {pkt_label} | hops={hops} path=[{path_str}]{dest_info}{obs_info}{dec_info}\n"
                with open(DEBUG_LOG, 'a') as f:
                    f.write(log_line)

            # TRACE-пакеты: path содержит SNR, не узлы — пропускаем статистику
            is_trace = parsed.get('trace_route') is not None
            if not is_trace:
                for node_hash in parsed['path']:
                    stats[node_hash].setdefault('hops_seen', 0)
                    stats[node_hash]['hops_seen'] += 1

                pkt_time = line.split(' U RAW:')[0].strip() if ' U RAW:' in line else '?'
                if max_hops_record is None or hops > max_hops_record['hops']:
                    max_hops_record = {
                        'time': pkt_time,
                        'hops': hops,
                        'path': parsed['path'],
                        'route_name': parsed['route_name'],
                        'payload_name': parsed['payload_name'],
                        'payload_type': parsed['payload_type'],
                        'payload': parsed['payload'],
                    }

            # Сохраняем примеры распарсенных RAW для диагностики
            if debug['raw_lines'] <= 3:
                debug.setdefault('raw_samples', []).append(
                    f"{pkt_label} | hops={hops} path=[{path_str}]"
                )
        else:
            if debug['raw_lines'] <= 3:
                debug.setdefault('raw_samples', []).append(line)

    # --- Строки, не являющиеся ни RX, ни TX, ни RAW — игнорируем ---
    else:
        debug['ignored'] += 1
        if debug['ignored'] <= 5:
            debug['ignored_samples'].append(line)


def print_stats(stats, cycle_info, debug):
    """Выводит в терминал сводную таблицу статистики по всем узлам сети.

    Включает:
      - Номер цикла и кол-во прочитанных строк
      - Диагностику парсинга (сколько RX/TX/broadcast/ошибок)
      - Таблицу узлов, отсортированную по среднему SNR (лучшие сверху)
      - Общие итоги за цикл: суммарные RX/TX, кол-во уникальных узлов

    Цветовая раскраска:
      - Зелёный: узлы с префиксом NODE_PREFIX (ваши ноды)
      - Голубой: узлы с префиксом REPEATER_PREFIX (ваши ретрансляторы)
      - Жёлтый + жирный: BROADCAST (широковещательные пакеты)
      - Без цвета: остальные узлы

    Args:
        stats: глобальный словарь статистики
        cycle_info: dict с данными текущего цикла (num, lines_read, rx_this, tx_this)
        debug: dict с отладочными счётчиками
    """
    print("\n" + "=" * 70)
    print(f"ЦИКЛ {cycle_info['num']} (прочитано строк: {cycle_info['lines_read']})")
    print("=" * 70)

    print("ДИАГНОСТИКА ПАРСИНГА (за этот цикл):")
    print(f"   Всего обработано: {debug.get('total', 0)}")
    print(f"   RX строк: {debug.get('rx_lines', 0)}")
    print(f"   TX строк: {debug.get('tx_lines', 0)}")
    print(f"   Broadcast RX: {debug.get('broadcast_rx', 0)}")
    print(f"   Broadcast TX: {debug.get('broadcast_tx', 0)}")
    print(f"   Игнорировано: {debug.get('ignored', 0)}")
    print(f"   Malformed: {debug.get('malformed', 0)}")
    print(f"   U RAW строк: {debug.get('raw_lines', 0)}")
    print(f"   Исключения RX: {debug.get('exception', 0)}")
    print(f"   Исключения TX: {debug.get('exception_tx', 0)}")

    if debug.get('rx_samples'):
        print(f"\nПримеры RX строк ({debug.get('rx_lines', 0)} всего):")
        for i, s in enumerate(debug['rx_samples'], 1):
            print(f"   {i}: {s}")

    if debug.get('raw_lines'):
        print(f"\nU RAW пакетов: {debug['raw_lines']}")
        if debug.get('raw_samples'):
            print("Примеры:")
            for i, s in enumerate(debug['raw_samples'], 1):
                print(f"   {i}: {s}")

    if debug.get('ignored_samples'):
        print(f"\nПримеры игнорированных строк:")
        for i, s in enumerate(debug['ignored_samples'], 1):
            print(f"   {i}: {repr(s)}")

    print("-" * 70)

    # Сортируем узлы по среднему SNR (лучший сигнал — сверху)
    sorted_nodes = sorted(
        stats.items(),
        key=lambda x: x[1]['snr_sum'] / x[1]['snr_count'] if x[1]['snr_count'] > 0 else -1000,
        reverse=True
    )

    total_rx_all = sum(d['rx'] for d in stats.values())
    print(f"\nНАКОПИТЕЛЬНАЯ СТАТИСТИКА (всего RX: {total_rx_all}):")
    print(f"{'Узел':<8} {'RX':>6} {'TX':>6} {'Hops':>6} {'Ошибки':>8} {'SNR ср':>8} {'RSSI ср':>8}")
    print("-" * 70)

    for node, data in sorted_nodes:
        avg_snr = data['snr_sum'] / data['snr_count'] if data['snr_count'] > 0 else 0
        avg_rssi = data['rssi_sum'] / data['rssi_count'] if data['rssi_count'] > 0 else 0
        hops_seen = data.get('hops_seen', 0)

        if node == BROADCAST_NODE:
            base_name = "BCAST"
        else:
            base_name = node

        base_line = f"{base_name:<8} {data['rx']:>6} {data['tx']:>6} {hops_seen:>6} {data['errors']:>8} {avg_snr:>7.1f}dB {avg_rssi:>7.1f}dB"

        # Цветовая раскраска: ноды — зелёным, ретрансляторы — голубым, broadcast — жёлтым
        if node == BROADCAST_NODE:
            print(f"{YELLOW}{BOLD}{base_line}{RESET}")
        elif is_repeater_token(node):
            print(f"{CYAN}{base_line}{RESET}")
        elif node.startswith(NODE_PREFIX):
            print(f"{GREEN}{base_line}{RESET}")
        else:
            print(base_line)

    print("-" * 70)

    # Общие итоги за цикл
    num_nodes = len([n for n in stats if n != BROADCAST_NODE])

    print(f"\nЗА ЭТОТ ЦИКЛ: RX: {cycle_info['rx_this']}, TX: {cycle_info['tx_this']}")
    print(f"ВСЕГО уникальных узлов: {num_nodes}")

    print("=" * 70)


def decrypt_group_msg(payload):
    """Пытается расшифровать payload группового сообщения (GRP_TXT/GRP_DATA).

    Формат payload (MeshCore v1):
      [channel_hash:1][MAC:2][ciphertext]

    Ciphertext = AES-128-ECB(channel_key, plaintext), zero-padded до кратности 16.
    Plaintext:  [timestamp:4][flags:1][sender_name: message_text][zero_padding]

    Channel_key = SHA256(channel_name)[:16]
    Channel_hash = SHA256(channel_key)[0]

    При коллизиях хешей пробуем все подходящие ключи.

    Args:
        payload: bytes полного payload (включая channel_hash)

    Returns:
        dict {'channel': имя, 'hash': hex-строка, 'text': расшифрованный текст}
        или None если расшифровка не удалась
    """
    if not HAS_CRYPTO or len(payload) < 4:
        return None

    ch_hash = payload[0]
    if ch_hash not in CHANNEL_KEYS:
        return None

    # MAC (2 байта) + ciphertext
    ciphertext = bytes(payload[3:])

    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        return None

    # Пробуем все ключи с совпадающим хешем (обработка коллизий)
    for ch_name, key in CHANNEL_KEYS[ch_hash]:
        try:
            cipher = AES.new(key, AES.MODE_ECB)
            plaintext = cipher.decrypt(ciphertext)

            # Пропускаем timestamp (4B) и flags (1B), остальное — текст
            if len(plaintext) < 6:
                continue
            text = plaintext[5:].rstrip(b'\x00').decode('utf-8', errors='ignore').strip()

            # Проверяем, что расшифрованный текст похож на читаемый
            if text and sum(c.isprintable() for c in text) > len(text) // 2:
                return {'channel': ch_name, 'hash': f"{ch_hash:02X}", 'text': text}
        except Exception:
            continue

    return None


def decode_payload_info(payload_type, payload):
    """Извлекает доступную информацию из payload пакета.

    Args:
        payload_type: числовой тип payload (из header)
        payload: bytes сырых данных payload

    Returns:
        str с описанием содержимого
    """
    if not payload:
        return ""

    # GRP_TXT (5) / GRP_DATA (6): пытаемся расшифровать, иначе показываем хеш канала
    if payload_type in (0x05, 0x06):
        decrypted = decrypt_group_msg(payload)
        if decrypted:
            return f"Канал: {decrypted['channel']} | {decrypted['text']}"
        channel_hash = f"{payload[0]:02X}"
        return f"Канал: {channel_hash} (текст зашифрован)"

    # ADVERT (4): pubkey(32) + timestamp(4) + signature(64) + appdata
    if payload_type == 0x04 and len(payload) > 100:
        appdata = payload[100:]
        if appdata:
            flags = appdata[0]
            node_type_map = {0x01: 'Chat', 0x02: 'Repeater', 0x03: 'Room Server', 0x04: 'Sensor'}
            node_type = node_type_map.get(flags & 0x0F, f'?{flags & 0x0F:02X}')
            # Пропускаем опциональные поля, ищем имя в конце appdata
            name = ""
            if flags & 0x80:
                # Имя — последнее поле appdata, после lat/long/features
                offset = 1
                if flags & 0x10:
                    offset += 8  # lat + long
                if flags & 0x20:
                    offset += 2  # feature 1
                if flags & 0x40:
                    offset += 2  # feature 2
                if offset < len(appdata):
                    try:
                        name = appdata[offset:].decode('utf-8', errors='ignore').strip()
                    except Exception:
                        pass
            result = f"Тип: {node_type}"
            if name:
                result += f", Имя: {name}"
            return result

    # REQ/RESPONSE/TXT_MSG/ACK и др.: dst/src hash
    if payload_type in (0x00, 0x01, 0x02, 0x08) and len(payload) >= 2:
        dst_hash = f"{payload[0]:02X}"
        src_hash = f"{payload[1]:02X}"
        return f"[{src_hash}->{dst_hash}]"

    return ""


def print_max_hops(cycle_info):
    """Выводит информацию о пакете с максимальным числом хопов."""
    print("\n" + "=" * 70)
    print(f"РЕКОРД ХОПОВ (цикл {cycle_info['num']})")
    print("=" * 70)

    if not max_hops_record:
        print("  Нет данных")
        print("=" * 70)
        return

    r = max_hops_record
    path_str = ','.join(r['path']) if r['path'] else '-'
    pkt_label = f"{r['route_name']} {r['payload_name']}"
    payload_info = decode_payload_info(r['payload_type'], r['payload'])

    print(f"  Время:  {r['time']}")
    print(f"  Тип:    {pkt_label}")
    print(f"  Хопов:  {r['hops']}")
    print(f"  Path:   [{path_str}]")
    if payload_info:
        print(f"  Инфо:   {payload_info}")

    print("=" * 70)


def print_neighbors(cycle_info):
    """Выводит таблицу соседей — узлов, доставляющих пакеты ретранслятору и наблюдателю.

    Сосед определяется из path FLOOD-пакетов.
    SNR→/SNR← — средние уровни сигнала из TRACE-пакетов.

    Args:
        cycle_info: dict с данными цикла
    """
    print("\n" + "=" * 70)
    print(f"СОСЕДИ (цикл {cycle_info['num']})")
    print("=" * 70)

    if not neighbor_stats:
        print("  Нет данных о соседях")
        print("=" * 70)
        return

    sorted_neighbors = sorted(neighbor_stats.items(), key=lambda x: x[1]['total'], reverse=True)
    grand_total = sum(d['total'] for d in neighbor_stats.values())

    print(f"{'Сосед':<8} {'Пакетов':>8} {'%':>6} {'SNR→':>7} {'SNR←':>7} {'Trace':>7}")
    print("-" * 70)

    for node, data in sorted_neighbors:
        pct = data['total'] / grand_total * 100 if grand_total > 0 else 0

        snr_out = f"{data['trace_out_sum'] / data['trace_out_count']:.2f}" if data.get('trace_out_count') else "-"
        snr_in = f"{data['trace_in_sum'] / data['trace_in_count']:.2f}" if data.get('trace_in_count') else "-"
        attempts = data.get('trace_attempts', 0)
        trace_col = f"{data.get('trace_ok', 0)}/{attempts}" if attempts else "-"

        base_line = f"{node:<8} {data['total']:>8} {pct:>5.1f}% {snr_out:>7} {snr_in:>7} {trace_col:>7}"

        if is_repeater_token(node):
            print(f"{CYAN}{base_line}{RESET}")
        elif node.startswith(NODE_PREFIX):
            print(f"{GREEN}{base_line}{RESET}")
        else:
            print(base_line)

    print("-" * 70)
    print(f"Всего пакетов от соседей: {grand_total}")
    print("=" * 70)


def print_outgoing_neighbors(cycle_info):
    """Выводит таблицу исходящих соседей — через кого уходят наши сообщения.

    Определяется из расшифрованных групповых сообщений, содержащих
    "Found N unique path(s): XX,YY,ZZ,...". Если первый хоп совпадает
    с REPEATER_PREFIX, то второй хоп — исходящий сосед.

    Args:
        cycle_info: dict с данными цикла
    """
    print("\n" + "=" * 70)
    print(f"ИСХОДЯЩИЕ СОСЕДИ (цикл {cycle_info['num']})")
    print("=" * 70)

    if not outgoing_stats:
        print("  Нет данных (включите --api или ждите расшифрованных сообщений с path)")
        print("=" * 70)
        return

    sorted_out = sorted(outgoing_stats.items(), key=lambda x: x[1]['total'], reverse=True)
    grand_total = sum(d['total'] for d in outgoing_stats.values())

    print(f"{'Сосед':<8} {'Пакетов':>8} {'%':>6}")
    print("-" * 70)

    for node, data in sorted_out:
        pct = data['total'] / grand_total * 100 if grand_total > 0 else 0
        base_line = f"{node:<8} {data['total']:>8} {pct:>5.1f}%"

        if node.upper().startswith(REPEATER_PREFIX.upper()):
            print(f"{CYAN}{base_line}{RESET}")
        elif node.upper().startswith(NODE_PREFIX.upper()):
            print(f"{GREEN}{base_line}{RESET}")
        else:
            print(base_line)

    print("-" * 70)
    print(f"Всего исходящих через соседей: {grand_total}")
    print("=" * 70)


def fetch_outgoing_from_api(repeater_prefix):
    """Получает пакеты из API MeshCoreTel и обновляет outgoing_stats.

    Ищет пакеты, в path_hops которых встречается repeater_prefix.
    Следующий хоп после repeater_prefix — исходящий сосед.
    Дедупликация по hash пакета (один пакет виден нескольким наблюдателям).
    Пагинация: забирает все новые пакеты с момента последнего запроса.

    Returns:
        int: количество новых исходящих соседей, найденных в этом запросе
    """
    global _api_last_id
    prefix_upper = repeater_prefix.upper()
    found = 0
    total_fetched = 0
    page_limit = 500
    max_pages = 5

    for page in range(max_pages):
        try:
            url = f'{MESHCORETEL_API}?limit={page_limit}'
            if _api_last_id is not None:
                url += f'&since_id={_api_last_id}'
            req = urllib.request.Request(url, headers={'User-Agent': 'meshcore-analyzer'})
            with urllib.request.urlopen(req, timeout=30) as resp:
                packets = json.loads(resp.read())
        except Exception:
            if VERBOSE:
                print(f"  {YELLOW}[API] таймаут, повтор через 15 сек{RESET}", flush=True)
            break

        if not packets:
            break

        total_fetched += len(packets)
        min_id = min(p['id'] for p in packets)
        max_id = max(p['id'] for p in packets)
        if _api_last_id is None or max_id > _api_last_id:
            _api_last_id = max_id

        for pkt in packets:
            pkt_hash = pkt.get('hash', '')
            if not pkt_hash or pkt_hash in _api_seen_hashes:
                continue
            _api_seen_hashes.add(pkt_hash)

            if pkt.get('payload_type') == 0x09:
                continue

            hops = pkt.get('path_hops')
            if not hops:
                continue

            for i, hop in enumerate(hops):
                if hop.upper() != prefix_upper:
                    continue
                if i + 1 >= len(hops):
                    break
                neighbor = hops[i + 1].upper()
                outgoing_stats[neighbor]['total'] += 1
                found += 1
                origin = pkt.get('origin', '?')
                path_str = ' → '.join(hops)
                ptype = PAYLOAD_TYPES.get(pkt.get('payload_type', -1), '?')
                if VERBOSE:
                    print(f"  {CYAN}[API] {origin}: {ptype} "
                          f"[{path_str}] → сосед {BOLD}{neighbor}{RESET}", flush=True)
                if DEBUG_MODE:
                    with open(DEBUG_LOG, 'a') as f:
                        f.write(f"[API] {origin}: {ptype} [{path_str}] → сосед {neighbor}\n")
                break

        if len(packets) < page_limit:
            break

    if len(_api_seen_hashes) > 50000:
        _api_seen_hashes.clear()

    return found


def _api_poller(repeater_prefix, stop_event):
    """Фоновый поток: периодически опрашивает API MeshCoreTel, пока не попросят остановиться.

    Работает независимо от состояния USB-порта: даже при потере Observer
    продолжает обновлять outgoing_stats через MeshCoreTel.
    """
    poll_interval = 15
    while not stop_event.is_set():
        fetch_outgoing_from_api(repeater_prefix)
        # Спим интервал, но проверяем stop_event каждую секунду
        for _ in range(poll_interval):
            if stop_event.is_set():
                return
            time.sleep(1)


def _serial_reader(ser, line_queue, stop_event, error_event):
    """Фоновый поток: непрерывно читает серийный порт и кладёт строки в очередь.

    Работает даже во время вывода статистики, чтобы не терять пакеты
    из-за переполнения буфера серийного порта.
    При ошибке порта устанавливает error_event для уведомления основного потока.
    """
    while not stop_event.is_set():
        try:
            if ser.in_waiting:
                line = ser.readline().decode('utf-8', errors='ignore').strip()
                if line:
                    line_queue.put(line)
            else:
                time.sleep(0.02)
        except Exception:
            error_event.set()
            break


RECONNECT_INTERVAL = 5  # секунд между попытками переподключения


def _wait_for_port(port):
    """Ожидает появления серийного порта, проверяя каждые RECONNECT_INTERVAL сек."""
    while True:
        if os.path.exists(port):
            return
        time.sleep(RECONNECT_INTERVAL)


def _connect_and_run(args, port, cycle_counter):
    """Подключается к порту, запускает чтение и цикл анализа.

    Возвращает True если нужно переподключиться, False если завершение.
    """
    ser = None
    stop_event = threading.Event()
    error_event = threading.Event()
    reader_thread = None
    try:
        ser = serial.Serial(port, BAUDRATE, timeout=1)
        print(f"\nПодключён к {port}")
        print(f"Цикл статистики: каждые {CYCLE_TIME} сек")
        if HAS_CRYPTO:
            print(f"Дешифрование каналов: {', '.join(KNOWN_CHANNEL_NAMES)}")
        else:
            print(f"{YELLOW}pycryptodome не установлен — расшифровка каналов отключена{RESET}")
        if args.api:
            print(f"API meshcoretel.ru: исходящие соседи для префикса {args.repeater}")
        if DEBUG_MODE:
            print(f"Отладка ->OBS: пакеты пишутся в {DEBUG_LOG}")
        print(flush=True)
        time.sleep(2)

        send_cmd(ser, "log start")
        time.sleep(1)
        # Диагностика: проверяем, отвечает ли порт
        waiting = ser.in_waiting
        test_line = ser.readline().decode('utf-8', errors='ignore').strip() if waiting else ''
        print(f"Логирование включено (буфер: {waiting} байт, ответ: '{test_line}')", flush=True)

        line_queue = queue.Queue()
        reader_thread = threading.Thread(
            target=_serial_reader, args=(ser, line_queue, stop_event, error_event),
            daemon=True
        )
        reader_thread.start()

        while True:
            cycle_counter[0] += 1

            debug = {
                'total': 0, 'rx_lines': 0, 'tx_lines': 0,
                'ignored': 0, 'malformed': 0, 'broadcast_rx': 0,
                'broadcast_tx': 0, 'exception': 0, 'exception_tx': 0,
                'ignored_samples': [], 'no_src_dst': 0,
            }

            lines_read = 0
            cycle_start = time.time()

            last_data_time = time.time()
            while time.time() - cycle_start < CYCLE_TIME:
                if error_event.is_set():
                    raise serial.SerialException("Устройство отключено")
                try:
                    line = line_queue.get(timeout=0.1)
                    lines_read += 1
                    last_data_time = time.time()
                    parse_line(line, stats, debug)
                except queue.Empty:
                    if time.time() - last_data_time > 1800:
                        try:
                            ser.write(b"log start\r\n")
                        except (serial.SerialException, OSError):
                            raise serial.SerialException("Порт отключён")
                        last_data_time = time.time()
                        if VERBOSE:
                            print(f"  {YELLOW}[!] нет данных 30 мин, переотправка log start{RESET}", flush=True)

            cycle_info = {
                'num': cycle_counter[0],
                'lines_read': lines_read,
                'rx_this': debug['rx_lines'],
                'tx_this': debug['tx_lines'],
            }

            if args.original:
                print_stats(stats, cycle_info, debug)
            if args.neighbors:
                print_neighbors(cycle_info)
                print_outgoing_neighbors(cycle_info)
            if args.hops:
                print_max_hops(cycle_info)

            save_stats()

    except (serial.SerialException, OSError) as e:
        save_stats()
        print(f"\n{YELLOW}Потеря соединения: {e}{RESET}", flush=True)
        return True
    finally:
        stop_event.set()
        if reader_thread:
            reader_thread.join(timeout=2)
        if ser:
            try:
                ser.close()
            except Exception:
                pass


def main(args):
    """Главный цикл работы анализатора с автоматическим переподключением.

    USB-часть (Observer по серийному порту) и API MeshCoreTel работают независимо:
    при потере USB API-прослушка продолжает обновлять исходящих соседей.
    """
    port = args.port
    cycle_counter = [0]

    api_stop_event = threading.Event() if args.api else None
    api_thread = None

    try:
        # Глобальный API-поллер, не зависящий от состояния USB-порта
        if args.api:
            api_thread = threading.Thread(
                target=_api_poller,
                args=(args.repeater, api_stop_event),
                daemon=True,
            )
            api_thread.start()

        while True:
            if not os.path.exists(port):
                print(f"Порт {port} не найден. Ожидание подключения...", flush=True)
                _wait_for_port(port)
                time.sleep(2)

            need_reconnect = _connect_and_run(args, port, cycle_counter)
            if not need_reconnect:
                break

            if args.api:
                print(f"Ожидание переподключения к {port}... (API продолжает работать)", flush=True)
            else:
                print(f"Ожидание переподключения к {port}...", flush=True)
            _wait_for_port(port)
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n\nОстановлено пользователем")
        total_rx = sum(d['rx'] for d in stats.values())
        total_tx = sum(d['tx'] for d in stats.values())
        cycle_info = {
            'num': 'ИТОГО',
            'lines_read': '-',
            'rx_this': total_rx,
            'tx_this': total_tx,
        }
        if args.original:
            print_stats(stats, cycle_info, {})
        if args.neighbors:
            print_neighbors(cycle_info)
            print_outgoing_neighbors(cycle_info)
        if args.hops:
            print_max_hops(cycle_info)
        save_stats()
    finally:
        # Аккуратно останавливаем глобальный API-поток
        if api_stop_event is not None:
            api_stop_event.set()
        if api_thread is not None:
            api_thread.join(timeout=2)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Анализатор пакетов Meshcore Observer. "
                    "Подключается к ноде Room Server по серийному порту, "
                    "собирает логи и выводит статистику по узлам сети.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Цвета в таблице статистики:\n"
               f"  {GREEN}Зелёный{RESET}        — ноды-компаньоны (префикс {NODE_PREFIX})\n"
               f"  {CYAN}Голубой{RESET}        — ретрансляторы (префикс {REPEATER_PREFIX})\n"
               f"  {YELLOW}{BOLD}Жёлтый жирный{RESET}  — широковещательные пакеты (BCAST)\n"
               "  Без цвета      — остальные узлы\n"
               "\nПеред запуском отключите веб-консоль (flasher.meshcore.dev) от серийного порта."
    )
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Выводить каждый проходящий пакет в реальном времени')
    parser.add_argument('-o', '--original', action='store_true',
                        help='Показывать накопительную статистику по узлам (RX/TX/SNR/RSSI)')
    parser.add_argument('-n', '--neighbors', action='store_true',
                        help='Показывать таблицы входящих и исходящих соседей '
                             '(входящие — из path, исходящие — из расшифрованных сообщений)')
    parser.add_argument('--hops', action='store_true',
                        help='Показывать пакет-рекордсмен по числу хопов '
                             '(тип, путь, канал для групповых сообщений)')
    parser.add_argument('-p', '--port', default=PORT,
                        help=f'Серийный порт Observer-ноды (по умолчанию {PORT})')
    parser.add_argument('--api', action='store_true',
                        help='Получать исходящих соседей из API meshcoretel.ru '
                             '(не требует отправки p/mt в канал)')
    parser.add_argument('--repeater', default=REPEATER_PREFIX,
                        help=f'Префикс ретранслятора для поиска через API '
                             f'(по умолчанию {REPEATER_PREFIX})')
    parser.add_argument('--bots', action='store_true',
                        help='Определять исходящих соседей из ответов ботов в каналах '
                             '(требует отправки p/mt через meshcore-probe)')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Логировать пакеты, принятые observer напрямую (->OBS), '
                             f'в файл {DEBUG_LOG}')
    parser.add_argument('--reset', action='store_true',
                        help='Сбросить сохранённую статистику и начать с нуля')
    args = parser.parse_args()
    VERBOSE = args.verbose
    BOTS_MODE = args.bots
    DEBUG_MODE = args.debug
    if args.api and not args.neighbors:
        args.neighbors = True
    # Если ни один режим вывода не указан, показываем оригинальную статистику
    if not args.original and not args.neighbors and not args.hops:
        args.original = True
    # Загрузка или сброс статистики
    if args.reset:
        removed = []
        for f in (STATS_FILE, DEBUG_LOG):
            if os.path.exists(f):
                os.remove(f)
                removed.append(os.path.basename(f))
        print(f"Сброшено: {', '.join(removed)}" if removed else "Нечего сбрасывать")
    else:
        load_stats()
    main(args)