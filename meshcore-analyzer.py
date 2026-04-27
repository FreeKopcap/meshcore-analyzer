"""Meshcore Analyzer — анализатор пакетов MeshCore Observer.

Version: 3.7

Changelog:
  v3.7 — Несколько ваших репитеров (3-байтные адреса), без перекрёстных соседей
    - MY_REPEATERS_HEX: список 3-байтных адресов ваших репитеров
      (по умолчанию ['333333','343434']) вместо одной 1-байтной константы
      REPEATER_PREFIX. Можно переопределить через --repeaters
    - is_my_repeater(token) сравнивает токены 2/4/6 hex с префиксом
      соответствующей длины из MY_REPEATERS_HEX. Убраны ложные срабатывания
      при bph=3 на чужих узлах вида 34xxxx, попадавшие под старый
      startswith(REPEATER_PREFIX)
    - Пакеты, ретранслированные между моими же репитерами (33 → 34, 34 → 33),
      больше не учитываются ни в neighbor_stats, ни в outgoing_stats —
      это перекрёстная служебная пересылка, а не сосед. Применяется в
      path FLOOD, TRACE, API и в extract_outgoing_neighbors
    - CLI: --repeater (одиночный префикс) заменён на --repeaters
      (список через запятую). API ищет любой из адресов
    - В MQTT-only режиме (без -u/--usb) скрыт блок «ДИАГНОСТИКА ПАРСИНГА»
      и связанные примеры RX/RAW/ignored — они всегда показывают нули,
      т.к. parse_line() для USB-лога не вызывается
    - extract_outgoing_neighbors: добавлен Паттерн 4 для ответа роботов вида
      "@[name] <текст> = XX,YY,..." (например, VAO Hekru: pong/discover).
      Паттерн 3 расширен с 2/4 hex до 2/4/6 hex, чтобы поддерживать 3-байтные
      хопы (Meshcore 1.14+ packed path)
  v3.6 — Устойчивый MQTT-коннект, чище вывод в MQTT-only
    - Ретрай первичного connect() с видимым логом "попытка #N" (каждые 5с)
    - reconnect_delay_set(1..30s) для авто-реконнекта paho после установленной сессии
    - Транзиентный EHOSTUNREACH (протухший ARP, засыпание Wi-Fi) больше не роняет
      MQTT-поток: ретраим до успеха или остановки
    - В MQTT-only режиме таблица НАКОПИТЕЛЬНАЯ СТАТИСТИКА скрыта: без USB
      у транзитных узлов всё равно RX/TX/SNR/RSSI = 0 (заполняются только
      для прямых соседей, а они уже есть в таблице СОСЕДИ)
  v3.5 — DIRECT TRACE по спецификации MeshCore 1.11+, мелкие правки
    - Канал Public: расшифровка по общему PSK MeshCore (Base64), HMAC(2)+AES как в Utils::MACThenDecrypt
    - TRACE: поле path на wire — только байты SNR; длина — path_len & 0x3F; маршрут в payload с байта 9
    - Ширина хэша маршрута TRACE: flags & 3 → 1/2/4/8 байт на хоп (как в Mesh::onRecvPacket)
    - Verbose, debug и учёт соседей (SNR→/SNR←) по типу 0x09 + DIRECT, не по «trace_route is not None»
    - DIRECT TRACE: не подставлять первые 6 байт payload как dest (там tag/auth, не pubkey)
    - MQTT: при разборе сырого hex задан path_bytes_per_hop (исправлено обращение к bph)
    - Packed path_len: ветка расширения 0b11 по proposal MeshCore#1083 (2B 32-й хоп как 0xD1)
    - MQTT: режим только --mqtt (таймер статистики); CLI --mqtt-tcp/--mqtt-broker для локального брокера
    - MQTT JSON с полем raw: полный разбор как U RAW (GRP, verbose -v, hops_seen, рекорды хопов)
    - Таблица СОСЕДИ: колонка «Приём» (средний SNR с USB RX или из JSON MQTT по тому же соседу)
    - meshcore-mqtt-bridge.py: локальный брокер → пересылка на meshcoretel.ru
  v3.4 — Исправления выбора длины маршрута и debug-логирования
    - API отключён по умолчанию: опрос MeshCoreTel только с флагом --api
    - Исправлен выбор 2B/3B при длинных аномальных 1B-путях (сначала 3B, затем 2B)
    - Исправлен выбор packed path_len для неоднозначных пакетов (устранено завышение hops)
    - Debug: корректная привязка RX hash к U RAW и явная запись строки RAW: <hex> в debug-лог
  v3.3 — Маршруты 1/2/3 байта на хоп (1.14+), шум эфира, подсветка режимов
    - Парсинг packed path_len: mode+hops в одном байте (1/2/3 байта на хоп)
    - Корректная расшифровка GRP_TXT/GRP_DATA при 2B/3B маршрутах (выбор валидной раскладки)
    - Подсветка [2B]/[3B] в verbose и в «Рекорд хопов»
    - Подавление спама DEBUG noise_floor в выводе; среднее noise_floor за цикл в таблице «СОСЕДИ»
    - Debug: связывание hash из RX со строкой U RAW и вывод RAW для «Пакеты только USB»
  v3.2 — Версия 3.2, опция -u для USB
    - Нумерация и описание: API только с --api, USB только с -u/--usb
    - Сравнение USB vs API в debug: только при -u и --api (без API блок не печатается)
  v3.1 — API и USB по опциям
    - Опрос API meshcoretel.ru только с --api (без серийного порта)
    - Опция -u/--usb: дополнительно прослушивать Observer по USB
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

__version__ = '3.7'

import serial
import time
import sys
import os
import re
import json
import argparse
import hashlib
import hmac
import base64
import threading
import queue
import urllib.request
from collections import defaultdict
from collections import deque

try:
    from Crypto.Cipher import AES
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import paho.mqtt.client as mqtt
    HAS_MQTT = True
except ImportError:
    HAS_MQTT = False

# ========== ANSI-коды цветов для терминального вывода ==========
GREEN = '\033[92m'
CYAN = '\033[96m'
YELLOW = '\033[93m'
RED = '\033[91m'
MAGENTA = '\033[95m'
BLUE = '\033[94m'
RESET = '\033[0m'
BOLD = '\033[1m'
# ===============================================================


def is_my_repeater(token: str) -> bool:
    """Возвращает True, если hex-токен в path/trace_route относится к одному
    из ваших репитеров (см. MY_REPEATERS_HEX).

    В пакете токен может быть 2 hex (bph=1), 4 hex (bph=2) или 6 hex (bph=3)
    символов. Сравниваем с префиксом длины n каждого полного адреса из
    MY_REPEATERS_HEX. Например для адреса 343434:
      - токен '34'      → True (1B-маршрут);
      - токен '3434'    → True (2B-маршрут);
      - токен '343434'  → True (3B-маршрут);
      - токен '343535'  → False;
      - токен '34xxxx'  → False (чужой узел с тем же первым байтом).

    Длины, не входящие в {2,4,6} (например, после нормализации MQTT) матчим
    в обе стороны, чтобы не потерять совпадение.
    """
    if not token:
        return False
    t = token.upper()
    n = len(t)
    if n in (2, 4, 6):
        return any(rep[:n] == t for rep in MY_REPEATERS_HEX)
    return any(rep.startswith(t) or t.startswith(rep) for rep in MY_REPEATERS_HEX)


# Наборы hash-пакетов для сравнения USB vs API.
# _usb_hashes_curr  — USB-пакеты текущего цикла;
# _usb_hashes_prev  — USB-пакеты предыдущего цикла;
# _api_hashes_curr  — API-пакеты текущего интервала;
# _api_hashes_prev  — API-пакеты предыдущего интервала.
_usb_hashes_curr = set()
_usb_hashes_prev = set()
_api_hashes_curr = set()
_api_hashes_prev = set()

# Для USB-пакетов дополнительно запоминаем пример строки RX по hash,
# чтобы в отладочном выводе можно было увидеть конкретные пакеты,
# которых нет в API.
_usb_hash_to_line_curr = {}
_usb_hash_to_line_prev = {}

# При --debug: пытаемся связать U RAW (без hash) с U: RX (с hash),
# чтобы для "только USB" можно было увидеть сырой hex и path конкретного hash.
_usb_hash_to_raw_curr = {}
_usb_hash_to_raw_prev = {}
_recent_raw_usb = deque(maxlen=50)  # элементы: {'payload_type','route_char','payload_len','hex','path'}

# Накопительный счётчик пакетов, которые увидели по USB, но не увидели в API.
_usb_only_total = 0

# При --debug: множество origin, увиденных в API за цикл (для диагностики фильтра).
_api_origins_seen = set()

# ========== КОНФИГУРАЦИЯ ==========
# Серийный порт, к которому подключена нода Meshcore.
# macOS: обычно /dev/cu.usbmodemXXXX или /dev/cu.usbserial-XXXX
# Windows: COM24, COM3 и т.д.
# PORT = '/dev/cu.usbmodemE8F60ACB1A401'    # коричневый корпус
PORT = '/dev/cu.usbmodemE8F60ACB19781'      # черный корпус
# PORT = '/dev/cu.usbmodemB0A604C57F281'    # Черный репитер (старый)

BAUDRATE = 115200

# Префикс hex-адресов ваших нод-компаньонов. Подсвечиваются зелёным в таблице.
NODE_PREFIX = '10'
# Адреса ваших ретрансляторов (полные 3-байтные hex-адреса).
# В path пакета адрес может приходить как первый байт (bph=1: '33'/'34'),
# первые два (bph=2: '3333'/'3434') или полностью (bph=3: '333333'/'343434').
# Подсвечиваются голубым в таблицах. Можно переопределить через --repeaters.
MY_REPEATERS_HEX = ['333333', '343434']

# Байт на хоп в маршруте (1 — старые прошивки; 2/3 — Meshcore 1.14+).
# В логах Observer путь приходит как последовательность байт; адрес ретранслятора
# занимает 1/2/3 байта в зависимости от прошивки. Принадлежность токена вашему
# репитеру определяется через is_my_repeater() — сравнение префикса
# соответствующей длины с каждым адресом из MY_REPEATERS_HEX.
PATH_BYTES_PER_HOP = 1

# Префиксы origin-нод в API MeshCoreTel, соответствующие вашему Observer/репитеру.
# Сравнение идёт по startswith; если список пустой — для сравнения USB/API
# учитываются все origin.
OBSERVER_ORIGINS = ['MO Zvenigorod Room']

# Виртуальный адрес для пакетов без конкретного источника (широковещательные).
BROADCAST_NODE = 'BCAST'

# Имя бота, передающего маршруты в формате "XX: Описание репитера" (паттерн 2).
PATHBOT_SENDER = 'AetherByte\U0001f916'  # AetherByte🤖

# Имена ваших компаньонов для обработки ack@[...] без префикса репитера.
MY_COMPANIONS = ['Kopcap V4️⃣', 'Kopcap 1️⃣1️⃣4️⃣']

# MQTT MeshCoreTel — настройки для подписки на поток пакетов (как при set mqtt.* на наблюдателе).
# Подключение к тому же брокеру, куда наблюдатель отправляет пакеты.
MQTT_SERVER = 'meshcoretel.ru'
MQTT_PORT = 1883          # TCP (если MQTT_USE_WEBSOCKETS = False)
MQTT_PORT_WS = 9001       # WebSockets (analyzer.letsme.sh/observer: порт 9001, WebSockets)
MQTT_USE_WEBSOCKETS = True   # наблюдатель подключается по WS:9001, не TCP:1883
MQTT_USERNAME = 'meshcore'
MQTT_PASSWORD = 'meshcore'
# Топики подписки (формат meshcoretomqtt: meshcore/{IATA}/{PUBLIC_KEY}/packets).
# Подписка на # брокер может запрещать; используем явные шаблоны с +.
MQTT_TOPICS = [
    'meshcore/+/+/packets',   # пакеты от любых репитеров/наблюдателей
    'meshcore/+/+/status',    # статус онлайн/офлайн
]
# Дополнительно топики для вашего IATA (mqtt.iata MOW), если брокер различает по региону:
MQTT_TOPICS_IATA = ['meshcore/MOW/+/packets', 'meshcore/MOW/+/status']

# Сколько первых MQTT-сообщений вывести в лог как образец формата (0 = не выводить).
MQTT_LOG_FIRST_N_RAW = 10

# Интервал между циклами сбора статистики (секунды).
CYCLE_TIME = 60

# Таймаут чтения лога из серийного порта (секунды).
READ_TIMEOUT = 5

# Известные публичные каналы для расшифровки групповых сообщений.
# Именованные: ключ = SHA256(имя)[:16], хеш = SHA256(ключа)[0] (как в старых заметках к анализатору).
# Канал «Public» в прошивке MeshCore — отдельно: PSK Base64 и хеш = SHA256(PSK)[0] (см. BaseChatMesh::addChannel).
KNOWN_CHANNEL_NAMES = [
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

# Общий PSK канала Public (как в examples companion_radio / simple_secure_chat).
PUBLIC_GROUP_PSK_B64 = 'izOH6cXN6mrJ5e26oRXNcg=='

# ========== КЛЮЧИ КАНАЛОВ ==========
# Именованные: AES-ключ = SHA256(имя)[:16], хеш на wire = SHA256(AES-ключа)[0].
# При коллизиях хешей пробуем все варианты.
# Структура: channel_hash -> [(имя, AES-ключ 16 байт), ...]
CHANNEL_KEYS = {}
for _ch_name in KNOWN_CHANNEL_NAMES:
    _key = hashlib.sha256(_ch_name.encode()).digest()[:16]
    _ch_hash = hashlib.sha256(_key).digest()[0]
    CHANNEL_KEYS.setdefault(_ch_hash, []).append((_ch_name, _key))

# Каналы с PSK (MeshCore v1: encryptThenMAC / MACThenDecrypt).
# secret на wire: 16 или 32 байта PSK, в HMAC ключ дополняется нулями до 32 байт.
# channel.hash[0] = SHA256(PSK)[0] (длина 16 или 32 как при addChannel).
# Структура: channel_hash -> [(имя, secret32), ...]
CHANNEL_PSK = {}


def _register_psk_channel(name: str, psk_b64: str) -> None:
    raw = base64.b64decode(psk_b64)
    if len(raw) not in (16, 32):
        return
    sec32 = bytearray(32)
    sec32[: len(raw)] = raw
    sec32 = bytes(sec32)
    ch_h = hashlib.sha256(raw).digest()[0]
    CHANNEL_PSK.setdefault(ch_h, []).append((name, sec32))


_register_psk_channel('Public', PUBLIC_GROUP_PSK_B64)
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

# Рекорды максимального числа хопов отдельно по 1B/2B/3B.
max_hops_by_bph = {1: None, 2: None, 3: None}

# Путь к файлу сохранения статистики (рядом со скриптом)
STATS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'meshcore-stats.json')

# API MeshCoreTel для получения пакетов от всех наблюдателей региона
MESHCORETEL_API = 'https://meshcoretel.ru/api/packets'

# ID последнего обработанного пакета из API (для инкрементальных запросов)
_api_last_id = None
# Множество обработанных хешей пакетов (дедупликация: один пакет виден многим наблюдателям)
_api_seen_hashes = set()

# Счётчик залогированных сырых MQTT-сообщений (для вывода образцов формата).
_mqtt_samples_logged = 0
# Счётчик всех пришедших MQTT-сообщений (для диагностики «ничего не приходит»).
_mqtt_messages_received = 0


def save_stats():
    """Сохраняет накопленную статистику в JSON-файл."""
    data = {
        'stats': dict(stats),
        'neighbor_stats': dict(neighbor_stats),
        'outgoing_stats': dict(outgoing_stats),
        'max_hops_by_bph': {},
    }
    # Отдельные рекорды по 1B/2B/3B
    try:
        for bph, rec in max_hops_by_bph.items():
            if not rec:
                continue
            r = dict(rec)
            if isinstance(r.get('payload'), (bytes, bytearray)):
                r['payload'] = r['payload'].hex()
            data['max_hops_by_bph'][str(bph)] = r
    except Exception:
        pass
    try:
        with open(STATS_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"{YELLOW}Ошибка сохранения статистики: {e}{RESET}")


def load_stats():
    """Загружает статистику из JSON-файла, если он существует."""
    global max_hops_by_bph
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
        max_hops_by_bph = {1: None, 2: None, 3: None}
        for k, rec in (data.get('max_hops_by_bph') or {}).items():
            try:
                bph = int(k)
            except Exception:
                continue
            if bph not in (1, 2, 3) or not isinstance(rec, dict):
                continue
            if isinstance(rec.get('payload'), str):
                rec = dict(rec)
                rec['payload'] = bytes.fromhex(rec['payload'])
            max_hops_by_bph[bph] = rec
        total_rx = sum(d['rx'] for d in stats.values())
        print(f"Загружена статистика: {len(stats)} узлов, {total_rx} RX, "
              f"{len(neighbor_stats)} соседей, {len(outgoing_stats)} исх. соседей")
    except Exception as e:
        print(f"{YELLOW}Ошибка загрузки статистики: {e}{RESET}")


def _process_mqtt_payload(topic, payload_bytes):
    """Обрабатывает одно MQTT-сообщение: логирует сырой формат и обновляет статистику.

    Сначала выводит несколько образцов (MQTT_LOG_FIRST_N_RAW), чтобы увидеть формат.
    Пытается распарсить JSON (path/path_hops, hash, snr, rssi) или сырую hex-строку.
    """
    global _mqtt_samples_logged, _mqtt_messages_received, max_hops_by_bph
    _mqtt_messages_received += 1
    try:
        payload = payload_bytes.decode('utf-8', errors='replace') if isinstance(payload_bytes, bytes) else str(payload_bytes)
    except Exception:
        payload = str(payload_bytes)

    # Логируем первые N сообщений как образец формата
    if MQTT_LOG_FIRST_N_RAW > 0 and _mqtt_samples_logged < MQTT_LOG_FIRST_N_RAW:
        _mqtt_samples_logged += 1
        sample = payload[:500] + ('...' if len(payload) > 500 else '')
        print(f"{CYAN}[MQTT] образец #{_mqtt_samples_logged} topic={topic} payload={sample}{RESET}", flush=True)
        if DEBUG_MODE and DEBUG_LOG:
            try:
                with open(DEBUG_LOG, 'a', encoding='utf-8') as f:
                    f.write(f"[MQTT] topic={topic} payload={payload[:2000]}\n")
            except Exception:
                pass

    # Пробуем JSON
    try:
        data = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        data = None

    if isinstance(data, dict):
        # JSON наблюдателя / meshcoretomqtt: полное RAW — тот же разбор, что U RAW: (GRP, рекорды хопов).
        if isinstance(data.get('raw'), str):
            raw_hex = re.sub(r'\s+', '', data['raw'])
            parsed = parse_raw(raw_hex)
            if parsed:
                pkt_time = (f"{data.get('date', '')} {data.get('time', '')}".strip()
                            or time.strftime('%H:%M:%S - %d/%m/%Y'))
                snr = data.get('snr') or data.get('SNR')
                _process_parsed_raw(
                    parsed,
                    raw_hex,
                    pkt_time=pkt_time,
                    debug=None,
                    record_usb_recent=False,
                    mqtt_attach_snr=True,
                    mqtt_snr=snr,
                )
                return

        # Формат meshcoretomqtt только с path (без полного raw в сообщении)
        path = data.get('path') or data.get('path_hops')
        if isinstance(path, str):
            path = [x.strip().upper() for x in re.split(r'\s*->\s*|\s*,\s*', path) if x.strip()]
        if path and isinstance(path, (list, tuple)):
            hops = [str(h).strip().upper() for h in path]
            # Нормализуем до 2 hex-символов на хоп (берём последние 2 если длиннее)
            path_norm = []
            for h in hops:
                h = re.sub(r'[^0-9A-Fa-f]', '', h)
                if len(h) >= 2:
                    path_norm.append(h[-2:].upper())
                elif len(h) == 1:
                    path_norm.append(('0' + h).upper())
            if path_norm:
                nb = None
                if len(path_norm) >= 2 and is_my_repeater(path_norm[-1]):
                    cand = path_norm[-2]
                    # Если предпоследний хоп — тоже наш репитер,
                    # это пересылка между нашими нодами, не сосед.
                    if not is_my_repeater(cand):
                        nb = cand
                elif path_norm:
                    cand = path_norm[-1]
                    if not is_my_repeater(cand):
                        nb = cand
                if nb:
                    neighbor_stats[nb]['total'] += 1
                    # meshcoretomqtt шлёт "SNR"/"RSSI" с большой буквы
                    snr = data.get('snr') or data.get('SNR')
                    if snr is not None:
                        try:
                            s = float(snr)
                            neighbor_stats[nb]['snr_sum'] += s
                            neighbor_stats[nb]['snr_count'] += 1
                        except (TypeError, ValueError):
                            pass
                rec = max_hops_by_bph.get(1)
                if rec is None or len(path_norm) > rec.get('hops', 0):
                    max_hops_by_bph[1] = {
                        'time': time.strftime('%H:%M:%S - %d/%m/%Y'),
                        'hops': len(path_norm),
                        'path': path_norm,
                        'path_bytes_per_hop': 1,
                        'route_name': 'MQTT',
                        'payload_name': data.get('type', ''),
                        'payload_type': -1,
                        'payload': b'',
                    }
        return

    # Пробуем сырую hex-строку (как в U RAW)
    raw_hex = re.sub(r'\s+', '', payload.strip())
    if len(raw_hex) >= 10 and all(c in '0123456789abcdefABCDEF' for c in raw_hex):
        parsed = parse_raw(raw_hex)
        if parsed and parsed.get('path'):
            path = parsed['path']
            is_trace = (
                parsed.get('payload_type') == 0x09
                and parsed.get('route_type') in (0x02, 0x03)
            )
            if not is_trace:
                last = path[-1]
                if is_my_repeater(last) and len(path) >= 2:
                    nb = path[-2]
                else:
                    nb = last
                if nb and not is_my_repeater(nb):
                    neighbor_stats[nb]['total'] += 1
                hops = len(path)
                bph = parsed.get('path_bytes_per_hop', 1)
                if bph in (1, 2, 3):
                    rec = max_hops_by_bph.get(bph)
                    if rec is None or hops > rec.get('hops', 0):
                        max_hops_by_bph[bph] = {
                            'time': time.strftime('%H:%M:%S - %d/%m/%Y'),
                            'hops': hops,
                            'path': path,
                            'path_bytes_per_hop': bph,
                            'route_name': parsed.get('route_name', 'MQTT'),
                            'payload_name': parsed.get('payload_name', ''),
                            'payload_type': parsed.get('payload_type', -1),
                            'payload': parsed.get('payload', b''),
                        }


def parse_raw(hex_str):
    """Парсит сырые hex-данные пакета MeshCore и извлекает заголовок, path и метаданные.

    Формат пакета (v1):
      [header 1B][transport_codes 4B (опц.)][path_len 1B][path ...][payload]

    Начиная с прошивок 1.14 возможен режим 1/2/3 байта на хоп.
    В этом режиме один байт после header кодирует сразу и число хопов, и размер хопа:
      - старшие 2 бита: mode (0/1/2 => 1/2/3 байта на хоп)
      - младшие 6 бит: hops (0..63)
    Пример: 0x41 = 0b01_000001 => mode=1 (2B), hops=1.

    Header (1 байт, 0bVVPPPPRR):
      - биты 0-1: route type (FLOOD, DIRECT, TRANSPORT_*)
      - биты 2-5: payload type (ADVERT, GRP_TXT, GRP_DATA, ...)
      - биты 6-7: версия формата

    Args:
        hex_str: строка hex-данных пакета (без пробелов)

    Returns:
        dict с полями: route_type, payload_type, route_name, payload_name,
                       path_length (как в пакете: bytes или hops, см. ниже),
                       path_bytes_per_hop (1/2/3), path_hops, path (список хопов),
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
        if offset >= len(data):
            return None

        # В старых прошивках path_length — это число БАЙТ маршрута.
        # В 1.14+ path_length может быть упакованным (mode+hops). Авто-распознаём по эвристике.

        def _looks_like_group_payload(p: bytes) -> bool:
            if not p or len(p) < 4:
                return False
            # payload: [channel_hash:1][MAC:2][ciphertext]; ciphertext кратен 16
            ct = p[3:]
            if len(ct) == 0 or (len(ct) % 16) != 0:
                return False
            # Дополнительная эвристика: известный hash канала
            known = set(CHANNEL_KEYS) | set(CHANNEL_PSK)
            return (p[0] in known) if known else True

        def _decode_path(raw: bytes, bph: int) -> list[str]:
            out = []
            for i in range(0, len(raw), bph):
                chunk = raw[i:i + bph]
                if len(chunk) != bph:
                    break
                out.append(chunk.hex().upper())
            return out

        offset_after_len = offset

        # Вариант A (старый): path_length = bytes
        old_path_bytes_len = int(path_length)
        old_valid = (offset_after_len + old_path_bytes_len) <= len(data)
        if old_valid:
            old_raw_path = data[offset_after_len:offset_after_len + old_path_bytes_len]
            old_payload = data[offset_after_len + old_path_bytes_len:]
        else:
            old_raw_path = b''
            old_payload = b''

        # Вариант B (1.14+): path_length упакован как mode+hops (Packet.cpp).
        # Стандарт: биты 7-6 = 0/1/2 → 1/2/3 байта на хоп, младшие 6 бит = число хопов
        # (32×2 B = 0x60). Proposal #1083 (v2): биты 7-6 = 0b11 → hop_count = max_base + ext,
        # max_base 63/31 для 1B/2B сегментов (напр. 0xD1 = 2B, 31+1 = 32 хопа).
        def _decode_mesh_packed_path_len(packed: int):
            max_path = 64
            upper = (packed >> 6) & 0x03
            if upper != 0x03:
                if upper > 2:
                    return None
                bph = upper + 1
                hops = packed & 0x3F
                total = hops * bph
                if total > max_path:
                    return None
                return bph, hops, total
            seg_code = (packed >> 4) & 0x03
            ext = packed & 0x0F
            if seg_code not in (0, 1):
                return None
            bph = 1 << seg_code
            max_base = 63 if seg_code == 0 else 31
            hops = max_base + ext
            total = hops * bph
            if total > max_path:
                return None
            return bph, hops, total

        packed = int(path_length)
        dec = _decode_mesh_packed_path_len(packed)
        new_ok = dec is not None
        if new_ok:
            new_bph, new_hops, new_path_bytes_len = dec
            if (offset_after_len + new_path_bytes_len) <= len(data):
                new_raw_path = data[offset_after_len:offset_after_len + new_path_bytes_len]
                new_payload = data[offset_after_len + new_path_bytes_len:]
            else:
                new_ok = False
                new_raw_path = b''
                new_payload = b''
        else:
            new_bph, new_hops, new_path_bytes_len = 1, 0, 0
            new_raw_path = b''
            new_payload = b''

        # Выбор интерпретации
        # Если один из вариантов вообще невалиден — берём другой.
        if new_ok and not old_valid:
            use_new = True
        elif old_valid and not new_ok:
            use_new = False
        else:
            use_new = False

            # Если "старый" path_length слишком большой для реального 1B-маршрута,
            # а packed-вариант валиден, это почти всегда 1.14+ пакет.
            # Иначе в path попадает кусок payload и hops завышается.
            if new_ok and old_valid and old_path_bytes_len > 63:
                use_new = True

            if (not use_new) and new_ok and payload_type in (0x05, 0x06):
                # Для GRP_TXT/GRP_DATA избегаем привязки к адресу (3333...),
                # выбираем вариант по "валидности" расшифровки/структуры payload.
                looks_new = _looks_like_group_payload(new_payload)
                looks_old = _looks_like_group_payload(old_payload)

                if looks_new and not looks_old:
                    use_new = True
                elif looks_old and not looks_new:
                    use_new = False
                elif looks_new and looks_old:
                    # Если оба варианта выглядят правдоподобно — пробуем реальную расшифровку (если есть crypto).
                    if HAS_CRYPTO:
                        dec_new = decrypt_group_msg(new_payload)
                        dec_old = decrypt_group_msg(old_payload)
                        if dec_new and not dec_old:
                            use_new = True
                        elif dec_old and not dec_new:
                            use_new = False
                        else:
                            # Если обе расшифровки неуспешны или обе успешны — предпочитаем 2B/3B.
                            use_new = new_bph in (2, 3)
                    else:
                        use_new = new_bph in (2, 3)
            elif (not use_new) and new_ok and new_bph in (2, 3):
                # Для остальных: если явно 2B/3B и всё укладывается — используем новый
                use_new = True

        if not old_valid and not new_ok:
            return None

        if use_new:
            path_bytes_per_hop = new_bph
            path_hops = new_hops
            raw_path = new_raw_path
            payload = new_payload
        else:
            path_bytes_per_hop = 1
            path_hops = old_path_bytes_len  # побайтно
            raw_path = old_raw_path
            payload = old_payload

        # Группируем raw_path в хопы по path_bytes_per_hop (1/2/3)
        path = _decode_path(raw_path, path_bytes_per_hop)

        # DIRECT TRACE: поле path на wire — только SNR (1 байт на ретрансляцию), не узлы.
        # path_len как в Packet: младшие 6 бит — число байт SNR; в Mesh.cpp к path[] добавляется
        # по одному байту (getSNR()*4). Маршрут — в payload после tag(4)+auth(4)+flags(1);
        # размер хэша на хоп: 1 << (flags & 3) (см. Mesh::onRecvPacket TRACE, v1.11+).
        if payload_type == 0x09 and route_type in (0x02, 0x03):
            ph = int(path_length)
            n_snr = ph & 0x3F
            end_path = offset_after_len + n_snr
            if end_path <= len(data):
                raw_path = data[offset_after_len:end_path]
                payload = data[end_path:]
                path_bytes_per_hop = 1
                path_hops = n_snr
                path = [f"{b:02X}" for b in raw_path]

        # Защита от явной аномалии: если после разбора 1B получилось слишком много хопов,
        # но длина пути кратна 2/3, это почти наверняка 2B/3B маршрут.
        # Такая ситуация встречается на 1.14+ при неоднозначном path_len.
        # Важно: сначала пробовать 3B, потом 2B — иначе при длине кратной 6 (напр. 282 B)
        # ошибочно выбирается 2B и остаётся то же число «хопов», что и при ошибочном 1B
        # (напр. 141 токенов вместо 94 трёхбайтных узлов).
        if payload_type != 0x09 and path_bytes_per_hop == 1:
            if len(path) > 63:
                if len(raw_path) % 3 == 0:
                    path_bytes_per_hop = 3
                    path_hops = len(raw_path) // 3
                    path = _decode_path(raw_path, 3)
                elif len(raw_path) % 2 == 0:
                    path_bytes_per_hop = 2
                    path_hops = len(raw_path) // 2
                    path = _decode_path(raw_path, 2)

        # DIRECT-пакеты: первые 6 байт payload — destination pubkey prefix (не TRACE)
        dest = None
        if route_type in (0x02, 0x03) and len(payload) >= 6 and payload_type != 0x09:
            dest = payload[:6].hex().upper()

        # TRACE-пакеты: path содержит SNR (×4) на каждом хопе, а не узлы;
        # маршрут — в payload после tag(4)+auth(4)+flags(1); flags&3 — log2 ширины хэша (1/2/4/8 B).
        trace_route = None
        trace_snr = None
        if payload_type == 0x09 and route_type in (0x02, 0x03):
            trace_snr = [(b - 256 if b > 127 else b) / 4.0 for b in raw_path]
            trace_route = []
            if len(payload) > 9:
                path_sz = payload[8] & 0x03
                route_bph = 1 << path_sz
                if route_bph > 8:
                    route_bph = 8
                raw_route = payload[9:]
                if route_bph > 1 and len(raw_route) >= route_bph:
                    for i in range(0, len(raw_route), route_bph):
                        chunk = raw_route[i:i + route_bph]
                        if len(chunk) != route_bph:
                            break
                        trace_route.append(chunk.hex().upper())
                else:
                    trace_route = [f"{b:02X}" for b in raw_route]

        return {
            'route_type': route_type,
            'payload_type': payload_type,
            'route_name': ROUTE_TYPES.get(route_type, f'?{route_type}'),
            'payload_name': PAYLOAD_TYPES.get(payload_type, f'?{payload_type}'),
            'path_length': path_length,
            'path_bytes_per_hop': path_bytes_per_hop,
            'path_hops': path_hops,
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
    Паттерн 3: "ack@[имя] XX,YY,..." или "@[имя] XX,YY,..." — хопы сразу за именем.
    Паттерн 4: "@[имя] <текст> = XX,YY,..." — между именем и хопами произвольный
               текст и знак '='. Например, ответ от робота VAO Hekru:
               "@[Kopcap V4️⃣] pong [2b 13h] = 3434,C980,5086,..."

    Во всех случаях хопы — 2/4/6 hex (1B/2B/3B per hop). Если первый хоп —
    один из ваших репитеров (см. MY_REPEATERS_HEX), второй считается исходящим
    соседом. Если второй хоп тоже один из ваших репитеров (перекрёстная
    служебка), пропускаем. В Паттернах 3/4 дополнительно: если первый хоп НЕ
    мой репитер, но name в MY_COMPANIONS — первый хоп считается соседом
    (компаньон услышал соседа напрямую).

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
                if (len(hops) >= 2 and is_my_repeater(hops[0])
                        and not is_my_repeater(hops[1])):
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
            if (len(prefixes) >= 2 and is_my_repeater(prefixes[0])
                    and not is_my_repeater(prefixes[1])):
                neighbors.append(prefixes[1])

    # Паттерн 3: "ack@[имя] XX,YY,..." или "@[имя] XX,YY,..." сразу после имени.
    # Хопы 2/4/6 hex (1B/2B/3B per hop, MeshCore 1.14+).
    # Если путь начинается с одного из ваших репитеров — берём второй хоп
    # (но только если он сам не один из ваших репитеров).
    # Если нет, но имя в MY_COMPANIONS — первый хоп (репитер считается
    # дублем, компаньон услышал соседа напрямую).
    m = re.search(
        r'(?:ack)?@\[(.*?)\]\s+([\da-fA-F]{2,6}(?:,\s*[\da-fA-F]{2,6})+)',
        text,
    )
    if m:
        name = m.group(1)
        hops = [h.strip().upper() for h in m.group(2).split(',')]
        if (len(hops) >= 2 and is_my_repeater(hops[0])
                and not is_my_repeater(hops[1])):
            neighbors.append(hops[1])
        elif hops and name in MY_COMPANIONS and not is_my_repeater(hops[0]):
            neighbors.append(hops[0])

    # Паттерн 4: ответ робота с произвольным текстом и '=' перед путём:
    #   "@[name] pong [2b 13h] = XX,YY,..."
    #   "@[name] <любой текст без '=' и переноса> = XX,YY,..."
    # Логика та же, что в Паттерне 3: первый хоп — мой репитер → второй сосед;
    # иначе name в MY_COMPANIONS → первый хоп.
    m = re.search(
        r'@\[(.*?)\][^\n=]*=\s*([\da-fA-F]{2,6}(?:,\s*[\da-fA-F]{2,6})+)',
        text,
    )
    if m:
        name = m.group(1)
        hops = [h.strip().upper() for h in m.group(2).split(',')]
        if (len(hops) >= 2 and is_my_repeater(hops[0])
                and not is_my_repeater(hops[1])):
            neighbors.append(hops[1])
        elif hops and name in MY_COMPANIONS and not is_my_repeater(hops[0]):
            neighbors.append(hops[0])

    return neighbors


def _process_parsed_raw(
    parsed: dict,
    hex_str: str,
    *,
    pkt_time: str = '?',
    debug: dict | None = None,
    record_usb_recent: bool = True,
    mqtt_attach_snr: bool = False,
    mqtt_snr: float | str | None = None,
):
    """Общая логика после parse_raw(): соседи, расшифровка GRP, VERBOSE, stats/hops, max_hops.

    USB (U RAW:) передаёт debug и record_usb_recent=True. MQTT JSON с полем raw — без debug,
    record_usb_recent=False; если mqtt_attach_snr, SNR из JSON привязывается к соседу как в RX.
    """
    global _last_raw_neighbor
    is_direct_trace = (
        parsed['payload_type'] == 0x09
        and parsed['route_type'] in (0x02, 0x03)
    )
    pkt_label = f"{parsed['route_name']} {parsed['payload_name']}"
    path_str = ','.join(parsed['path']) if parsed['path'] else '-'
    hops = len(parsed['path'])

    if record_usb_recent:
        route_char = 'F' if parsed.get('route_type') in (0x00, 0x01) else (
            'D' if parsed.get('route_type') in (0x02, 0x03) else None
        )
        payload_len = len(parsed.get('payload') or b'')
        _recent_raw_usb.append({
            'payload_type': parsed.get('payload_type'),
            'route_char': route_char,
            'payload_len': payload_len,
            'hex': hex_str,
            'path': parsed.get('path') or [],
        })

    decrypted = None
    outgoing_nbs = []
    if parsed['payload_type'] in (0x05, 0x06) and parsed['payload']:
        decrypted = decrypt_group_msg(parsed['payload'])
        if decrypted and BOTS_MODE:
            outgoing_nbs = extract_outgoing_neighbors(decrypted['text'])
            for out_nb in outgoing_nbs:
                outgoing_stats[out_nb]['total'] += 1

    _last_raw_neighbor = None
    direct_to_obs = False
    is_flood = parsed['route_type'] in (0x00, 0x01)
    if is_flood and parsed['path']:
        last = parsed['path'][-1]
        if is_my_repeater(last):
            # Last hop = наш репитер. Сосед — предпоследний, если он сам не наш
            # репитер (пересылка между нашими нодами не учитывается).
            if len(parsed['path']) >= 2:
                nb = parsed['path'][-2]
                if not is_my_repeater(nb):
                    neighbor_stats[nb]['total'] += 1
                    _last_raw_neighbor = nb
        else:
            neighbor_stats[last]['total'] += 1
            _last_raw_neighbor = last
            direct_to_obs = True

    if is_direct_trace:
        tr = parsed.get('trace_route') or []
        ts = parsed.get('trace_snr') or []
        if len(tr) >= 3 and is_my_repeater(tr[0].upper()):
            nb = tr[1].upper()
            # Если второй хоп тоже наш репитер — это перекрёстная служебная
            # пересылка между нашими нодами, не сосед.
            if not is_my_repeater(nb):
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

    if mqtt_attach_snr and mqtt_snr is not None and _last_raw_neighbor:
        try:
            s = float(mqtt_snr)
            nb = _last_raw_neighbor
            neighbor_stats[nb]['snr_sum'] += s
            neighbor_stats[nb]['snr_count'] += 1
        except (TypeError, ValueError):
            pass

    if VERBOSE:
        if outgoing_nbs:
            color, end = f"{MAGENTA}{BOLD}", RESET
        elif direct_to_obs:
            color, end = f"{YELLOW}{BOLD}", RESET
        else:
            color, end = "", ""
        obs_tag = f" {YELLOW}[OBS]{RESET}{color}" if direct_to_obs else ""

        if is_direct_trace:
            tr = parsed.get('trace_route') or []
            route_str = '→'.join(tr) if tr else '?'
            ts = parsed.get('trace_snr') or []
            snr_str = ','.join(f"{s:.2f}" for s in ts) if ts else '-'
            mode_tag = ""
            if tr:
                tok_len = len(tr[0])
                if tok_len == 4:
                    mode_tag = f" {BLUE}{BOLD}[2B]{RESET}"
                elif tok_len == 6:
                    mode_tag = f" {MAGENTA}{BOLD}[3B]{RESET}"
                elif tok_len == 8:
                    mode_tag = f" {CYAN}{BOLD}[4B]{RESET}"
            print(f"{CYAN}    -> {pkt_label} | route=[{route_str}] SNR=[{snr_str}]{mode_tag}{RESET}", flush=True)
        else:
            bph = parsed.get('path_bytes_per_hop', 1)
            mode_tag = ""
            if bph == 2:
                mode_tag = f" {BLUE}{BOLD}[2B]{RESET}{color}"
            elif bph == 3:
                mode_tag = f" {MAGENTA}{BOLD}[3B]{RESET}{color}"
            dest_tag = f" -> {parsed['dest']}" if parsed.get('dest') else ""
            src_tag = f"{CYAN}[MQTT] {RESET}" if not record_usb_recent else ""
            print(f"{src_tag}{color}    -> {pkt_label} | hops={hops} path=[{path_str}]{mode_tag}{dest_tag}{obs_tag}{end}", flush=True)
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
        dest_info = f" -> {parsed['dest']}" if parsed.get('dest') else ""
        obs_info = " [OBS]" if direct_to_obs else ""
        dec_info = ""
        if decrypted:
            dec_info = f" | {decrypted['channel']}: {decrypted['text']}"
        if is_direct_trace:
            tr = parsed.get('trace_route') or []
            route_str = '→'.join(tr) if tr else '?'
            ts = parsed.get('trace_snr') or []
            snr_str = ','.join(f"{s:.2f}" for s in ts) if ts else '-'
            log_line = f"{pkt_time} | {pkt_label} | route=[{route_str}] SNR=[{snr_str}]\n"
        else:
            log_line = f"{pkt_time} | {pkt_label} | hops={hops} path=[{path_str}]{dest_info}{obs_info}{dec_info}\n"
        try:
            with open(DEBUG_LOG, 'a') as f:
                f.write(log_line)
                f.write(f"  RAW: {hex_str}\n")
        except Exception:
            pass

    is_trace = is_direct_trace
    if not is_trace:
        for node_hash in parsed['path']:
            stats[node_hash].setdefault('hops_seen', 0)
            stats[node_hash]['hops_seen'] += 1

        bph = parsed.get('path_bytes_per_hop', 1)
        if bph in (1, 2, 3):
            rec = max_hops_by_bph.get(bph)
            if rec is None or hops > rec.get('hops', 0):
                max_hops_by_bph[bph] = {
                    'time': pkt_time,
                    'hops': hops,
                    'path': parsed['path'],
                    'path_bytes_per_hop': bph,
                    'route_name': parsed['route_name'],
                    'payload_name': parsed['payload_name'],
                    'payload_type': parsed['payload_type'],
                    'payload': parsed['payload'],
                }

    if debug is not None and debug.get('raw_lines', 0) <= 3:
        debug.setdefault('raw_samples', []).append(
            f"{pkt_label} | hops={hops} path=[{path_str}]"
        )

    if not record_usb_recent:
        _last_raw_neighbor = None


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
    global _last_raw_neighbor
    debug['total'] += 1

    # Пропускаем служебные строки (команда log, маркер EOF, пустые)
    if not line or line.startswith('log') or 'EOF' in line:
        debug['ignored'] += 1
        return

    # Прошивка может писать служебный шум эфира (мешает живому выводу).
    # Эти строки не показываем, но собираем среднее noise_floor за цикл.
    if 'noise_floor' in line and 'RadioLibWrapper' in line:
        m = re.search(r'noise_floor\s*=\s*(-?\d+)', line)
        if m:
            nf = int(m.group(1))
            debug['noise_floor_sum'] = debug.get('noise_floor_sum', 0) + nf
            debug['noise_floor_count'] = debug.get('noise_floor_count', 0) + 1
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
            # Тип пакета нужен дальше, в том числе для сопоставления hash<->U RAW.
            ptype = None
            if 'type=' in line:
                type_part = line.split('type=')[1].split(',')[0]
                ptype = int(type_part)

            global _usb_hashes_curr, _usb_hash_to_line_curr
            global _usb_hash_to_raw_curr
            if 'hash=' in line:
                try:
                    pkt_hash = line.split('hash=')[1].split()[0]
                    if pkt_hash:
                        _usb_hashes_curr.add(pkt_hash)
                        # Запоминаем пример строки для этого hash (только первый раз)
                        _usb_hash_to_line_curr.setdefault(pkt_hash, line)

                        # Если есть недавний U RAW, пытаемся сопоставить его с этой RX-строкой
                        # по (type, route, payload_len). Это нужно только для отладки.
                        if DEBUG_MODE and _recent_raw_usb:
                            try:
                                route_char = None
                                if 'route=' in line:
                                    route_char = line.split('route=')[1].split(',')[0].strip()
                                payload_len = None
                                if 'payload_len=' in line:
                                    payload_len = int(line.split('payload_len=')[1].split(')')[0])
                            except Exception:
                                route_char = None
                                payload_len = None

                            if route_char and payload_len is not None:
                                for entry in reversed(_recent_raw_usb):
                                    if (ptype is not None and
                                            entry.get('payload_type') == ptype and
                                            entry.get('route_char') == route_char and
                                            entry.get('payload_len') == payload_len):
                                        _usb_hash_to_raw_curr.setdefault(pkt_hash, {
                                            'hex': entry.get('hex'),
                                            'path': entry.get('path'),
                                        })
                                        break
                except IndexError:
                    pass

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
            if ptype is None:
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
        pkt_time = line.split(' U RAW:')[0].strip() if ' U RAW:' in line else '?'
        if parsed:
            _process_parsed_raw(
                parsed, hex_str, pkt_time=pkt_time, debug=debug, record_usb_recent=True,
            )
        else:
            if debug['raw_lines'] <= 3:
                debug.setdefault('raw_samples', []).append(line)

    # --- Строки, не являющиеся ни RX, ни TX, ни RAW — игнорируем ---
    else:
        debug['ignored'] += 1
        if debug['ignored'] <= 5:
            debug['ignored_samples'].append(line)


def print_stats(stats, cycle_info, debug, skip_cumulative=False):
    """Выводит в терминал сводную таблицу статистики по всем узлам сети.

    Включает:
      - Номер цикла и кол-во прочитанных строк
      - Диагностику парсинга (сколько RX/TX/broadcast/ошибок)
      - Таблицу узлов, отсортированную по среднему SNR (лучшие сверху)
      - Общие итоги за цикл: суммарные RX/TX, кол-во уникальных узлов

    Цветовая раскраска:
      - Зелёный: узлы с префиксом NODE_PREFIX (ваши ноды)
      - Голубой: ваши ретрансляторы (см. MY_REPEATERS_HEX)
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

    # В MQTT-only режиме весь блок диагностики USB-парсера всегда показывает
    # нули (parse_line() не вызывается), поэтому скрываем его так же,
    # как и накопительную таблицу.
    if not skip_cumulative:
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

    if skip_cumulative:
        num_nodes = len([n for n in stats if n != BROADCAST_NODE])
        print(f"\nЗА ЭТОТ ЦИКЛ: RX: {cycle_info['rx_this']}, TX: {cycle_info['tx_this']}")
        print(f"ВСЕГО уникальных узлов: {num_nodes}")
        print("=" * 70)
        return

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
        elif is_my_repeater(node):
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


def _decrypt_grp_mesh_v1(enc_part: bytes, secret32: bytes):
    """Расшифровка по MeshCore Utils::MACThenDecrypt (HMAC-SHA256 2B + AES-128-ECB)."""
    if len(enc_part) < 2 + 16 or len(enc_part[2:]) % 16 != 0:
        return None
    mac, ct = enc_part[:2], enc_part[2:]
    if hmac.new(secret32, ct, hashlib.sha256).digest()[:2] != mac:
        return None
    try:
        cipher = AES.new(secret32[:16], AES.MODE_ECB)
        plaintext = cipher.decrypt(ct)
    except Exception:
        return None
    if len(plaintext) < 6:
        return None
    text = plaintext[5:].rstrip(b'\x00').decode('utf-8', errors='ignore').strip()
    if text and sum(c.isprintable() for c in text) > len(text) // 2:
        return text
    return None


def decrypt_group_msg(payload):
    """Пытается расшифровать payload группового сообщения (GRP_TXT/GRP_DATA).

    Формат payload (MeshCore v1, group):
      [channel_hash:1][MAC:2][ciphertext]

    Ciphertext = AES-128-ECB, zero-padded до кратности 16.
    Plaintext:  [timestamp:4][flags:1][sender_name: message_text][zero_padding]

    Два типа каналов:
      - PSK (как Public в прошивке): secret из Base64 16/32 B; hash = SHA256(secret)[0];
        MAC = HMAC-SHA256(secret доп. до 32 B, ciphertext)[:2].
      - Именованные в KNOWN_CHANNEL_NAMES: AES-ключ = SHA256(имя)[:16],
        hash = SHA256(AES-ключа)[0]; прежний fallback без проверки MAC (старый режим).

    Args:
        payload: bytes полного payload (включая channel_hash)

    Returns:
        dict {'channel': имя, 'hash': hex-строка, 'text': расшифрованный текст}
        или None если расшифровка не удалась
    """
    if not HAS_CRYPTO or len(payload) < 4:
        return None

    ch_hash = payload[0]
    enc_part = bytes(payload[1:])

    for ch_name, secret32 in CHANNEL_PSK.get(ch_hash, []):
        text = _decrypt_grp_mesh_v1(enc_part, secret32)
        if text:
            return {'channel': ch_name, 'hash': f"{ch_hash:02X}", 'text': text}

    if ch_hash not in CHANNEL_KEYS:
        return None

    # Старый путь: только AES по ciphertext (MAC на wire всё равно 2 байта — пропускаем).
    ciphertext = enc_part[2:]
    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        return None

    for ch_name, key in CHANNEL_KEYS[ch_hash]:
        try:
            cipher = AES.new(key, AES.MODE_ECB)
            plaintext = cipher.decrypt(ciphertext)

            if len(plaintext) < 6:
                continue
            text = plaintext[5:].rstrip(b'\x00').decode('utf-8', errors='ignore').strip()

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

    def _print_record(title, r):
        if not r:
            print(f"  {title}: нет данных")
            return
        path_str = ','.join(r['path']) if r.get('path') else '-'
        pkt_label = f"{r.get('route_name', '?')} {r.get('payload_name', '?')}"
        payload_info = decode_payload_info(r.get('payload_type', -1), r.get('payload', b''))
        print(f"  {title}:")
        print(f"    Время:  {r.get('time', '?')}")
        print(f"    Тип:    {pkt_label}")
        print(f"    Хопов:  {r.get('hops', 0)}")
        bph = r.get('path_bytes_per_hop', 1)
        if bph == 2:
            print(f"    Path:   [{BLUE}{BOLD}{path_str}{RESET}] {BLUE}{BOLD}[2B]{RESET}")
        elif bph == 3:
            print(f"    Path:   [{MAGENTA}{BOLD}{path_str}{RESET}] {MAGENTA}{BOLD}[3B]{RESET}")
        else:
            print(f"    Path:   [{path_str}]")
        if payload_info:
            print(f"    Инфо:   {payload_info}")

    _print_record("Рекорд (1B)", max_hops_by_bph.get(1))
    _print_record("Рекорд (2B)", max_hops_by_bph.get(2))
    _print_record("Рекорд (3B)", max_hops_by_bph.get(3))

    print("=" * 70)


def print_neighbors(cycle_info, debug=None):
    """Выводит таблицу соседей — узлов, доставляющих пакеты ретранслятору и наблюдателю.

    Сосед — из path FLOOD-пакетов (как U RAW / MQTT JSON с полем raw); TRACE — колонки SNR→/SNR←.
    Колонка «Приём» — средний SNR USB RX или MQTT (поле SNR), привязанный к тому же соседу.

    Args:
        cycle_info: dict с данными цикла
        debug: dict с отладочными счётчиками (опционально)
    """
    print("\n" + "=" * 78)
    print(f"СОСЕДИ (цикл {cycle_info['num']})")

    if debug and debug.get('noise_floor_count'):
        avg_nf = debug['noise_floor_sum'] / debug['noise_floor_count']
        print(f"Noise floor (среднее за цикл): {avg_nf:.1f} dBm  "
              f"(n={debug['noise_floor_count']})")

    print("=" * 78)

    if not neighbor_stats:
        print("  Нет данных о соседях")
        print("=" * 78)
        return

    sorted_neighbors = sorted(neighbor_stats.items(), key=lambda x: x[1]['total'], reverse=True)
    grand_total = sum(d['total'] for d in neighbor_stats.values())

    print(f"{'Сосед':<8} {'Пакетов':>8} {'%':>6} {'Приём':>7} {'SNR→':>7} {'SNR←':>7} {'Trace':>7}")
    print("-" * 78)

    for node, data in sorted_neighbors:
        pct = data['total'] / grand_total * 100 if grand_total > 0 else 0

        rx_snr = (
            f"{data['snr_sum'] / data['snr_count']:.1f}"
            if data.get('snr_count')
            else "-"
        )
        snr_out = f"{data['trace_out_sum'] / data['trace_out_count']:.2f}" if data.get('trace_out_count') else "-"
        snr_in = f"{data['trace_in_sum'] / data['trace_in_count']:.2f}" if data.get('trace_in_count') else "-"
        attempts = data.get('trace_attempts', 0)
        trace_col = f"{data.get('trace_ok', 0)}/{attempts}" if attempts else "-"

        base_line = (
            f"{node:<8} {data['total']:>8} {pct:>5.1f}% {rx_snr:>7} "
            f"{snr_out:>7} {snr_in:>7} {trace_col:>7}"
        )

        if is_my_repeater(node):
            print(f"{CYAN}{base_line}{RESET}")
        elif node.startswith(NODE_PREFIX):
            print(f"{GREEN}{base_line}{RESET}")
        else:
            print(base_line)

    print("-" * 78)
    print(f"Всего пакетов от соседей: {grand_total}")
    print("=" * 78)


def print_outgoing_neighbors(cycle_info):
    """Выводит таблицу исходящих соседей — через кого уходят наши сообщения.

    Определяется из расшифрованных групповых сообщений, содержащих
    "Found N unique path(s): XX,YY,ZZ,...". Если первый хоп — один из ваших
    репитеров (MY_REPEATERS_HEX), второй хоп считается исходящим соседом
    (если он сам не один из ваших репитеров — иначе пересылка пропускается).

    Args:
        cycle_info: dict с данными цикла
    """
    print("\n" + "=" * 70)
    print(f"ИСХОДЯЩИЕ СОСЕДИ (цикл {cycle_info['num']})")
    print("=" * 70)

    if not outgoing_stats:
        print("  Нет данных (ждём пакеты из API или расшифрованных сообщений с path)")
        print("=" * 70)
        return

    sorted_out = sorted(outgoing_stats.items(), key=lambda x: x[1]['total'], reverse=True)
    grand_total = sum(d['total'] for d in outgoing_stats.values())

    print(f"{'Сосед':<8} {'Пакетов':>8} {'%':>6}")
    print("-" * 70)

    for node, data in sorted_out:
        pct = data['total'] / grand_total * 100 if grand_total > 0 else 0
        base_line = f"{node:<8} {data['total']:>8} {pct:>5.1f}%"

        if is_my_repeater(node):
            print(f"{CYAN}{base_line}{RESET}")
        elif node.upper().startswith(NODE_PREFIX.upper()):
            print(f"{GREEN}{base_line}{RESET}")
        else:
            print(base_line)

    print("-" * 70)
    print(f"Всего исходящих через соседей: {grand_total}")
    print("=" * 70)


def fetch_outgoing_from_api():
    """Получает пакеты из API MeshCoreTel и обновляет outgoing_stats.

    Ищет в path_hops любой токен, относящийся к вашим репитерам
    (is_my_repeater). Следующий хоп после такого токена считается исходящим
    соседом. Если следующий хоп — тоже один из ваших репитеров, это
    перекрёстная пересылка между своими нодами, не сосед: пропускаем.
    Дедупликация по hash пакета (один пакет виден нескольким наблюдателям).
    Пагинация: забирает все новые пакеты с момента последнего запроса.

    Returns:
        int: количество новых исходящих соседей, найденных в этом запросе
    """
    global _api_last_id
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
            if DEBUG_MODE:
                global _api_origins_seen
                _api_origins_seen.add(pkt.get('origin', '?'))

            if pkt.get('payload_type') == 0x09:
                continue

            hops = pkt.get('path_hops')
            if not hops:
                continue

            origin = pkt.get('origin', '?')
            # Сравнение USB vs API — по всем пакетам из API (MeshCoreTel отдаёт того, кто первым сообщил)
            if pkt_hash:
                _api_hashes_curr.add(pkt_hash)

            is_my_observer = (OBSERVER_ORIGINS and
                              any(origin.startswith(pref) for pref in OBSERVER_ORIGINS))
            path_str = ' → '.join(hops)
            if DEBUG_MODE:
                my_tag = " [мой observer]" if is_my_observer else ""
                ptype = PAYLOAD_TYPES.get(pkt.get('payload_type', -1), '?')
                with open(DEBUG_LOG, 'a', encoding='utf-8') as f:
                    f.write(f"[API] {origin}{my_tag}: {ptype} [{path_str}]\n")

            for i, hop in enumerate(hops):
                if not is_my_repeater(hop):
                    continue
                if i + 1 >= len(hops):
                    break
                neighbor = hops[i + 1].upper()
                if is_my_repeater(neighbor):
                    # Перекрёстная пересылка между нашими репитерами —
                    # не считаем соседом.
                    break
                outgoing_stats[neighbor]['total'] += 1
                found += 1
                path_str = ' → '.join(hops)
                ptype = PAYLOAD_TYPES.get(pkt.get('payload_type', -1), '?')
                my_tag = " [мой observer]" if is_my_observer else ""
                if VERBOSE:
                    print(f"  {CYAN}[API] {origin}{my_tag}: {ptype} "
                          f"[{path_str}] → сосед {BOLD}{neighbor}{RESET}", flush=True)
                if DEBUG_MODE:
                    with open(DEBUG_LOG, 'a', encoding='utf-8') as f:
                        f.write(f"[API] {origin}{my_tag}: {ptype} [{path_str}] → сосед {neighbor}\n")
                break

        if len(packets) < page_limit:
            break

    if len(_api_seen_hashes) > 50000:
        _api_seen_hashes.clear()

    return found


def _api_poller(stop_event):
    """Фоновый поток: периодически опрашивает API MeshCoreTel, пока не попросят остановиться.

    Работает независимо от состояния USB-порта: даже при потере Observer
    продолжает обновлять outgoing_stats через MeshCoreTel.
    Адреса репитеров берутся из глобального MY_REPEATERS_HEX.
    """
    poll_interval = 15
    while not stop_event.is_set():
        fetch_outgoing_from_api()
        # Спим интервал, но проверяем stop_event каждую секунду
        for _ in range(poll_interval):
            if stop_event.is_set():
                return
            time.sleep(1)


def _apply_mqtt_cli(args):
    """Переопределяет глобальные MQTT_* из CLI (--mqtt-broker, --mqtt-tcp, ...)."""
    global MQTT_SERVER, MQTT_PORT, MQTT_PORT_WS, MQTT_USE_WEBSOCKETS
    global MQTT_USERNAME, MQTT_PASSWORD
    if getattr(args, 'mqtt_broker', None):
        MQTT_SERVER = args.mqtt_broker
    if getattr(args, 'mqtt_tcp', False):
        MQTT_USE_WEBSOCKETS = False
    mp = getattr(args, 'mqtt_port', None)
    if mp is not None:
        if MQTT_USE_WEBSOCKETS:
            MQTT_PORT_WS = mp
        else:
            MQTT_PORT = mp
    if getattr(args, 'mqtt_username', None):
        MQTT_USERNAME = args.mqtt_username
    if getattr(args, 'mqtt_password', None):
        MQTT_PASSWORD = args.mqtt_password


def _mqtt_thread(stop_event):
    """Фоновый поток: подписка на MQTT MeshCoreTel, обработка входящих сообщений."""
    if not HAS_MQTT:
        return
    transport = "websockets" if MQTT_USE_WEBSOCKETS else "tcp"
    port = MQTT_PORT_WS if MQTT_USE_WEBSOCKETS else MQTT_PORT
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, transport=transport)
    except (AttributeError, TypeError):
        try:
            client = mqtt.Client(transport=transport)
        except TypeError:
            client = mqtt.Client()
            transport = "tcp"
            port = MQTT_PORT
    client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)

    def _rc_value(rc):
        """Приводит reason_code к int (и для VERSION1, и для VERSION2)."""
        return getattr(rc, 'value', rc) if rc is not None else 0

    def on_connect(c, userdata, flags, reason_code, properties=None):
        if _rc_value(reason_code) == 0:
            for t in MQTT_TOPICS + MQTT_TOPICS_IATA:
                c.subscribe(t)
            try:
                c.subscribe('#')  # если брокер разрешает — увидим любые топики
            except Exception:
                pass
            print(f"{CYAN}[MQTT] подключено к {MQTT_SERVER}:{port} ({transport}){RESET}", flush=True)
            print(f"  подписки: meshcore/+/+/packets|status, meshcore/MOW/+/packets|status, #", flush=True)
        else:
            print(f"{YELLOW}[MQTT] подключение отклонено, reason_code={_rc_value(reason_code)}{RESET}", flush=True)

    def on_disconnect(c, userdata, *rest):
        # VERSION1: (client, userdata, rc); VERSION2: (client, userdata, flags, reason_code, properties)
        rc = rest[1] if len(rest) >= 2 else (rest[0] if rest else 0)
        if _rc_value(rc) != 0:
            print(f"{YELLOW}[MQTT] отключено, reason_code={_rc_value(rc)}{RESET}", flush=True)

    def on_message(c, userdata, msg):
        try:
            _process_mqtt_payload(msg.topic, msg.payload)
            # Первые 20 сообщений — краткий лог «получено», чтобы убедиться, что что-то приходит.
            if _mqtt_messages_received <= 20:
                print(f"{CYAN}[MQTT] получено сообщение #{_mqtt_messages_received} topic={msg.topic} len={len(msg.payload)}{RESET}", flush=True)
        except Exception as e:
            if DEBUG_MODE:
                print(f"{YELLOW}[MQTT] ошибка обработки: {e}{RESET}", flush=True)

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message
    try:
        client.reconnect_delay_set(min_delay=1, max_delay=30)
    except Exception:
        pass

    # Ретрай первичного подключения с видимым логом: транзиентный EHOSTUNREACH
    # (протухший ARP, засыпание Wi-Fi) не должен тихо убивать MQTT-поток.
    attempt = 0
    connected = False
    while not stop_event.is_set():
        attempt += 1
        msg = f"{CYAN}[MQTT] подключение к {MQTT_SERVER}:{port} ({transport})"
        if attempt > 1:
            msg += f" попытка #{attempt}"
        msg += f"...{RESET}"
        print(msg, flush=True)
        try:
            client.connect(MQTT_SERVER, port, 60)
            connected = True
            break
        except Exception as e:
            print(f"{YELLOW}[MQTT] ошибка подключения: {e} — повтор через 5с{RESET}", flush=True)
            if stop_event.wait(timeout=5):
                break

    if not connected:
        return

    try:
        client.loop_start()
        while not stop_event.wait(timeout=1):
            pass
    except Exception as e:
        print(f"{YELLOW}[MQTT] ошибка MQTT-потока: {e}{RESET}", flush=True)
    finally:
        client.loop_stop()
        try:
            client.disconnect()
        except Exception:
            pass


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
            _ch_disp = ['Public (PSK MeshCore)'] + list(KNOWN_CHANNEL_NAMES)
            print(f"Дешифрование каналов: {', '.join(_ch_disp)}")
        else:
            print(f"{YELLOW}pycryptodome не установлен — расшифровка каналов отключена{RESET}")
        if args.api:
            print(f"API meshcoretel.ru: исходящие соседи для адресов {','.join(MY_REPEATERS_HEX)}")
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
                print_neighbors(cycle_info, debug)
                print_outgoing_neighbors(cycle_info)
            if args.hops:
                print_max_hops(cycle_info)

            # В отладочном режиме сравниваем USB и API: только при -u и --api (иначе API-набор пуст и сравнение бессмысленно).
            # Считаем так:
            #   - USB: пакеты предыдущего цикла (_usb_hashes_prev)
            #   - API: пакеты из предыдущего и текущего интервалов
            # Ищем только те hash, которые были в USB, но так и не появились в API.
            if DEBUG_MODE:
                global _usb_hashes_curr, _usb_hashes_prev, _api_hashes_curr, _api_hashes_prev
                global _usb_hash_to_line_curr, _usb_hash_to_line_prev, _usb_only_total
                global _usb_hash_to_raw_curr, _usb_hash_to_raw_prev
                global _api_origins_seen
                usb_prev = _usb_hashes_prev
                api_union = _api_hashes_prev | _api_hashes_curr
                if usb_prev and getattr(args, 'api', False):
                    both = usb_prev & api_union
                    usb_only_hashes = sorted(usb_prev - api_union)
                    print("\nСРАВНЕНИЕ USB vs API (по hash):")
                    print(f"  USB пакетов (предыдущий цикл): {len(usb_prev)}")
                    print(f"  API пакетов (предыдущий+текущий, все origin): {len(api_union)}")
                    print(f"  Совпали по hash: {len(both)}")
                    _usb_only_total += len(usb_only_hashes)
                    print(f"  Только USB: {len(usb_only_hashes)} (накопительно: {_usb_only_total})")
                    if usb_only_hashes:
                        print("  Пакеты только USB (hash и RX-строка):")
                        for h in usb_only_hashes:
                            line = _usb_hash_to_line_prev.get(h, '(строка RX недоступна)')
                            print(f"    {h}: {line}")
                            raw = _usb_hash_to_raw_prev.get(h)
                            if raw and raw.get('hex'):
                                path = raw.get('path') or []
                                print(f"      RAW: {raw['hex']}")
                                if path:
                                    print(f"      path(bytes)=[{','.join(path)}]")
                    # Пишем тот же блок в отладочный лог
                    try:
                        with open(DEBUG_LOG, 'a', encoding='utf-8') as f:
                            f.write("\nСРАВНЕНИЕ USB vs API (по hash):\n")
                            f.write(f"  USB пакетов (предыдущий цикл): {len(usb_prev)}\n")
                            f.write(f"  API пакетов (предыдущий+текущий, все origin): {len(api_union)}\n")
                            f.write(f"  Совпали по hash: {len(both)}\n")
                            f.write(f"  Только USB: {len(usb_only_hashes)} (накопительно: {_usb_only_total})\n")
                            if usb_only_hashes:
                                f.write("  Пакеты только USB (hash и RX-строка):\n")
                                for h in usb_only_hashes:
                                    line = _usb_hash_to_line_prev.get(h, '(строка RX недоступна)')
                                    f.write(f"    {h}: {line}\n")
                                    raw = _usb_hash_to_raw_prev.get(h)
                                    if raw and raw.get('hex'):
                                        f.write(f"      RAW: {raw['hex']}\n")
                                        if raw.get('path'):
                                            f.write(f"      path(bytes)=[{','.join(raw['path'])}]\n")
                            f.write("-" * 70 + "\n")
                    except Exception:
                        pass
                    print("-" * 70)
                # переносим текущие наборы в "предыдущие" для следующего цикла
                _usb_hashes_prev = _usb_hashes_curr.copy()
                _usb_hashes_curr.clear()
                _api_hashes_prev = _api_hashes_curr.copy()
                _api_hashes_curr.clear()
                _usb_hash_to_line_prev = _usb_hash_to_line_curr.copy()
                _usb_hash_to_line_curr.clear()
                _usb_hash_to_raw_prev = _usb_hash_to_raw_curr.copy()
                _usb_hash_to_raw_curr.clear()
                _api_origins_seen.clear()

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
    """Главный цикл работы анализатора.

    API MeshCoreTel опрашивается только с опцией --api.
    С опцией -u/--usb подключается Observer по серийному порту (USB).
    """
    port = args.port
    cycle_counter = [0]

    api_stop_event = None
    api_thread = None
    if getattr(args, 'api', False):
        api_stop_event = threading.Event()
        api_thread = threading.Thread(
            target=_api_poller,
            args=(api_stop_event,),
            daemon=True,
        )
        api_thread.start()

    mqtt_thread = None
    mqtt_stop_event = None
    if getattr(args, 'mqtt', False):
        if HAS_MQTT:
            mqtt_stop_event = threading.Event()
            mqtt_thread = threading.Thread(target=_mqtt_thread, args=(mqtt_stop_event,), daemon=True)
            mqtt_thread.start()
        else:
            print(f"{YELLOW}Опция --mqtt требует paho-mqtt: uv pip install paho-mqtt{RESET}", flush=True)

    def _stats_timer_loop(label: str):
        print(f"{label} Цикл статистики: каждые {CYCLE_TIME} сек", flush=True)
        print(flush=True)
        while True:
            cycle_counter[0] += 1
            time.sleep(CYCLE_TIME)
            cycle_info = {
                'num': cycle_counter[0],
                'lines_read': 0,
                'rx_this': 0,
                'tx_this': 0,
            }
            if args.original:
                print_stats(stats, cycle_info, {}, skip_cumulative=not args.usb)
            if args.neighbors:
                print_neighbors(cycle_info, {})
                print_outgoing_neighbors(cycle_info)
            if args.hops:
                print_max_hops(cycle_info)
            save_stats()

    try:
        if args.usb:
            # Режим с USB: подключаемся к порту, читаем лог, циклы и сравнение USB/API
            while True:
                if not os.path.exists(port):
                    print(f"Порт {port} не найден. Ожидание подключения...", flush=True)
                    _wait_for_port(port)
                    time.sleep(2)

                need_reconnect = _connect_and_run(args, port, cycle_counter)
                if not need_reconnect:
                    break

                reconnect_note = " (API продолжает работать)" if args.api else ""
                print(f"Ожидание переподключения к {port}...{reconnect_note}", flush=True)
                _wait_for_port(port)
                time.sleep(2)
        else:
            if args.api:
                print("Режим только API (без USB).", flush=True)
                print(f"API meshcoretel.ru: исходящие соседи для адресов {','.join(MY_REPEATERS_HEX)}")
                _stats_timer_loop("")
            elif args.mqtt and HAS_MQTT:
                print("Режим только MQTT (без USB). Данные — из потока meshcore/.../packets|status.", flush=True)
                _stats_timer_loop("")
            else:
                print("Нет источника данных. Укажите --api, --mqtt и/или -u/--usb.", flush=True)

    except KeyboardInterrupt:
        print("\n\nОстановлено пользователем")
        total_rx = sum(d['rx'] for d in stats.values())
        total_tx = sum(d['tx'] for d in stats.values())
        last_cycle_num = cycle_counter[0] if 'cycle_counter' in locals() else 0
        cycle_info = {
            'num': 'ИТОГО',
            'lines_read': '-',
            'rx_this': total_rx,
            'tx_this': total_tx,
        }
        if args.original:
            print_stats(stats, cycle_info, {}, skip_cumulative=not args.usb)
        if args.neighbors:
            neighbors_cycle_info = dict(cycle_info)
            neighbors_cycle_info['num'] = f'ИТОГОВЫЙ цикл {last_cycle_num}'
            print_neighbors(neighbors_cycle_info, {})
            print_outgoing_neighbors(cycle_info)
        if args.hops:
            print_max_hops(cycle_info)
        save_stats()
    finally:
        if mqtt_stop_event is not None:
            mqtt_stop_event.set()
        if mqtt_thread is not None:
            mqtt_thread.join(timeout=3)
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
               f"  {CYAN}Голубой{RESET}        — ваши ретрансляторы ({','.join(MY_REPEATERS_HEX)})\n"
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
    parser.add_argument('-u', '--usb', action='store_true',
                        help='Прослушивать Observer по серийному порту (USB). '
                             'Можно использовать вместе с --api.')
    parser.add_argument('--api', action='store_true',
                        help='Включить опрос API meshcoretel.ru '
                             '(исходящие соседи для адресов из --repeaters)')
    parser.add_argument('-p', '--port', default=PORT,
                        help=f'Серийный порт Observer-ноды (по умолчанию {PORT})')
    parser.add_argument('--repeaters', default=','.join(MY_REPEATERS_HEX),
                        help=f'Адреса ваших репитеров через запятую (полные '
                             f'3-байтные hex или префиксы), используются для '
                             f'поиска соседей через API и подсветки в таблицах. '
                             f'По умолчанию {",".join(MY_REPEATERS_HEX)}')
    parser.add_argument('--bots', action='store_true',
                        help='Определять исходящих соседей из ответов ботов в каналах '
                             '(требует отправки p/mt через meshcore-probe)')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Логировать пакеты, принятые observer напрямую (->OBS), '
                             f'в файл {DEBUG_LOG}')
    parser.add_argument('--mqtt', action='store_true',
                        help='Подписаться на MQTT (по умолчанию meshcoretel.ru из констант), '
                             'получать пакеты как от наблюдателя; для локального брокера: '
                             '--mqtt-tcp --mqtt-broker HOST')
    parser.add_argument('--mqtt-broker', default=None, metavar='HOST',
                        help='Хост MQTT (иначе MQTT_SERVER из скрипта, чаще meshcoretel.ru)')
    parser.add_argument('--mqtt-port', type=int, default=None, metavar='N',
                        help='Порт: при WebSockets — MQTT_PORT_WS, при TCP — MQTT_PORT')
    parser.add_argument('--mqtt-tcp', action='store_true',
                        help='TCP вместо WebSockets (локальный Mosquitto, как set mqtt.port 1883)')
    parser.add_argument('--mqtt-username', default=None, help='Логин MQTT (по умолчанию из констант)')
    parser.add_argument('--mqtt-password', default=None, help='Пароль MQTT')
    parser.add_argument('--reset', action='store_true',
                        help='Сбросить сохранённую статистику и начать с нуля')
    args = parser.parse_args()
    VERBOSE = args.verbose
    BOTS_MODE = args.bots
    DEBUG_MODE = args.debug
    # Применяем CLI-список репитеров поверх дефолта в MY_REPEATERS_HEX.
    if args.repeaters:
        MY_REPEATERS_HEX = [r.strip().upper() for r in args.repeaters.split(',') if r.strip()]
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
    if getattr(args, 'mqtt', False):
        _apply_mqtt_cli(args)
    main(args)