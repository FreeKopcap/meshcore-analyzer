import serial
import time
import sys
import argparse
from collections import defaultdict

# ========== ANSI-коды цветов для терминального вывода ==========
GREEN = '\033[92m'
CYAN = '\033[96m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
# ===============================================================

# ========== КОНФИГУРАЦИЯ ==========
# Серийный порт, к которому подключена нода Meshcore.
# macOS: обычно /dev/cu.usbmodemXXXX или /dev/cu.usbserial-XXXX
# Windows: COM24, COM3 и т.д.
PORT = '/dev/cu.usbmodemE8F60ACB1A401'
BAUDRATE = 115200

# Префикс hex-адресов ваших нод-компаньонов. Подсвечиваются зелёным в таблице.
NODE_PREFIX = '10'
# Префикс hex-адресов ваших ретрансляторов. Подсвечиваются голубым.
REPEATER_PREFIX = '33'

# Виртуальный адрес для пакетов без конкретного источника (широковещательные).
BROADCAST_NODE = 'BCAST'

# Интервал между циклами сбора статистики (секунды).
CYCLE_TIME = 60

# Таймаут чтения лога из серийного порта (секунды).
READ_TIMEOUT = 5
# ==================================

# Режим подробного вывода (включается через -v).
VERBOSE = False

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
    'rpt': 0,        # Доставлено ретранслятору
    'obs': 0,        # Доставлено наблюдателю
    'total': 0,      # Всего
    'snr_sum': 0,    # Сумма SNR для расчёта среднего
    'snr_count': 0,  # Количество замеров SNR
})

# Последний определённый сосед из RAW-пакета (для корреляции с SNR из RX-строки)
_last_raw_neighbor = None

# Рекорд максимального числа хопов (dict с данными пакета или None)
max_hops_record = None


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
                       path_length, path (список hex-адресов хопов),
                       payload (bytes сырых данных payload), или None при ошибке
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

        path = [f"{b:02X}" for b in data[offset:offset + path_length]]
        payload = data[offset + path_length:]

        return {
            'route_type': route_type,
            'payload_type': payload_type,
            'route_name': ROUTE_TYPES.get(route_type, f'?{route_type}'),
            'payload_name': PAYLOAD_TYPES.get(payload_type, f'?{payload_type}'),
            'path_length': path_length,
            'path': path,
            'payload': payload,
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
            hops = parsed['path_length']

            if VERBOSE:
                print(f"    -> {pkt_label} | hops={hops} path=[{path_str}]", flush=True)

            # Обновляем счётчик хопов в статистике для каждого узла в path
            for node_hash in parsed['path']:
                stats[node_hash].setdefault('hops_seen', 0)
                stats[node_hash]['hops_seen'] += 1

            # Обновляем рекорд максимальных хопов
            # Извлекаем timestamp из строки лога (формат: "HH:MM:SS - DD/M/YYYY U RAW:")
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

            # Определяем соседа — кто доставил пакет ретранслятору или наблюдателю.
            # Сохраняем в _last_raw_neighbor для корреляции с SNR из следующей RX-строки.
            _last_raw_neighbor = None
            if parsed['path']:
                last = parsed['path'][-1]
                if last.startswith(REPEATER_PREFIX):
                    if len(parsed['path']) >= 2:
                        nb = parsed['path'][-2]
                        neighbor_stats[nb]['rpt'] += 1
                        neighbor_stats[nb]['total'] += 1
                        _last_raw_neighbor = nb
                else:
                    neighbor_stats[last]['obs'] += 1
                    neighbor_stats[last]['total'] += 1
                    _last_raw_neighbor = last

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
        elif node.startswith(REPEATER_PREFIX):
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

    # GRP_TXT (5) / GRP_DATA (6): первый байт — channel hash, остальное зашифровано
    if payload_type in (0x05, 0x06):
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

    Сосед определяется из path пакета:
      - Если последний хоп = REPEATER_PREFIX → предпоследний доставил ретранслятору
      - Иначе → последний хоп доставил напрямую наблюдателю

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

    # Сортируем по общему количеству пакетов (убывание)
    sorted_neighbors = sorted(neighbor_stats.items(), key=lambda x: x[1]['total'], reverse=True)
    grand_total = sum(d['total'] for d in neighbor_stats.values())

    print(f"{'Сосед':<8} {'Пакетов':>8} {'%':>6} {'SNR ср':>8}")
    print("-" * 70)

    for node, data in sorted_neighbors:
        pct = data['total'] / grand_total * 100 if grand_total > 0 else 0
        avg_snr = data['snr_sum'] / data['snr_count'] if data['snr_count'] > 0 else 0
        snr_str = f"{avg_snr:>6.1f}dB" if data['snr_count'] > 0 else "     n/a"

        base_line = f"{node:<8} {data['total']:>8} {pct:>5.1f}% {snr_str}"

        if node.startswith(REPEATER_PREFIX):
            print(f"{CYAN}{base_line}{RESET}")
        elif node.startswith(NODE_PREFIX):
            print(f"{GREEN}{base_line}{RESET}")
        else:
            print(base_line)

    print("-" * 70)
    print(f"Всего пакетов от соседей: {grand_total}")
    print("=" * 70)


def main(args):
    """Главный цикл работы анализатора.

    Алгоритм:
      1. Открывает серийный порт и подключается к ноде Meshcore
      2. Отправляет команду "log start" для включения логирования на ноде
      3. В бесконечном цикле:
         a) Читает серийный порт в реальном времени в течение CYCLE_TIME секунд
         b) Парсит каждую строку, обновляя статистику (в режиме -v печатает пакеты)
         c) В конце цикла выводит выбранные отчёты (-o, -n)
      4. При Ctrl+C — выводит финальную статистику и закрывает порт
    """
    ser = None
    try:
        ser = serial.Serial(PORT, BAUDRATE, timeout=1)
        print(f"Подключён к {PORT}")
        print(f"Цикл статистики: каждые {CYCLE_TIME} сек\n")
        time.sleep(2)

        # Включаем логирование на ноде
        send_cmd(ser, "log start")
        print("Логирование включено")
        time.sleep(1)

        cycle = 0
        while True:
            cycle += 1

            # Отладочные счётчики для текущего цикла
            debug = {
                'total': 0,
                'rx_lines': 0,
                'tx_lines': 0,
                'ignored': 0,
                'malformed': 0,
                'broadcast_rx': 0,
                'broadcast_tx': 0,
                'exception': 0,
                'exception_tx': 0,
                'ignored_samples': [],
                'no_src_dst': 0,
            }

            # Активное чтение порта в течение CYCLE_TIME секунд.
            # В режиме -v каждая строка печатается сразу при поступлении.
            lines_read = 0
            cycle_start = time.time()
            while time.time() - cycle_start < CYCLE_TIME:
                if ser.in_waiting:
                    line = ser.readline().decode('utf-8', errors='ignore').strip()
                    if line:
                        lines_read += 1
                        parse_line(line, stats, debug)
                else:
                    time.sleep(0.05)

            cycle_info = {
                'num': cycle,
                'lines_read': lines_read,
                'rx_this': debug['rx_lines'],
                'tx_this': debug['tx_lines'],
            }

            if args.original:
                print_stats(stats, cycle_info, debug)
            if args.neighbors:
                print_neighbors(cycle_info)
            if args.path:
                print_max_hops(cycle_info)

    except serial.SerialException as e:
        print(f"\nОшибка порта: {e}")
        print(f"Проверьте подключение и имя порта: ls /dev/cu.*")
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
        if args.path:
            print_max_hops(cycle_info)
    finally:
        if ser:
            ser.close()


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
                        help='Показывать таблицу соседей — кто доставляет пакеты '
                             'ретранслятору и наблюдателю (по данным path)')
    parser.add_argument('-p', '--path', action='store_true',
                        help='Показывать пакет-рекордсмен по числу хопов '
                             '(тип, путь, канал для групповых сообщений)')
    args = parser.parse_args()
    VERBOSE = args.verbose
    # Если ни один режим вывода не указан, показываем оригинальную статистику
    if not args.original and not args.neighbors and not args.path:
        args.original = True
    main(args)