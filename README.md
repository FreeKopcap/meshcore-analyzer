# Meshcore Analyzer

Анализатор пакетов для [MeshCore](https://github.com/meshcore-dev/MeshCore) Observer. Подключается к ноде Room Server по серийному порту, в реальном времени читает радиопакеты и выводит статистику по узлам mesh-сети.

**Версия 3.3** — API по умолчанию, USB только с опцией `-u`. Поддержка маршрутов 1/2/3 байта на хоп (1.14+) и noise_floor-статистики.

## Возможности

-- **Исходящие соседи через API** — по умолчанию опрашивается [MeshCoreTel](https://meshcoretel.ru). С опцией `-u` дополнительно подключается Observer по USB.
- **Декодирование TRACE** — расшифровка пакетов трассировки: SNR на каждом хопе и маршрут
- **Статистика по узлам** — RX/TX, средние SNR и RSSI, ошибки, счётчик хопов
- **Таблица соседей** — кто доставляет пакеты, средний SNR туда/обратно из TRACE
- **Таблица исходящих соседей** — через кого уходят пакеты (API, TRACE, ответы ботов)
- **Отладка** — полный лог всех пакетов в файл (`-d`)
- **Рекорд хопов** — пакет с максимальным числом хопов, его маршрут и расшифровка
- **Дешифрование каналов** — расшифровка групповых сообщений (GRP_TXT/GRP_DATA) публичных каналов (AES-128-ECB)
- **Автоматическое переподключение** — при потере USB-соединения ждёт возвращения порта и продолжает работу
- **Сохранение статистики** — накопленные данные сохраняются в `meshcore-stats.json` между запусками
- **Декодирование RAW-пакетов** — парсинг заголовка MeshCore v1: route type, payload type, path (1/2/3 байта на хоп для 1.14+)
- **Цветовая раскраска** — свои ноды, ретрансляторы, broadcast, ->OBS и исходящие соседи визуально различаются

## Требования

- Python 3.10+
- [uv](https://docs.astral.sh/uv/)
- [pyserial](https://pypi.org/project/pyserial/)
- [pycryptodome](https://pypi.org/project/pycryptodome/) — для расшифровки групповых сообщений (опционально)
- [paho-mqtt](https://pypi.org/project/paho-mqtt/) — для подписки на MQTT MeshCoreTel (опция `--mqtt`)
- Нода MeshCore Room Server с функцией Observer, подключённая по USB

## Установка

```bash
uv venv
uv pip install pyserial pycryptodome paho-mqtt
```

## Настройка

В начале файла `meshcore-analyzer.py` настройте константы:

```python
PORT = '/dev/cu.usbmodemXXXX'   # серийный порт ноды (ls /dev/cu.usb*)
NODE_PREFIX = '10'               # префикс hex-адресов ваших нод-компаньонов
REPEATER_PREFIX = '33'           # префикс hex-адресов ваших ретрансляторов
PATH_BYTES_PER_HOP = 1          # 1 — до 1.14, 2 — режим маршрутов 1.14+ (2 байта на хоп)
MY_COMPANIONS = ['Kopcap V4️⃣', 'Kopcap 1️⃣1️⃣4️⃣']  # имена компаньонов для ack@/@ маршрутов
CYCLE_TIME = 60                  # интервал вывода статистики (секунды)

# MQTT MeshCoreTel (прошивка с analyzer.letsme.sh/observer: WebSockets, порт 9001)
MQTT_SERVER = 'meshcoretel.ru'
MQTT_PORT = 1883
MQTT_PORT_WS = 9001
MQTT_USE_WEBSOCKETS = True   # наблюдатель шлёт по WS:9001
MQTT_USERNAME = 'meshcore'
MQTT_PASSWORD = 'meshcore'
MQTT_TOPICS = ['meshcore/+/+/packets', 'meshcore/+/+/status']
MQTT_TOPICS_IATA = ['meshcore/MOW/+/packets', 'meshcore/MOW/+/status']  # ваш IATA

# Известные публичные каналы для расшифровки
KNOWN_CHANNEL_NAMES = [
    'Public',
    '#connections',
    '#robot',
    ...
]
```

Ключи каналов вычисляются автоматически: `SHA256(имя)[:16]`. Добавьте свои каналы в список.

Перед запуском отключите веб-консоль (flasher.meshcore.dev) от серийного порта.

## Использование

По умолчанию скрипт опрашивает только API meshcoretel.ru (без USB). С опцией `-u` дополнительно подключается к Observer по серийному порту.

```bash
# Только API: таблицы соседей и исходящих (каждые 60 сек)
uv run meshcore-analyzer.py -n

# С USB: полный лог с порта + сравнение USB vs API в отладке
uv run meshcore-analyzer.py -unvd --hops

# Отслеживать соседей другого ретранслятора
uv run meshcore-analyzer.py -n --repeater A7

# Накопительная статистика по узлам (по умолчанию)
uv run meshcore-analyzer.py

# Указать порт (только при -u)
uv run meshcore-analyzer.py -u -p /dev/cu.usbmodem1234

# Подписка на MQTT MeshCoreTel (первые N сообщений — образец формата)
uv run meshcore-analyzer.py -n --mqtt

# Сбросить накопленную статистику и отладочный лог
uv run meshcore-analyzer.py --reset
```

## Опции

| Опция | Описание |
|-------|----------|
| `-v`, `--verbose` | Выводить каждый пакет в реальном времени (при `-u`) |
| `-o`, `--original` | Накопительная статистика по узлам (RX/TX/SNR/RSSI) |
| `-n`, `--neighbors` | Таблицы входящих и исходящих соседей |
| `--hops` | Пакет-рекордсмен по числу хопов |
| `-u`, `--usb` | Прослушивать Observer по серийному порту (USB) |
| `--mqtt` | Подписка на MQTT meshcoretel.ru; первые N сообщений — образец формата |
| `--repeater XX` | Префикс ретранслятора для поиска через API (по умолчанию `33`) |
| `--bots` | Искать исходящих соседей через ответы ботов в каналах (при `-u`) |
| `-d`, `--debug` | Логировать пакеты в файл `meshcore-debug.log` |
| `-p`, `--port` | Серийный порт Observer-ноды (по умолчанию из константы PORT) |
| `--reset` | Сбросить сохранённую статистику и отладочный лог |

Если ни `-o`, `-n`, `--hops` не указаны — показывается `-o` по умолчанию.

## Цвета в verbose-выводе

- **Зелёный** — ноды-компаньоны (префикс `NODE_PREFIX`)
- **Голубой** — ретрансляторы (префикс `REPEATER_PREFIX`), пакеты из API `[API]`
- **Жёлтый жирный** — пакеты, принятые observer напрямую `[OBS]`
- **Магента** — сообщения с информацией об исходящих соседях (от ботов)
- Без цвета — остальные узлы

## Протокол MeshCore

Скрипт декодирует пакеты по [спецификации MeshCore v1](https://github.com/meshcore-dev/MeshCore/blob/main/docs/packet_format.md):

```
[header 1B][transport_codes 4B (опц.)][path_length 1B][path NB][payload]
```

- **path**: при `PATH_BYTES_PER_HOP=1` — по 1 байту на хоп (до 1.14); при `PATH_BYTES_PER_HOP=2` (1.14+) — по 2 байта на хоп. Число хопов = длина path в байтах / PATH_BYTES_PER_HOP.
- Поддерживаемые типы пакетов: REQ, RESPONSE, TXT_MSG, ACK, ADVERT, GRP_TXT, GRP_DATA, ANON_REQ, PATH, TRACE, MULTIPART, CONTROL.
- Для TRACE-пакетов поле path содержит не узлы, а измерения SNR (×4) на каждом хопе; маршрут трассировки в payload с тем же размером хопа (1 или 2 байта).

## Лицензия

MIT
