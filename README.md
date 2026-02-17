# Meshcore Analyzer

Анализатор пакетов для [MeshCore](https://github.com/meshcore-dev/MeshCore) Observer. Подключается к ноде Room Server по серийному порту, в реальном времени читает радиопакеты и выводит статистику по узлам mesh-сети.

## Возможности

- **Статистика по узлам** — RX/TX, средние SNR и RSSI, ошибки, счётчик хопов
- **Таблица соседей** — кто доставляет пакеты ретранслятору и наблюдателю, с процентным соотношением
- **Рекорд хопов** — пакет с максимальным числом хопов, его маршрут и расшифровка (тип, канал, имя ноды)
- **Дешифрование каналов** — расшифровка групповых сообщений (GRP_TXT/GRP_DATA) публичных каналов с известными именами (AES-128-ECB)
- **Декодирование RAW-пакетов** — парсинг заголовка MeshCore v1: route type, payload type, path
- **Реальный режим** — пакеты отображаются по мере поступления (опция `-v`)
- **Цветовая раскраска** — свои ноды, ретрансляторы и broadcast визуально различаются

## Требования

- Python 3.10+
- [uv](https://docs.astral.sh/uv/)
- [pyserial](https://pypi.org/project/pyserial/)
- [pycryptodome](https://pypi.org/project/pycryptodome/) — для расшифровки групповых сообщений (опционально)
- Нода MeshCore Room Server с функцией Observer, подключённая по USB

## Установка

```bash
uv venv
uv pip install pyserial pycryptodome
```

## Настройка

В начале файла `meshcore-analyzer.py` настройте константы:

```python
PORT = '/dev/cu.usbmodemXXXX'   # серийный порт ноды (ls /dev/cu.usb*)
NODE_PREFIX = '10'               # префикс hex-адресов ваших нод-компаньонов
REPEATER_PREFIX = '33'           # префикс hex-адресов ваших ретрансляторов
CYCLE_TIME = 60                  # интервал вывода статистики (секунды)

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

```bash
# Накопительная статистика по узлам (по умолчанию)
uv run meshcore-analyzer.py

# Все пакеты в реальном времени + статистика
uv run meshcore-analyzer.py -v

# Таблица соседей
uv run meshcore-analyzer.py -n

# Рекорд хопов с расшифровкой пакета
uv run meshcore-analyzer.py -p

# Все отчёты + verbose
uv run meshcore-analyzer.py -v -o -n -p
```

## Опции

| Опция | Описание |
|-------|----------|
| `-v`, `--verbose` | Выводить каждый пакет в реальном времени |
| `-o`, `--original` | Накопительная статистика по узлам (RX/TX/SNR/RSSI) |
| `-n`, `--neighbors` | Таблица соседей с процентами и средним SNR |
| `-p`, `--path` | Пакет-рекордсмен по числу хопов |

Если ни `-o`, `-n`, `-p` не указаны — показывается `-o` по умолчанию.

## Цвета в таблицах

- **Зелёный** — ноды-компаньоны (префикс `NODE_PREFIX`)
- **Голубой** — ретрансляторы (префикс `REPEATER_PREFIX`)
- **Жёлтый жирный** — широковещательные пакеты (BCAST)
- Без цвета — остальные узлы

## Протокол MeshCore

Скрипт декодирует пакеты по [спецификации MeshCore v1](https://github.com/meshcore-dev/MeshCore/blob/main/docs/packet_format.md):

```
[header 1B][transport_codes 4B (опц.)][path_length 1B][path NB][payload]
```

Поддерживаемые типы пакетов: REQ, RESPONSE, TXT_MSG, ACK, ADVERT, GRP_TXT, GRP_DATA, ANON_REQ, PATH, TRACE, MULTIPART, CONTROL.

## Лицензия

MIT
