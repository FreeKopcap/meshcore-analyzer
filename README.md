# Meshcore Analyzer

Анализатор пакетов для [MeshCore](https://github.com/meshcore-dev/MeshCore) Observer. Подключается к ноде Room Server по серийному порту, в реальном времени читает радиопакеты и выводит статистику по узлам mesh-сети.

**Версия 3.5** — DIRECT TRACE приведён к логике MeshCore 1.11+ (`flags & 3`, сегмент SNR в path); стабильнее столбцы SNR→/SNR← и verbose; мелкий фикс MQTT raw (`bph`). Плюс поведение 3.4: `--api`, длина маршрута, debug `RAW:`.

## Возможности

- **Исходящие соседи через API** — [MeshCoreTel](https://meshcoretel.ru) опрашивается только с флагом `--api`; с `-u` дополнительно подключается Observer по USB.
- **Декодирование TRACE** — расшифровка пакетов трассировки: SNR на каждом хопе и маршрут
- **Статистика по узлам** — RX/TX, средние SNR и RSSI, ошибки, счётчик хопов
- **Таблица соседей** — кто доставляет пакеты, средний SNR туда/обратно из TRACE
- **Таблица исходящих соседей** — через кого уходят пакеты (API, TRACE, ответы ботов)
- **Отладка** — полный лог всех пакетов в файл (`-d`)
- **Рекорд хопов** — пакет с максимальным числом хопов, его маршрут и расшифровка
- **Дешифрование каналов** — GRP_TXT/GRP_DATA: канал **Public** по общему PSK MeshCore (HMAC+AES как в прошивке), остальные из списка — по `SHA256(имя)[:16]`
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

# Канал Public — фиксированный PSK (как в MeshCore companion_radio / simple_secure_chat)
PUBLIC_GROUP_PSK_B64 = 'izOH6cXN6mrJ5e26oRXNcg=='

# Остальные именованные каналы: AES-ключ = SHA256(имя)[:16], хеш на wire = SHA256(ключа)[0]
KNOWN_CHANNEL_NAMES = [
    '#connections',
    '#robot',
    ...
]
```

Для **Public** используется тот же Base64-PSK, что в примерах MeshCore; для строк из `KNOWN_CHANNEL_NAMES` ключи по-прежнему из `SHA256(имя)[:16]`.

Перед запуском отключите веб-консоль (flasher.meshcore.dev) от серийного порта.

## Использование

По умолчанию скрипт опрашивает только API meshcoretel.ru (без USB). С опцией `-u` дополнительно подключается к Observer по серийному порту.

```bash
# Только API: таблицы соседей и исходящих (каждые 60 сек)
uv run meshcore-analyzer.py -n

# С USB: полный лог с порта (-d). Сравнение USB vs API в -d только вместе с --api
uv run meshcore-analyzer.py -unvd --hops
uv run meshcore-analyzer.py -unvd --api --hops

# Отслеживать соседей другого ретранслятора
uv run meshcore-analyzer.py -n --repeater A7

# Накопительная статистика по узлам (по умолчанию)
uv run meshcore-analyzer.py

# Указать порт (только при -u)
uv run meshcore-analyzer.py -u -p /dev/cu.usbmodem1234

# Подписка на MQTT MeshCoreTel (первые N сообщений — образец формата)
uv run meshcore-analyzer.py -n --mqtt

# Только локальный брокер (наблюдатель шлёт не на meshcoretel.ru, а на ваш Mosquitto: set mqtt.server …, port 1883)
uv run meshcore-mqtt-bridge.py -v
uv run meshcore-analyzer.py -n --mqtt --mqtt-tcp --mqtt-broker 127.0.0.1 --mqtt-port 1883

# Сбросить накопленную статистику и отладочный лог
uv run meshcore-analyzer.py --reset
```

### Локальный брокер и мост на MeshCoreTel

Прошивка наблюдателя задаёт **один** MQTT-брокер (`set mqtt.server`, `set mqtt.port`, …). Если ноде недоступен USB, а на карте нужен поток на [meshcoretel.ru](https://meshcoretel.ru):

1. Поднимите свой брокер (например Mosquitto) и откройте порт **1883** с логином/паролем по желанию.
2. На наблюдателе: **`set mqtt.server`** и **`set mqtt.port`** под ваш брокер (часто 1883 TCP). Если на Mosquitto другие учётные записи — **`set mqtt.username`** / **`set mqtt.password`**. Остальное можно не трогать: **`mqtt.iata`**, **`mqtt.packets on`**, **`mqtt.status on`** оставьте как при публикации на meshcoretel (тот же формат топиков). Если прошивка поддерживает только TLS или WebSocket, брокер должен принимать тот же режим, что и раньше, иначе поменяйте порт/тип подключения на ноде.
3. На машине с доступом и к вашему брокеру, и в интернет запустите **мост** (скрипт — не брокер, а два MQTT-клиента):  
   `uv run meshcore-mqtt-bridge.py --local-host … --remote-host meshcoretel.ru`  
   Он подписывается на `meshcore/#` у вас и **пересылает каждое сообщение на meshcoretel** с тем же topic и телом (QoS/retain сохраняются). Если meshcoretel принимает только WebSocket, добавьте `--remote-ws --remote-port 9001`.  
**Анализатор** мост не запускает: у него своё MQTT-подключение к **тому же** Mosquitto — вы получаете и пересылку на meshcoretel, и статистику в скрипте за счёт **двух подписчиков** на одном брокере.
4. Анализатор подключается к **локальному** брокеру:  
   `uv run meshcore-analyzer.py -n --mqtt --mqtt-tcp --mqtt-broker <хост-где-mosquitto> --mqtt-port 1883`  
   (при необходимости `--mqtt-username` / `--mqtt-password`).

**Мост на том же хосте, что Mosquitto** — сначала вручную:

```bash
cd /путь/к/Meshcore-Analyzer
uv pip install paho-mqtt   # если ещё не ставили
uv run python meshcore-mqtt-bridge.py \
  --local-host 127.0.0.1 --local-port 1883 \
  --local-username meshcore --local-password meshcore \
  --remote-host meshcoretel.ru --remote-port 1883 \
  --remote-username meshcore --remote-password meshcore \
  -v --stats-every 60
```

Ожидаются строки `local OK`, `remote OK` и рост `forwarded` в `[bridge] stats`. Автозапуск: отредактируйте `meshcore-mqtt-bridge.service.example` (WorkingDirectory, User), установите как `/etc/systemd/system/meshcore-mqtt-bridge.service`, затем `systemctl enable --now meshcore-mqtt-bridge`.

Топики совпадают с принятым в стеке meshcoretomqtt: `meshcore/{IATA}/{public_key}/packets` и `…/status` (см. константы `MQTT_TOPICS` в скрипте).

**Проверка цепочки:** (1) на брокере с мостом должно расти `forwarded` в строке `[bridge] stats` раз в `--stats-every` сек; `remote=UP`; `dropped_remote_down` и `publish_fail` лучше держать нулевыми. (2) Второй терминал: подписка на MeshCoreTel тем же логином (если ACL разрешает):  
`mosquitto_sub -h meshcoretel.ru -p 1883 -u meshcore -P meshcore -t 'meshcore/MOW/#' -v`  
или с WS — отдельным клиентом под ваш порт. (3) Публичный поток: [meshcoretel.ru](https://meshcoretel.ru) / API пакетов — появление ваших нод с задержкой. (4) Локально: `uv run meshcore-analyzer.py -n --mqtt --mqtt-tcp --mqtt-broker …` — если считается статистика и в логе есть `[MQTT] получено сообщение`, нода доходит до вашего брокера.

## Опции

| Опция | Описание |
|-------|----------|
| `-v`, `--verbose` | Выводить каждый пакет в реальном времени (при `-u`) |
| `-o`, `--original` | Накопительная статистика по узлам (RX/TX/SNR/RSSI) |
| `-n`, `--neighbors` | Таблицы входящих и исходящих соседей |
| `--hops` | Пакет-рекордсмен по числу хопов |
| `-u`, `--usb` | Прослушивать Observer по серийному порту (USB) |
| `--mqtt` | Подписка на MQTT; по умолчанию хост из `MQTT_SERVER` (часто meshcoretel.ru) |
| `--mqtt-tcp` | TCP вместо WebSockets (локальный брокер, порт 1883) |
| `--mqtt-broker HOST` | Хост MQTT |
| `--mqtt-port N` | Порт (для WS — например 9001, для TCP — 1883) |
| `--mqtt-username` / `--mqtt-password` | Учётные данные брокера |
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
