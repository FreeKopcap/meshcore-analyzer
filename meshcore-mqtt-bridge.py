#!/usr/bin/env python3
"""MQTT-мост (не брокер): два клиента paho — подписка на ваш брокер → публикация на MeshCoreTel.

Сам скрипт брокером не является: нужен настоящий MQTT-сервер (например Mosquitto), куда шлёт наблюдатель.

Наблюдатель (Room Server / Repeater с MQTT) обычно настроен на один брокер (`set mqtt.server ...`).
Если USB недоступен, укажите на ноде свой Mosquitto, а этот скрипт на VPS/домашней машине:
  - подписывается на ваш брокер (всё под meshcore/#);
  - каждое сообщение пересылает на meshcoretel.ru с тем же topic и payload.

Анализатор НЕ вызывается из моста: это второй MQTT-клиент к тому же брокеру (тот же поток сообщений).
Команда: `uv run meshcore-analyzer.py --mqtt --mqtt-tcp --mqtt-broker <тот же хост> --mqtt-port 1883` (+ логин/пароль при необходимости).

На наблюдателе меняют в первую очередь mqtt.server (и при необходимости mqtt.port, логин/пароль
под ваш Mosquitto). iata, packets on / status on — как раньше, если нужен тот же поток на карту.

Зависимость: paho-mqtt (как у meshcore-analyzer.py).
"""

from __future__ import annotations

import argparse
import sys
import threading
import time


def _make_client(api_v2: bool, transport: str):
    try:
        import paho.mqtt.client as mqtt  # type: ignore
    except ImportError:
        print("Нужен пaho-mqtt: uv pip install paho-mqtt", file=sys.stderr)
        sys.exit(1)
    if api_v2:
        try:
            return mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, transport=transport)
        except (AttributeError, TypeError):
            pass
    try:
        return mqtt.Client(transport=transport)
    except TypeError:
        return mqtt.Client()


def _rc_int(rc) -> int:
    if rc is None:
        return 0
    return getattr(rc, "value", rc)


def _payload_preview(payload: bytes, n: int) -> str:
    """Первые n байт: UTF-8 (часто JSON) или hex."""
    if n <= 0 or not payload:
        return ""
    try:
        s = payload.decode("utf-8")
        cut = s[:n] if len(s) > n else s
        out = repr(cut)
        if len(payload) > n:
            out += f" … (+{len(payload) - n} bytes)"
        return out
    except UnicodeDecodeError:
        chunk = payload[:n]
        h = chunk.hex()
        if len(payload) > n:
            h += f" … (+{len(payload) - n} bytes)"
        return h


def main() -> None:
    p = argparse.ArgumentParser(
        description="MQTT meshcore: локальный брокер → meshcoretel.ru (тот же topic/payload)."
    )
    p.add_argument(
        "--local-host",
        default="127.0.0.1",
        help="Брокер, куда шлёт наблюдатель (по умолчанию 127.0.0.1)",
    )
    p.add_argument("--local-port", type=int, default=1883)
    p.add_argument("--local-ws", action="store_true", help="WebSocket к локальному брокеру")
    p.add_argument("--local-username", default=None)
    p.add_argument("--local-password", default=None)

    p.add_argument("--remote-host", default="meshcoretel.ru")
    p.add_argument("--remote-port", type=int, default=1883)
    p.add_argument("--remote-ws", action="store_true", help="WebSocket к MeshCoreTel (порт часто 9001)")
    p.add_argument("--remote-username", default="meshcore")
    p.add_argument("--remote-password", default="meshcore")

    p.add_argument(
        "--subscribe",
        action="append",
        default=[],
        help="Топик подписки на локальном брокере (можно несколько). По умолчанию: meshcore/#",
    )
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument(
        "--stats-every",
        type=int,
        default=60,
        metavar="SEC",
        help="Каждые SEC сек печатать сводку (fwd/drop/err, remote UP/DOWN). 0 — отключить",
    )
    p.add_argument(
        "--dump-payload",
        type=int,
        default=0,
        metavar="N",
        help="После каждой пересылки печатать превью первых N байт (UTF-8 или hex). 0=выкл",
    )
    args = p.parse_args()

    subs = args.subscribe if args.subscribe else ["meshcore/#"]

    local_transport = "websockets" if args.local_ws else "tcp"
    remote_transport = "websockets" if args.remote_ws else "tcp"

    local_client = _make_client(True, local_transport)
    remote_client = _make_client(True, remote_transport)

    remote_lock = threading.Lock()
    remote_connected = threading.Event()

    if args.local_username:
        local_client.username_pw_set(args.local_username, args.local_password or "")
    if args.remote_username:
        remote_client.username_pw_set(args.remote_username, args.remote_password or "")

    forwarded_count = 0
    dropped_remote_down = 0
    publish_fail = 0
    last_fwd_topic = ""
    count_lock = threading.Lock()

    def _publish_rc_int(pinfo) -> int:
        if pinfo is None:
            return 0
        rc = getattr(pinfo, "rc", 0)
        try:
            return int(rc)
        except (TypeError, ValueError):
            return 0

    def on_local_message(_c, _userdata, msg):
        nonlocal forwarded_count, dropped_remote_down, publish_fail, last_fwd_topic
        if not remote_connected.is_set():
            with count_lock:
                dropped_remote_down += 1
            if args.verbose:
                print("[bridge] remote offline, drop", msg.topic, file=sys.stderr)
            return
        try:
            with remote_lock:
                pinfo = remote_client.publish(msg.topic, msg.payload, qos=msg.qos, retain=msg.retain)
            rc = _publish_rc_int(pinfo)
            if rc != 0:
                with count_lock:
                    publish_fail += 1
                print(f"[bridge] publish rc={rc} topic={msg.topic}", file=sys.stderr)
                return
            with count_lock:
                forwarded_count += 1
                n = forwarded_count
                last_fwd_topic = msg.topic
            if args.verbose or n <= 5 or n % 500 == 0:
                print(f"[bridge] fwd #{n} topic={msg.topic} len={len(msg.payload)}", flush=True)
            if args.dump_payload > 0:
                prev = _payload_preview(msg.payload, args.dump_payload)
                if prev:
                    print(f"[bridge] payload preview: {prev}", flush=True)
        except Exception as e:
            with count_lock:
                publish_fail += 1
            print(f"[bridge] publish error: {e}", file=sys.stderr)

    def on_local_connect(c, _u, _f, rc, _props=None):
        if _rc_int(rc) != 0:
            print(f"[bridge] local connect failed rc={_rc_int(rc)}", file=sys.stderr)
            return
        for t in subs:
            c.subscribe(t)
        print(f"[bridge] local OK {args.local_host}:{args.local_port} ({local_transport}), sub: {subs}", flush=True)
        _hint = (
            f"uv run meshcore-analyzer.py -n --mqtt --mqtt-tcp "
            f"--mqtt-broker {args.local_host} --mqtt-port {args.local_port}"
        )
        if args.local_username:
            _hint += (
                f" --mqtt-username {args.local_username} "
                f"--mqtt-password <как в Mosquitto>"
            )
        print("[bridge] поток для meshcore-analyzer.py: отдельное подключение к ЭТОМУ брокеру (не через мост):", flush=True)
        print(f"[bridge]   {_hint}", flush=True)

    def on_remote_connect(c, _u, _f, rc, _props=None):
        if _rc_int(rc) != 0:
            print(f"[bridge] remote connect failed rc={_rc_int(rc)}", file=sys.stderr)
            remote_connected.clear()
            return
        remote_connected.set()
        print(
            f"[bridge] remote OK {args.remote_host}:{args.remote_port} ({remote_transport}) — "
            "дубликат сообщений на MeshCoreTel включён",
            flush=True,
        )

    def on_remote_disconnect(_c, _u, *rest):
        remote_connected.clear()
        rc = rest[1] if len(rest) >= 2 else (rest[0] if rest else -1)
        if args.verbose:
            print(f"[bridge] remote disconnect rc={_rc_int(rc)}", file=sys.stderr)

    local_client.on_connect = on_local_connect
    local_client.on_message = on_local_message
    remote_client.on_connect = on_remote_connect
    remote_client.on_disconnect = on_remote_disconnect

    # Сначала удалённый брокер: иначе первые пакеты с локального успевают прийти до CONNACK
    # meshcoretel → «remote offline, drop» и потеря сообщений при старте.
    try:
        remote_client.connect(args.remote_host, args.remote_port, 60)
    except Exception as e:
        print(f"[bridge] remote connect error: {e}", file=sys.stderr)
        sys.exit(1)
    remote_client.loop_start()
    _wait_sec = 45
    if not remote_connected.wait(timeout=_wait_sec):
        print(
            f"[bridge] нет подключения к {args.remote_host}:{args.remote_port} за {_wait_sec}s — выход",
            file=sys.stderr,
        )
        remote_client.loop_stop()
        try:
            remote_client.disconnect()
        except Exception:
            pass
        sys.exit(1)

    try:
        local_client.connect(args.local_host, args.local_port, 60)
    except Exception as e:
        print(f"[bridge] local connect error: {e}", file=sys.stderr)
        remote_client.loop_stop()
        try:
            remote_client.disconnect()
        except Exception:
            pass
        sys.exit(1)
    local_client.loop_start()

    try:
        while True:
            if args.stats_every > 0:
                time.sleep(args.stats_every)
                with count_lock:
                    fc = forwarded_count
                    dr = dropped_remote_down
                    pf = publish_fail
                    lt = last_fwd_topic
                up = "UP" if remote_connected.is_set() else "DOWN"
                print(
                    f"[bridge] stats remote={up} forwarded={fc} dropped_remote_down={dr} "
                    f"publish_fail={pf} last_topic={lt or '—'}",
                    flush=True,
                )
            else:
                time.sleep(60)
    except KeyboardInterrupt:
        pass
    finally:
        local_client.loop_stop()
        remote_client.loop_stop()
        try:
            local_client.disconnect()
            remote_client.disconnect()
        except Exception:
            pass


if __name__ == "__main__":
    main()
