import os
import requests
import socket
import time
import base64
from urllib.parse import urlparse

# =========================================================
# 1. ИСТОЧНИК
# Читаем файл ИЗ ТВОЕГО FORK
# =========================================================

URLS = [
    "https://raw.githubusercontent.com/malfy-driller/vpn-configs-for-russia/main/WHITE-CIDR-RU-checked.txt"
]

# =========================================================
# 2. НАСТРОЙКИ
# =========================================================

PROTOCOLS = [
    "vless://",
    "vmess://",
    "ss://",
    "trojan://",
    "hysteria2://"
]

MAX_CONNECT_MS = 800
SOCKET_TIMEOUT = 3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

OUTPUT_TXT_FILE = os.path.join(BASE_DIR, "malfoy_subscription.txt")
OUTPUT_BASE64_FILE = os.path.join(BASE_DIR, "malfoy_subscription_base64.txt")
DEBUG_RESULTS_FILE = os.path.join(BASE_DIR, "checked_results.txt")

# =========================================================
# 3. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# =========================================================

def extract_configs(text):
    configs = []

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        for proto in PROTOCOLS:
            if line.startswith(proto):
                configs.append(line)
                break

    return configs


def extract_host_port(config):
    try:
        parsed = urlparse(config)
        host = parsed.hostname
        port = parsed.port

        if not host or not port:
            return None, None

        return host, port
    except Exception:
        return None, None


def check_tcp_connect(host, port, timeout=SOCKET_TIMEOUT):
    try:
        t1 = time.perf_counter()

        with socket.create_connection((host, port), timeout=timeout):
            t2 = time.perf_counter()

        latency_ms = int((t2 - t1) * 1000)
        return True, latency_ms

    except Exception:
        return False, None


def make_server_key(config):
    host, port = extract_host_port(config)
    if not host or not port:
        return None
    return f"{host}:{port}"


# =========================================================
# 4. ОСНОВНАЯ ЛОГИКА
# =========================================================

def main():
    all_configs = []

    print("=== Сборка подписки Malfoy ===")
    print(f"Источник: {URLS[0]}")
    print("==============================\n")

    for url in URLS:
        try:
            print(f"[+] Загружаю: {url}")
            response = requests.get(url, timeout=20)

            if response.status_code != 200:
                print(f"[!] Не удалось загрузить файл. Код ответа: {response.status_code}")
                continue

            text = response.text
            configs = extract_configs(text)

            print(f"    найдено конфигов: {len(configs)}")
            all_configs.extend(configs)

        except Exception as e:
            print(f"[!] Ошибка при загрузке {url}: {e}")

    # Убираем полные дубли строк
    unique_configs = sorted(set(all_configs))

    print(f"\n[=] Уникальных строк после удаления дублей: {len(unique_configs)}")

    checked_rows = []
    passed_configs = []
    skipped_configs = 0

    print("\n[=] Начинаю проверку TCP-доступности...\n")

    total = len(unique_configs)

    for i, cfg in enumerate(unique_configs, start=1):
        host, port = extract_host_port(cfg)

        if not host or not port:
            skipped_configs += 1
            checked_rows.append((cfg, None, None, "SKIP"))
            print(f"[{i}/{total}] SKIP не удалось вытащить host/port")
            continue

        ok, latency_ms = check_tcp_connect(host, port)

        if ok and latency_ms is not None:
            if latency_ms <= MAX_CONNECT_MS:
                passed_configs.append((cfg, latency_ms))
                checked_rows.append((cfg, host, port, f"OK {latency_ms} ms"))
                print(f"[{i}/{total}] OK   {host}:{port}  {latency_ms} ms")
            else:
                checked_rows.append((cfg, host, port, f"SLOW {latency_ms} ms"))
                print(f"[{i}/{total}] SLOW {host}:{port}  {latency_ms} ms")
        else:
            checked_rows.append((cfg, host, port, "FAIL"))
            print(f"[{i}/{total}] FAIL {host}:{port}")

    # Ужатие по host:port — оставляем лучший конфиг на один сервер
    best_by_server = {}

    for cfg, latency_ms in passed_configs:
        server_key = make_server_key(cfg)
        if not server_key:
            continue

        if server_key not in best_by_server:
            best_by_server[server_key] = (cfg, latency_ms)
        else:
            old_cfg, old_latency = best_by_server[server_key]
            if latency_ms < old_latency:
                best_by_server[server_key] = (cfg, latency_ms)

    final_pairs = list(best_by_server.values())
    final_pairs.sort(key=lambda x: x[1])

    final_configs = [cfg for cfg, _ in final_pairs]

    # Обычный txt
    with open(OUTPUT_TXT_FILE, "w", encoding="utf-8") as f:
        for cfg in final_configs:
            f.write(cfg + "\n")

    # base64-версия
    joined_text = "\n".join(final_configs)
    encoded_text = base64.b64encode(joined_text.encode("utf-8")).decode("utf-8")

    with open(OUTPUT_BASE64_FILE, "w", encoding="utf-8") as f:
        f.write(encoded_text)

    # Подробный лог
    with open(DEBUG_RESULTS_FILE, "w", encoding="utf-8") as f:
        for cfg, host, port, status in checked_rows:
            f.write(f"{status} | {host}:{port} | {cfg}\n")

    print("\n==============================")
    print(f"Всего уникальных строк: {len(unique_configs)}")
    print(f"Пропущено (не распарсились): {skipped_configs}")
    print(f"Прошли TCP-фильтр <= {MAX_CONNECT_MS} ms: {len(passed_configs)}")
    print(f"Уникальных серверов после ужатия host:port: {len(final_configs)}")
    print(f"TXT сохранён сюда: {OUTPUT_TXT_FILE}")
    print(f"Base64 сохранён сюда: {OUTPUT_BASE64_FILE}")
    print(f"Лог сохранён сюда: {DEBUG_RESULTS_FILE}")
    print("==============================")


if __name__ == "__main__":
    main()