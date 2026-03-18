import os
import requests
import socket
import time
from urllib.parse import urlparse, unquote
from datetime import datetime, timezone, timedelta

# =========================================================
# 1. ИСТОЧНИК
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

TOTAL_TOP_LIMIT = 30
PER_COUNTRY_LIMIT = 2
ANYCAST_LIMIT = 4

PRIORITY_COUNTRIES = [
    "Anycast-IP",
    "Belarus",
    "Estonia",
    "Finland",
    "France",
    "Germany",
    "India",
    "Japan",
    "Kazakhstan",
    "Lithuania",
    "Netherlands",
    "Poland",
    "Russia",
    "Sweden",
    "Switzerland",
    "Turkey",
    "United States",
]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

OUTPUT_FULL_FILE = os.path.join(BASE_DIR, "malfoy_subscription.txt")
OUTPUT_TOP_FILE = os.path.join(BASE_DIR, "malfoy_subscription_top.txt")
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

        # пропускаем служебные комментарии
        if line.startswith("#"):
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


def extract_label(config):
    if "#" not in config:
        return ""
    return unquote(config.split("#", 1)[1]).strip()


def detect_country(config):
    """
    Пытаемся вытащить страну из подписи конфига.
    Примеры:
    '🇩🇪 Germany | [*CIDR] YA' -> Germany
    '🌐 Anycast-IP | [*CIDR] VK' -> Anycast-IP
    """
    label = extract_label(config)
    if not label:
        return "Unknown"

    first_part = label.split("|", 1)[0].strip()

    if "Anycast-IP" in first_part:
        return "Anycast-IP"

    words = first_part.split()
    if not words:
        return "Unknown"

    # обычно первый токен — эмодзи, дальше страна
    if len(words) >= 2:
        country = " ".join(words[1:]).strip()
    else:
        country = words[0].strip()

    if not country:
        return "Unknown"

    # нормализация часто встречающихся вариантов
    replacements = {
        "The Netherlands": "Netherlands",
        "United States,": "United States",
    }

    if country in replacements:
        country = replacements[country]

    return country


def get_country_limit(country_name):
    if country_name == "Anycast-IP":
        return ANYCAST_LIMIT
    return PER_COUNTRY_LIMIT


def get_moscow_time_str():
    moscow_tz = timezone(timedelta(hours=3))
    now = datetime.now(moscow_tz)
    return now.strftime("%Y-%m-%d / %H:%M"), "Moscow"


def build_profile_header(title, count, description, update_interval=30):
    dt_str, tz_name = get_moscow_time_str()

    header_lines = [
        f"# profile-title: {title}",
        f"# profile-update-interval: {update_interval}",
        f"# Date/Time: {dt_str} ({tz_name})",
        f"# Количество: {count}",
        f"# Описание: {description}",
        ""
    ]
    return "\n".join(header_lines)


def sort_configs_alphabetically_by_country(configs):
    """
    Сортировка:
    1. по стране (алфавит)
    2. по подписи целиком
    3. по самой строке, чтобы порядок был стабильный
    """
    return sorted(
        configs,
        key=lambda cfg: (
            detect_country(cfg).lower(),
            extract_label(cfg).lower(),
            cfg.lower()
        )
    )


def save_configs_to_file(path, configs, title, description, update_interval=30):
    header = build_profile_header(
        title=title,
        count=len(configs),
        description=description,
        update_interval=update_interval
    )

    with open(path, "w", encoding="utf-8") as f:
        f.write(header)
        for cfg in configs:
            f.write(cfg + "\n")


# =========================================================
# 4. ОСНОВНАЯ ЛОГИКА
# =========================================================

def main():
    all_configs = []

    print("=== Сборка подписок Malfoy ===")
    print(f"Источник: {URLS[0]}")
    print("==============================\n")

    # 1. Загружаем исходный файл
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

    # 2. Убираем полные дубли строк
    unique_configs = sorted(set(all_configs))
    print(f"\n[=] Уникальных строк после удаления дублей: {len(unique_configs)}")

    # 3. Проверяем TCP и фильтруем по времени
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

    # 4. Ужатие по host:port — оставляем лучший конфиг на один сервер
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

    # Пары (cfg, latency), отсортированные по latency — это база отбора
    final_pairs = list(best_by_server.values())
    final_pairs.sort(key=lambda x: x[1])

    # Полная подписка: просто весь список, но красиво по алфавиту стран
    full_configs_unsorted = [cfg for cfg, _ in final_pairs]
    full_configs = sort_configs_alphabetically_by_country(full_configs_unsorted)

    # 5. Формируем top-list с приоритетом стран и лимитами
    country_buckets = {}

    for cfg, latency_ms in final_pairs:
        country = detect_country(cfg)

        if country not in country_buckets:
            country_buckets[country] = []

        country_buckets[country].append((cfg, latency_ms))

    # внутри страны сортируем по latency
    for country in country_buckets:
        country_buckets[country].sort(key=lambda x: x[1])

    top_configs_selected = []
    country_counts = {}

    # 5.1 Сначала приоритетные страны
    for country in PRIORITY_COUNTRIES:
        if country not in country_buckets:
            continue

        for cfg, latency_ms in country_buckets[country]:
            if country not in country_counts:
                country_counts[country] = 0

            country_limit = get_country_limit(country)

            if country_counts[country] >= country_limit:
                break

            top_configs_selected.append(cfg)
            country_counts[country] += 1

            if len(top_configs_selected) >= TOTAL_TOP_LIMIT:
                break

        if len(top_configs_selected) >= TOTAL_TOP_LIMIT:
            break

    # 5.2 Потом добиваем остальными лучшими
    if len(top_configs_selected) < TOTAL_TOP_LIMIT:
        for cfg, latency_ms in final_pairs:
            if cfg in top_configs_selected:
                continue

            country = detect_country(cfg)

            if country not in country_counts:
                country_counts[country] = 0

            country_limit = get_country_limit(country)

            if country_counts[country] >= country_limit:
                continue

            top_configs_selected.append(cfg)
            country_counts[country] += 1

            if len(top_configs_selected) >= TOTAL_TOP_LIMIT:
                break

    # И уже после отбора раскладываем красиво по алфавиту
    top_configs = sort_configs_alphabetically_by_country(top_configs_selected)

    # 6. Сохраняем файлы
    save_configs_to_file(
        OUTPUT_FULL_FILE,
        full_configs,
        title="Malfoy Subscription | WHITE-CIDR | Full",
        description="Полный список после TCP-фильтра и ужатия по host:port, отсортирован по странам",
        update_interval=30
    )

    save_configs_to_file(
        OUTPUT_TOP_FILE,
        top_configs,
        title="Malfoy Subscription | WHITE-CIDR | Top",
        description="Приоритетный список по странам: до 2 на страну, Anycast до 4, отсортирован по странам",
        update_interval=30
    )

    with open(DEBUG_RESULTS_FILE, "w", encoding="utf-8") as f:
        for cfg, host, port, status in checked_rows:
            f.write(f"{status} | {host}:{port} | {cfg}\n")

    # 7. Вывод
    print("\n==============================")
    print(f"Всего уникальных строк: {len(unique_configs)}")
    print(f"Пропущено (не распарсились): {skipped_configs}")
    print(f"Прошли TCP-фильтр <= {MAX_CONNECT_MS} ms: {len(passed_configs)}")
    print(f"Уникальных серверов после ужатия host:port: {len(full_configs)}")
    print(f"Top-list после фильтра по странам: {len(top_configs)}")
    print(f"Полная подписка: {OUTPUT_FULL_FILE}")
    print(f"Top-подписка: {OUTPUT_TOP_FILE}")
    print(f"Лог проверок: {DEBUG_RESULTS_FILE}")
    print("==============================")


if __name__ == "__main__":
    main()
