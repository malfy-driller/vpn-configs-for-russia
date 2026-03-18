import os
import requests
import socket
import time
from urllib.parse import urlparse, unquote
from datetime import datetime, timezone, timedelta

# =========================================================
# 1. ИСТОЧНИКИ
# =========================================================

CIDR_URL = "https://raw.githubusercontent.com/malfy-driller/vpn-configs-for-russia/main/WHITE-CIDR-RU-checked.txt"
SNI_URL = "https://raw.githubusercontent.com/malfy-driller/vpn-configs-for-russia/main/WHITE-SNI-RU-all.txt"

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

CIDR_BEST_TOTAL_LIMIT = 30
CIDR_BEST_PER_COUNTRY_LIMIT = 2
CIDR_BEST_ANYCAST_LIMIT = 4

SNI_BEST_TOTAL_LIMIT = 5
SNI_BEST_PER_COUNTRY_LIMIT = 1

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
    "Norway",
    "Poland",
    "Russia",
    "Sweden",
    "Switzerland",
    "Turkey",
    "United States",
]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

OUTPUT_CIDR_FULL_FILE = os.path.join(BASE_DIR, "white_cidr_checked_full.txt")
OUTPUT_CIDR_BEST_FILE = os.path.join(BASE_DIR, "white_cidr_checked_best.txt")
OUTPUT_SNI_BEST_FILE = os.path.join(BASE_DIR, "white_sni_best.txt")
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

    replacements = {
        "The Netherlands": "Netherlands",
        "United States,": "United States",
    }

    return replacements.get(country, country)


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


def get_cidr_country_limit(country_name):
    if country_name == "Anycast-IP":
        return CIDR_BEST_ANYCAST_LIMIT
    return CIDR_BEST_PER_COUNTRY_LIMIT


def build_country_limited_list(
    pairs,
    total_limit,
    per_country_limit,
    priority_countries=None,
    special_limit_func=None
):
    """
    pairs: list[(cfg, latency_ms)] уже отсортированы по latency
    """
    if priority_countries is None:
        priority_countries = []

    country_buckets = {}

    for cfg, latency_ms in pairs:
        country = detect_country(cfg)
        country_buckets.setdefault(country, []).append((cfg, latency_ms))

    for country in country_buckets:
        country_buckets[country].sort(key=lambda x: x[1])

    selected = []
    country_counts = {}

    def get_limit(country_name):
        if special_limit_func:
            return special_limit_func(country_name)
        return per_country_limit

    # 1. Сначала приоритетные страны
    for country in priority_countries:
        if country not in country_buckets:
            continue

        for cfg, latency_ms in country_buckets[country]:
            country_counts.setdefault(country, 0)

            if country_counts[country] >= get_limit(country):
                break

            selected.append(cfg)
            country_counts[country] += 1

            if len(selected) >= total_limit:
                break

        if len(selected) >= total_limit:
            break

    # 2. Потом добиваем оставшимися лучшими
    if len(selected) < total_limit:
        for cfg, latency_ms in pairs:
            if cfg in selected:
                continue

            country = detect_country(cfg)
            country_counts.setdefault(country, 0)

            if country_counts[country] >= get_limit(country):
                continue

            selected.append(cfg)
            country_counts[country] += 1

            if len(selected) >= total_limit:
                break

    return sort_configs_alphabetically_by_country(selected)


def process_source(source_name, url):
    print(f"=== Обработка источника: {source_name} ===")
    print(f"URL: {url}\n")

    all_configs = []

    response = requests.get(url, timeout=20)
    if response.status_code != 200:
        raise RuntimeError(f"Не удалось загрузить {source_name}. Код ответа: {response.status_code}")

    text = response.text
    configs = extract_configs(text)
    print(f"[+] Найдено конфигов в {source_name}: {len(configs)}")
    all_configs.extend(configs)

    unique_configs = sorted(set(all_configs))
    print(f"[=] Уникальных строк после удаления дублей: {len(unique_configs)}")

    checked_rows = []
    passed_configs = []
    skipped_configs = 0

    print(f"\n[=] Начинаю проверку TCP-доступности для {source_name}...\n")
    total = len(unique_configs)

    for i, cfg in enumerate(unique_configs, start=1):
        host, port = extract_host_port(cfg)

        if not host or not port:
            skipped_configs += 1
            checked_rows.append((source_name, cfg, None, None, "SKIP"))
            print(f"[{i}/{total}] SKIP не удалось вытащить host/port")
            continue

        ok, latency_ms = check_tcp_connect(host, port)

        if ok and latency_ms is not None:
            if latency_ms <= MAX_CONNECT_MS:
                passed_configs.append((cfg, latency_ms))
                checked_rows.append((source_name, cfg, host, port, f"OK {latency_ms} ms"))
                print(f"[{i}/{total}] OK   {host}:{port}  {latency_ms} ms")
            else:
                checked_rows.append((source_name, cfg, host, port, f"SLOW {latency_ms} ms"))
                print(f"[{i}/{total}] SLOW {host}:{port}  {latency_ms} ms")
        else:
            checked_rows.append((source_name, cfg, host, port, "FAIL"))
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

    print(f"\n[=] После ужатия по host:port: {len(final_pairs)}")
    print("========================================\n")

    return {
        "unique_count": len(unique_configs),
        "skipped_count": skipped_configs,
        "passed_count": len(passed_configs),
        "final_pairs": final_pairs,
        "checked_rows": checked_rows,
    }


# =========================================================
# 4. ОСНОВНАЯ ЛОГИКА
# =========================================================

def main():
    # --- CIDR ---
    cidr_result = process_source("WHITE-CIDR-RU-checked", CIDR_URL)
    cidr_final_pairs = cidr_result["final_pairs"]

    cidr_full_configs = sort_configs_alphabetically_by_country(
        [cfg for cfg, _ in cidr_final_pairs]
    )

    cidr_best_configs = build_country_limited_list(
        pairs=cidr_final_pairs,
        total_limit=CIDR_BEST_TOTAL_LIMIT,
        per_country_limit=CIDR_BEST_PER_COUNTRY_LIMIT,
        priority_countries=PRIORITY_COUNTRIES,
        special_limit_func=get_cidr_country_limit
    )

    # --- SNI ---
    sni_result = process_source("WHITE-SNI-RU-all", SNI_URL)
    sni_final_pairs = sni_result["final_pairs"]

    sni_best_configs = build_country_limited_list(
        pairs=sni_final_pairs,
        total_limit=SNI_BEST_TOTAL_LIMIT,
        per_country_limit=SNI_BEST_PER_COUNTRY_LIMIT,
        priority_countries=PRIORITY_COUNTRIES
    )

    # --- Сохранение файлов ---
    save_configs_to_file(
        OUTPUT_CIDR_FULL_FILE,
        cidr_full_configs,
        title="🏳️ БЕЛЫЕ СПИСКИ 🏳️ WHITE LISTS | CIDR | Только VK, Yandex, CDNvideo, Beeline",
        description="Полный список после TCP-фильтра и ужатия по host:port, отсортирован по странам",
        update_interval=30
    )

    save_configs_to_file(
        OUTPUT_CIDR_BEST_FILE,
        cidr_best_configs,
        title="⚡ БЕЛЫЕ СПИСКИ ⚡ WHITE LISTS | CIDR | Лучшие сервера",
        description="Отобранный список: до 2 серверов на страну, Anycast до 4, отсортирован по странам",
        update_interval=30
    )

    save_configs_to_file(
        OUTPUT_SNI_BEST_FILE,
        sni_best_configs,
        title="📡 БЕЛЫЕ СПИСКИ 📡 WHITE LISTS | SNI",
        description="Лучшие SNI-конфиги: до 5 серверов из разных стран, отсортированы по странам",
        update_interval=30
    )

    all_checked_rows = cidr_result["checked_rows"] + sni_result["checked_rows"]

    with open(DEBUG_RESULTS_FILE, "w", encoding="utf-8") as f:
        for source_name, cfg, host, port, status in all_checked_rows:
            f.write(f"{source_name} | {status} | {host}:{port} | {cfg}\n")

    print("\n==============================")
    print(f"CIDR FULL: {len(cidr_full_configs)}")
    print(f"CIDR BEST: {len(cidr_best_configs)}")
    print(f"SNI BEST: {len(sni_best_configs)}")
    print(f"Лог проверок: {DEBUG_RESULTS_FILE}")
    print("==============================")


if __name__ == "__main__":
    main()
