import os
import socket
import time
from urllib.parse import urlparse, unquote, parse_qs
from datetime import datetime, timezone, timedelta

# =========================================================
# 1. БАЗОВАЯ ПАПКА
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# =========================================================
# 2. ЛОКАЛЬНЫЕ ИСХОДНЫЕ ФАЙЛЫ
# Эти файлы workflow подтягивает из upstream перед запуском
# =========================================================

SOURCE_FILES = [
    {
        "name": "CIDR-CHECKED",
        "path": os.path.join(BASE_DIR, "WHITE-CIDR-RU-checked.txt"),
    },
    {
        "name": "REALITY-MOBILE-1",
        "path": os.path.join(BASE_DIR, "Vless-Reality-White-Lists-Rus-Mobile.txt"),
    },
]

# =========================================================
# 3. НАСТРОЙКИ
# =========================================================

PROTOCOLS = [
    "vless://",
    "vmess://",
    "ss://",
    "trojan://",
    "hysteria2://",
]

MAX_CONNECT_MS = 800
SOCKET_TIMEOUT = 3

# FULL
FULL_TOTAL_LIMIT = 150
FULL_COUNTRY_LIMIT = 8
FULL_BACKEND_LIMIT = 3
FULL_ANYCAST_LIMIT = 10

# BEST
BEST_TOTAL_LIMIT = 80
BEST_COUNTRY_LIMIT = 4
BEST_BACKEND_LIMIT = 2
BEST_ANYCAST_LIMIT = 6

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

OUTPUT_FULL_FILE = os.path.join(BASE_DIR, "white_lists_full.txt")
OUTPUT_BEST_FILE = os.path.join(BASE_DIR, "white_lists_best.txt")
DEBUG_RESULTS_FILE = os.path.join(BASE_DIR, "checked_results.txt")

# =========================================================
# 4. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
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

    # Обычно первый токен — эмодзи, дальше страна
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


def sort_configs_alphabetically_by_country(configs):
    return sorted(
        configs,
        key=lambda cfg: (
            detect_country(cfg).lower(),
            extract_label(cfg).lower(),
            cfg.lower(),
        )
    )


def get_moscow_time_str():
    moscow_tz = timezone(timedelta(hours=3))
    now = datetime.now(moscow_tz)
    return now.strftime("%Y-%m-%d / %H:%M"), "Moscow"


def build_profile_header(title, count, description, update_interval=120):
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


def save_configs_to_file(path, configs, title, description, update_interval=120):
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


def get_country_limit(country_name, mode):
    if mode == "full":
        if country_name == "Anycast-IP":
            return FULL_ANYCAST_LIMIT
        return FULL_COUNTRY_LIMIT

    if mode == "best":
        if country_name == "Anycast-IP":
            return BEST_ANYCAST_LIMIT
        return BEST_COUNTRY_LIMIT

    raise ValueError(f"Unknown mode: {mode}")


def get_backend_limit(mode):
    if mode == "full":
        return FULL_BACKEND_LIMIT
    if mode == "best":
        return BEST_BACKEND_LIMIT
    raise ValueError(f"Unknown mode: {mode}")


def build_backend_family_key(config):
    """
    Пытаемся сгруппировать "почти одинаковые" узлы.
    Приоритет:
    1) pbk + sid + sni
    2) pbk + sni
    3) host + sni
    4) host
    """
    try:
        parsed = urlparse(config)
        host = parsed.hostname or "unknown-host"
        query = parse_qs(parsed.query)

        def q(name):
            values = query.get(name)
            if not values:
                return ""
            return values[0].strip()

        pbk = q("pbk")
        sid = q("sid")
        sni = q("sni")
        security = q("security")

        if pbk and sid and sni:
            return f"reality|{pbk}|{sid}|{sni}"

        if pbk and sni:
            return f"reality|{pbk}|{sni}"

        if host and sni:
            return f"hostsni|{host}|{sni}"

        return f"host|{host}|{security}"
    except Exception:
        return f"fallback|{config}"


def load_all_sources():
    all_configs = []
    source_map = {}

    for source in SOURCE_FILES:
        source_name = source["name"]
        file_path = source["path"]

        print(f"=== Источник: {source_name} ===")
        print(f"FILE: {file_path}")

        if not os.path.exists(file_path):
            raise RuntimeError(f"Файл не найден: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            text = f.read()

        configs = extract_configs(text)
        print(f"[+] Найдено конфигов: {len(configs)}\n")

        for cfg in configs:
            all_configs.append(cfg)
            source_map.setdefault(cfg, set()).add(source_name)

    unique_configs = sorted(set(all_configs))
    return unique_configs, source_map


def tcp_prefilter(unique_configs, source_map):
    checked_rows = []
    passed_pairs = []
    skipped_configs = 0

    print(f"[=] Уникальных строк после удаления дублей: {len(unique_configs)}")
    print("\n[=] Начинаю TCP pre-filter...\n")

    total = len(unique_configs)

    for i, cfg in enumerate(unique_configs, start=1):
        host, port = extract_host_port(cfg)
        source_names = ",".join(sorted(source_map.get(cfg, {"unknown"})))

        if not host or not port:
            skipped_configs += 1
            checked_rows.append((source_names, cfg, None, None, "SKIP"))
            print(f"[{i}/{total}] SKIP не удалось вытащить host/port")
            continue

        ok, latency_ms = check_tcp_connect(host, port)

        if ok and latency_ms is not None:
            if latency_ms <= MAX_CONNECT_MS:
                passed_pairs.append((cfg, latency_ms))
                checked_rows.append((source_names, cfg, host, port, f"OK {latency_ms} ms"))
                print(f"[{i}/{total}] OK   {host}:{port}  {latency_ms} ms")
            else:
                checked_rows.append((source_names, cfg, host, port, f"SLOW {latency_ms} ms"))
                print(f"[{i}/{total}] SLOW {host}:{port}  {latency_ms} ms")
        else:
            checked_rows.append((source_names, cfg, host, port, "FAIL"))
            print(f"[{i}/{total}] FAIL {host}:{port}")

    return passed_pairs, checked_rows, skipped_configs


def dedup_by_host_port(pairs):
    """
    Оставляем лучший по latency на один host:port
    """
    best_by_host_port = {}

    for cfg, latency_ms in pairs:
        host, port = extract_host_port(cfg)
        if not host or not port:
            continue

        key = f"{host}:{port}"

        if key not in best_by_host_port:
            best_by_host_port[key] = (cfg, latency_ms)
        else:
            old_cfg, old_latency = best_by_host_port[key]
            if latency_ms < old_latency:
                best_by_host_port[key] = (cfg, latency_ms)

    result = list(best_by_host_port.values())
    result.sort(key=lambda x: x[1])
    return result


def build_limited_list(pairs, total_limit, mode):
    """
    pairs уже отсортированы по latency
    Применяем:
    - лимит по стране
    - лимит по backend family
    - сначала приоритетные страны, потом остальные
    """
    country_buckets = {}

    for cfg, latency_ms in pairs:
        country = detect_country(cfg)
        country_buckets.setdefault(country, []).append((cfg, latency_ms))

    for country in country_buckets:
        country_buckets[country].sort(key=lambda x: x[1])

    selected = []
    selected_set = set()
    country_counts = {}
    backend_counts = {}

    backend_limit = get_backend_limit(mode)

    def try_add(cfg):
        country = detect_country(cfg)
        backend_key = build_backend_family_key(cfg)

        country_counts.setdefault(country, 0)
        backend_counts.setdefault(backend_key, 0)

        if country_counts[country] >= get_country_limit(country, mode):
            return False

        if backend_counts[backend_key] >= backend_limit:
            return False

        selected.append(cfg)
        selected_set.add(cfg)
        country_counts[country] += 1
        backend_counts[backend_key] += 1
        return True

    # 1. Приоритетные страны
    for country in PRIORITY_COUNTRIES:
        if country not in country_buckets:
            continue

        for cfg, latency_ms in country_buckets[country]:
            added = try_add(cfg)
            if added and len(selected) >= total_limit:
                break

        if len(selected) >= total_limit:
            break

    # 2. Остальные по общему рейтингу (latency)
    if len(selected) < total_limit:
        for cfg, latency_ms in pairs:
            if cfg in selected_set:
                continue

            added = try_add(cfg)
            if added and len(selected) >= total_limit:
                break

    return sort_configs_alphabetically_by_country(selected)


# =========================================================
# 5. ОСНОВНАЯ ЛОГИКА
# =========================================================

def main():
    unique_configs, source_map = load_all_sources()

    passed_pairs, checked_rows, skipped_configs = tcp_prefilter(unique_configs, source_map)

    host_port_dedup_pairs = dedup_by_host_port(passed_pairs)

    print("\n========================================")
    print(f"После дедупа по host:port: {len(host_port_dedup_pairs)}")
    print("========================================\n")

    full_configs = build_limited_list(
        pairs=host_port_dedup_pairs,
        total_limit=FULL_TOTAL_LIMIT,
        mode="full",
    )

    best_configs = build_limited_list(
        pairs=host_port_dedup_pairs,
        total_limit=BEST_TOTAL_LIMIT,
        mode="best",
    )

    save_configs_to_file(
        OUTPUT_FULL_FILE,
        full_configs,
        title="🏳️ БЕЛЫЕ СПИСКИ 🏳️ WHITE LISTS | FULL | CIDR + MOBILE",
        description="Собрано из WHITE-CIDR-RU-checked и Vless-Reality-White-Lists-Rus-Mobile. TCP pre-filter, лимит по странам и backend family.",
        update_interval=120,
    )

    save_configs_to_file(
        OUTPUT_BEST_FILE,
        best_configs,
        title="⚡ БЕЛЫЕ СПИСКИ ⚡ WHITE LISTS | BEST | CIDR + MOBILE",
        description="Отобранный список: до 80 конфигов, лимит по странам и backend family, отсортирован по странам.",
        update_interval=120,
    )

    with open(DEBUG_RESULTS_FILE, "w", encoding="utf-8") as f:
        for source_names, cfg, host, port, status in checked_rows:
            f.write(f"{source_names} | {status} | {host}:{port} | {cfg}\n")

    print("\n==============================")
    print(f"Уникальных строк: {len(unique_configs)}")
    print(f"Пропущено (не распарсились): {skipped_configs}")
    print(f"Прошли TCP pre-filter: {len(passed_pairs)}")
    print(f"После host:port дедупа: {len(host_port_dedup_pairs)}")
    print(f"FULL: {len(full_configs)}")
    print(f"BEST: {len(best_configs)}")
    print(f"Лог: {DEBUG_RESULTS_FILE}")
    print("==============================")


if __name__ == "__main__":
    main()
