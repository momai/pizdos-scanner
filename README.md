# pizdos-scanner

Сканер `/24` подсетей из Xray/V2Ray `geoip.dat`. ICMP используется как дополнительный сигнал, TCP 443 проверяется всегда, остальные TCP-порты берутся из `tcp_ports` в `config.toml`. Результаты пишутся после каждой подсети, поэтому скан можно остановить и продолжить той же командой. Опционально можно остановить скан, когда стал доступен ресурс из белого списка (например Google) — это проверка на включённые whitelist-маршруты.

## Быстрый старт (Docker)

Скачайте репозиторий, подтяните образ из GitHub Container Registry и запустите скан RU:

```bash
git clone https://github.com/momai/pizdos-scanner
cd pizdos-scanner

docker compose pull
curl -L -o geoip.dat \
  https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat

docker compose run --rm pizdos-scanner geoip-scan ru
```

Образ: `ghcr.io/momai/pizdos-scanner:latest`

Остановить скан можно через `Ctrl+C`. Повторный запуск той же команды продолжит с сохраненного состояния.

### MaxMind GeoIP (опционально)

MaxMind `.mmdb` нужны только для колонок `city`, `asn`, `as_name`. Без них скан работает, но эти поля будут `N/A`. Папка `db/` уже есть в репе:

```bash
curl -L -o db/GeoLite2-City.mmdb \
  https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb

curl -L -o db/GeoLite2-ASN.mmdb \
  https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb
```

## Локальная сборка

Если нужно собрать Docker image из исходников:

```bash
docker compose build
docker compose run --rm pizdos-scanner geoip-scan ru
```

Для запуска бинарника без Docker на Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

./build.sh
export PATH="$HOME/.local/bin:$PATH"
```

Системная установка:

```bash
INSTALL_DIR=/usr/local/bin sudo ./build.sh
```

Для ICMP без `sudo` на Linux можно включить `DGRAM`:

```bash
sudo sysctl -w net.ipv4.ping_group_range="0 1000"
```

```toml
socket_type = "DGRAM"
```

В Docker используется `network_mode: host`, capability `NET_RAW` и RAW-сокеты.

## Полезные команды

Через Docker:

```bash
docker compose run --rm --no-build pizdos-scanner geoip-list
docker compose run --rm --no-build pizdos-scanner geoip-scan ru
docker compose run --rm --no-build pizdos-scanner geoip-scan cn private
docker compose run --rm --no-build pizdos-scanner geoip-scan telegram
docker compose run --rm --no-build pizdos-scanner finalize results/<scan>.jsonl
docker compose run --rm --no-build pizdos-scanner test 1.1.1.1 80 443
docker compose run --rm --no-build pizdos-scanner test 1.1.1.1 443 --sni example.com
```

После локальной установки:

```bash
pizdos-scanner geoip-list
pizdos-scanner geoip-scan ru
pizdos-scanner geoip-scan cn private
pizdos-scanner geoip-scan telegram
pizdos-scanner finalize results/<scan>.jsonl
pizdos-scanner test 1.1.1.1 80 443
pizdos-scanner test 1.1.1.1 443 --sni example.com
```

Если остались старые контейнеры:

```bash
docker compose down --remove-orphans
```

## Конфиг скана

Основные параметры в `config.toml`:

```toml
geoip_dat_path = "geoip.dat"
geoip_codes = ["ru"]

ping_type = ["ICMP", "TCP"]
tcp_ports = [80, 443]

results_dir = "results"
resume_state_dir = "results/state"
resume = true
```

`geoip-scan` без аргументов берет коды из `geoip_codes`. Аргументы команды переопределяют конфиг.

`console = "plain"` — progress-bar (по умолчанию, для Docker). `console = "tui"` — дашборд в локальном терминале.

TCP считается живым, если соединение прошло или порт быстро ответил отказом до общего таймаута 2 секунды. Быстрый отказ отдельно попадает в `tcp_<port>_rejected_hosts` в CSV и `tcp_rejected` в JSONL. Если ответа нет до таймаута — это `false`.

Для TLS-проверки с SNI:

```toml
tcp_sni_host = "example.com"
```

Принудительно слать через конкретный интерфейс:

```toml
network_interface = "eth1"
```

### Результаты и resume

Результаты пишутся после каждой `/24`:

```text
results/*.csv
results/*.jsonl
results/*_alive.txt
results/*_rejected.txt
results/state/<job_id>.json
```

CSV содержит сводку по подсети: `icmp_hosts`, `active_hosts`, колонки по каждому TCP-порту (`tcp_80_hosts`, `tcp_443_hosts`) и быстрые отказы (`tcp_80_rejected_hosts`, `tcp_443_rejected_hosts`).

JSONL содержит расширенную запись с компактным `probe`: диапазоны последних октетов для `icmp`, `tcp_ports`, `tcp_rejected` и `dead`.

`*_alive.txt` содержит живые TCP IP без быстрых отказов. `*_rejected.txt` содержит IP, где TCP быстро ответил отказом. Для уже готового JSONL эти файлы можно пересобрать командой:

```bash
pizdos-scanner finalize results/<scan>.jsonl
```

### Endpoint и ротация IP

После каждой `/24` сканер проверяет контрольный endpoint. Если он несколько раз не отвечает — `Stop` остановит скан, `ChangeIp` дернет HTTP-хук:

```toml
endpoint = "77.88.8.8"
endpoint_failure_action = "Stop"   # или ChangeIp
```

`ChangeIp` делает GET на `change_ip_url`, ждет `delay_seconds` и проверяет endpoint снова. Сканер сам не переключает модем/VPN — на той стороне должен быть скрипт или API:

```toml
[task]
change_ip_url = "http://127.0.0.1:8080/change-ip"
delay_seconds = 10
```

Плановая ротация после N подсетей:

```toml
[task]
stop_every_times = 10
stop_action = "ChangeIp"
change_ip_url = "http://192.168.1.1/changeIp"
delay_seconds = 10
```

### Stop on available (whitelist)

Проверка на включённые белые списки: пока whitelist-ресурс недоступен — сканируем дальше, как только стал доступен — останавливаемся. Обычно в `target` ставят сайт из whitelist, например Google.

```toml
[stop_on_available]
enabled = true
target = "google.com"
port = 443
```

Проверка по TCP до и после каждой `/24`. Если stop сработал после скана подсети, её результат не пишется и не попадает в resume.
