# pizdos-scanner

Сканер `/24` подсетей из Xray/V2Ray `geoip.dat`. ICMP используется как дополнительный сигнал, TCP 443 проверяется всегда, остальные TCP-порты берутся из `tcp_ports` в `config.toml`. Результаты пишутся инкрементально в `results/`, поэтому скан можно остановить и продолжить той же командой.

## Быстрый старт (Docker)

Скачать `geoip.dat`, собрать образ и запустить скан RU:

```bash
cd pizdos-scanner
curl -L -o geoip.dat \
  https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat

docker compose build
docker compose run --rm pizdos-scanner geoip-scan ru
```

Остановить — `Ctrl+C`. Повторный запуск той же команды продолжит с сохраненного состояния.

Чтобы запустить другой список:

```bash
docker compose run --rm pizdos-scanner geoip-list
docker compose run --rm pizdos-scanner geoip-scan telegram
docker compose run --rm pizdos-scanner geoip-scan cn private
```

### MaxMind GeoIP (опционально)

Нужны только для колонок `city`, `asn`, `as_name`. Без них скан работает, поля будут `N/A`. Папка `db/` уже есть в репе:

```bash
curl -L -o db/GeoLite2-City.mmdb \
  https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb

curl -L -o db/GeoLite2-ASN.mmdb \
  https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb
```

## Локальная установка

Зависимости Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Сборка и установка в `~/.local/bin`:

```bash
./build.sh
export PATH="$HOME/.local/bin:$PATH"
```

Системная установка:

```bash
INSTALL_DIR=/usr/local/bin sudo ./build.sh
```

Для ICMP без `sudo`: разрешить ping для группы и поставить `DGRAM` в `config.toml`:

```bash
sudo sysctl -w net.ipv4.ping_group_range="0 1000"
```

```toml
socket_type = "DGRAM"
```

В Docker используется `network_mode: host`, capability `NET_RAW` и RAW-сокеты.

## Полезные команды

```bash
pizdos-scanner geoip-list
pizdos-scanner geoip-scan ru
pizdos-scanner geoip-scan cn private
pizdos-scanner geoip-scan telegram
pizdos-scanner test 1.1.1.1 80 443
pizdos-scanner test 1.1.1.1 443 --sni example.com
pizdos-scanner subnet 1.1.1.1
```

Аналогичные команды через Docker — `docker compose run --rm pizdos-scanner <команда>`.

Если зависли старые контейнеры:

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

`geoip-scan` без аргументов берет коды из `geoip_codes`. Аргументы переопределяют конфиг.

TCP считается живым, если соединение прошло или порт быстро ответил отказом до общего таймаута 2 секунды. Быстрый отказ отдельно попадает в `tcp_<port>_rejected_hosts` в CSV и `tcp_rejected` в JSONL. Если ответа нет до таймаута — это `false`.

Для TLS-проверки с SNI:

```toml
tcp_sni_host = "example.com"
```

```bash
pizdos-scanner test 1.1.1.1 443 --sni example.com
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
results/state/<job_id>.json
```

CSV содержит сводку по подсети: `icmp_hosts`, `active_hosts`, колонки по каждому TCP-порту (`tcp_80_hosts`, `tcp_443_hosts`) и быстрые отказы (`tcp_80_rejected_hosts`, `tcp_443_rejected_hosts`).

JSONL содержит расширенную запись с компактным `probe`: диапазоны последних октетов для `icmp`, `tcp_ports`, `tcp_rejected` и `dead`, например `tcp_rejected: {"443": ["6", "8-12"]}`.

Если остановить скан и запустить ту же команду снова, сканер пропустит уже обработанные `/24`.

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

Плановая ротация после N подсетей (по умолчанию выключена):

```toml
[task]
stop_every_times = 10
stop_action = "ChangeIp"
change_ip_url = "http://192.168.1.1/changeIp"
delay_seconds = 10
```

Цикл обработки:

```text
скан /24 -> запись результата -> проверка endpoint -> плановое действие -> следующая /24
```
