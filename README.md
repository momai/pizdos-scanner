# pizdos-scanner

Сканер `/24` подсетей: сначала ICMP, если не ответил - TCP по портам из `tcp_ports`. Умеет брать сети из Xray/V2Ray `geoip.dat`, писать результаты в `results/` и продолжать скан после остановки.

## Подготовить данные

`geoip.dat` скачайте из [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) и положите в корень проекта.

```bash
cd <project-dir>
ls -lh geoip.dat
```

MaxMind `.mmdb` нужны только для колонок `city`, `asn`, `as_name`. Без них скан работает, но эти поля будут `N/A`.

```bash
cd <project-dir>
sudo chown -R "$USER:$USER" .
mkdir -p db results

curl -L -o db/GeoLite2-City.mmdb \
  https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb

curl -L -o db/GeoLite2-ASN.mmdb \
  https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb

ls -lh db
```

## Docker Compose

Собрать образ:

```bash
docker compose build
```

Посмотреть списки из `geoip.dat`:

```bash
docker compose run --rm pizdos-scanner geoip-list
```

Сканировать весь RU:

```bash
docker compose up
```

Остановить скан:

```bash
Ctrl+C
docker compose down --remove-orphans
```

Продолжить скан:

```bash
docker compose up
```

Сканировать другой список:

```bash
docker compose run --rm pizdos-scanner geoip-scan telegram
docker compose run --rm pizdos-scanner geoip-scan cn private
```

TCP test:

```bash
docker compose run --rm pizdos-scanner test 1.1.1.1 80 443
docker compose run --rm pizdos-scanner test 1.1.1.1 443 --sni example.com
```

Если зависли старые контейнеры:

```bash
docker compose down --remove-orphans
docker ps --filter ancestor=pizdos-scanner
```

Compose запускается с `network_mode: host`, чтобы контейнер использовал сеть хоста.
Для ICMP в Docker используется `socket_type = "RAW"` и capability `NET_RAW`.

## Без Docker

Зависимости Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Для ICMP без `sudo`:

```bash
sudo sysctl -w net.ipv4.ping_group_range="0 1000"
```

Если запускаете без Docker и без `sudo`, можно поставить:

```toml
socket_type = "DGRAM"
```

Сборка и установка в `~/.local/bin`:

```bash
./build.sh
export PATH="$HOME/.local/bin:$PATH"
pizdos-scanner geoip-list
pizdos-scanner geoip-scan ru
```

Системная установка:

```bash
INSTALL_DIR=/usr/local/bin sudo ./build.sh
```

Другие команды:

```bash
pizdos-scanner test 1.1.1.1 80 443
pizdos-scanner subnet 1.1.1.1
pizdos-scanner subnets
```

## Resume и результаты

Результаты пишутся сразу после каждой `/24`:

```text
results/*.csv
results/*.jsonl
```

Прогресс хранится тут:

```text
results/state/<job_id>.json
```

Если остановить скан и запустить ту же команду снова, он продолжит с пропуском уже обработанных `/24`.

## Endpoint и ротация IP

После каждой `/24` сканер проверяет контрольный endpoint из `config.toml`:

```toml
endpoint = "77.88.8.8"
endpoint_failure_action = "Stop"
```

Если endpoint несколько раз подряд не отвечает, скан делает `endpoint_failure_action`:

```toml
endpoint_failure_action = "Stop"
```

или:

```toml
endpoint_failure_action = "ChangeIp"
```

`ChangeIp` дергает `[task].change_ip_url`, ждет `delay_seconds` и проверяет endpoint еще раз.

Плановая ротация IP настраивается отдельно в `[task]`. По умолчанию она выключена:

```toml
[task]
stop_every_times = 0
stop_action = "Prompt"
```

Чтобы менять IP после каждых 10 `/24`, включите `ChangeIp` в `[task]`:

```toml
[task]
stop_every_times = 10
stop_action = "ChangeIp"
change_ip_url = "http://192.168.1.1/changeIp"
```

Логика цикла:

```text
скан /24 -> запись результата -> endpoint action при проблеме -> periodic task action -> следующая /24
```

## Сетевой интерфейс

По умолчанию маршрут выбирает ОС. Чтобы принудительно слать ICMP/TCP через интерфейс Linux, укажите его в `config.toml`:

```toml
network_interface = "eth1"
```

В Docker это работает вместе с `network_mode: host` из `compose.yaml`.

## Что сканировать

Через Docker:

```bash
docker compose run --rm pizdos-scanner geoip-scan ru
docker compose run --rm pizdos-scanner geoip-scan cn private
docker compose run --rm pizdos-scanner geoip-scan telegram
```

После `./build.sh`:

```bash
pizdos-scanner geoip-scan ru
pizdos-scanner geoip-scan cn private
pizdos-scanner geoip-scan telegram
```

Через `config.toml`:

```toml
geoip_codes = ["ru"]
tcp_ports = [80, 443]
resume = true
```

Чтобы не было действий после каждой `/24`, должно быть:

```toml
[task]
stop_every_times = 0
```
