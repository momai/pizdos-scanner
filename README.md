# pizdos-scanner

Сканер `/24` подсетей из Xray/V2Ray `geoip.dat`. ICMP используется как дополнительный сигнал, TCP 443 проверяется всегда, остальные TCP-порты берутся из `tcp_ports` в `config.toml`. Результаты пишутся инкрементально в `results/`, поэтому скан можно остановить и продолжить той же командой.

## Быстрый старт

```bash
cd pizdos-scanner
curl -L -o geoip.dat \
  https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat

docker compose up --build
```

По умолчанию `compose.yaml` запускает `geoip-scan ru`. Чтобы посмотреть доступные списки или запустить другой скан:

```bash
docker compose run --rm pizdos-scanner geoip-list
docker compose run --rm pizdos-scanner geoip-scan telegram
docker compose run --rm pizdos-scanner geoip-scan cn private
```

Остановить скан можно через `Ctrl+C`. Повторный запуск той же команды продолжит обработку с уже сохраненного состояния.

## Данные GeoIP

Обязателен только `geoip.dat` в корне проекта:

```bash
ls -lh geoip.dat
```

MaxMind `.mmdb` нужны только для колонок `city`, `asn`, `as_name`. Без них скан работает, но эти поля будут `N/A`. Папка `db/` уже есть в репе:

```bash
curl -L -o db/GeoLite2-City.mmdb \
  https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb

curl -L -o db/GeoLite2-ASN.mmdb \
  https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb
```

## Полезные команды

Через Docker:

```bash
docker compose run --rm pizdos-scanner geoip-list
docker compose run --rm pizdos-scanner geoip-scan ru
docker compose run --rm pizdos-scanner geoip-scan telegram
docker compose run --rm pizdos-scanner test 1.1.1.1 80 443
docker compose run --rm pizdos-scanner test 1.1.1.1 443 --sni example.com
```

После локальной установки:

```bash
pizdos-scanner geoip-list
pizdos-scanner geoip-scan ru
pizdos-scanner geoip-scan cn private
pizdos-scanner test 1.1.1.1 80 443
pizdos-scanner subnet 1.1.1.1
pizdos-scanner subnets
```

Если после Docker-запуска остались старые контейнеры:

```bash
docker compose down --remove-orphans
docker ps --filter ancestor=pizdos-scanner
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

Для ICMP без `sudo` на Linux можно использовать `DGRAM` и разрешить ping для группы:

```bash
sudo sysctl -w net.ipv4.ping_group_range="0 1000"
```

```toml
socket_type = "DGRAM"
```

В Docker используется `network_mode: host`, capability `NET_RAW` и RAW-сокеты.

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

`geoip-scan` без аргументов берет списки из `geoip_codes`. Аргументы команды переопределяют конфиг:

```bash
pizdos-scanner geoip-scan ru
pizdos-scanner geoip-scan cn private
```

Если нужен SNI для TLS-проверки, включите его в конфиг или передайте в тестовой команде:

```toml
tcp_sni_host = "example.com"
```

```bash
pizdos-scanner test 1.1.1.1 443 --sni example.com
```

## Результаты и resume

Результаты пишутся после каждой `/24`:

```text
results/*.csv
results/*.jsonl
results/state/<job_id>.json
```

CSV содержит сводку по подсети: `icmp_hosts`, `active_hosts` и отдельные колонки по каждому TCP-порту, например `tcp_80_hosts`, `tcp_443_hosts`.

JSONL содержит расширенную запись со сводкой и компактным `probe`: диапазоны последних октетов для `icmp`, `tcp_ports` и `dead`, например `tcp_ports: {"80": ["6", "8-12"], "443": ["6", "8-12"]}`.

Если остановить скан и запустить ту же команду снова, сканер пропустит уже обработанные `/24`.

## Endpoint и ротация IP

После каждой `/24` сканер проверяет контрольный endpoint:

```toml
endpoint = "77.88.8.8"
endpoint_failure_action = "Stop"
```

Если endpoint несколько раз подряд не отвечает, доступны два действия: `Stop` остановит скан, `ChangeIp` дернет HTTP-хук ротации.

```toml
endpoint_failure_action = "ChangeIp"
```

`ChangeIp` делает GET на `[task].change_ip_url`, ждет `delay_seconds` и проверяет endpoint снова. Сканер сам не переключает модем, VPN или прокси; это должен делать внешний HTTP-хук.

```toml
[task]
change_ip_url = "http://127.0.0.1:8080/change-ip"
delay_seconds = 10
```

Плановая ротация между подсетями настраивается отдельно. По умолчанию она выключена:

```toml
[task]
stop_every_times = 0
stop_action = "Prompt"
```

Пример смены IP после каждых 10 `/24`:

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

## Сетевой интерфейс

По умолчанию маршрут выбирает ОС. Чтобы принудительно слать ICMP/TCP через конкретный интерфейс Linux:

```toml
network_interface = "eth1"
```

В Docker это работает вместе с `network_mode: host` из `compose.yaml`.
