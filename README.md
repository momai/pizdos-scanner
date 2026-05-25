# pizdos-scanner

Сканер `/24` подсетей из Xray/V2Ray `geoip.dat`.  
ICMP используется как дополнительный сигнал, TCP 443 проверяется всегда, остальные TCP-порты берутся из `tcp_ports` в `config.toml`.

Результаты пишутся после каждой подсети, поэтому скан можно остановить и продолжить той же командой.

## Быстрый старт

### Из бинаря

Latest release: [github.com/momai/pizdos-scanner/releases/latest](https://github.com/momai/pizdos-scanner/releases/latest)

Скачайте конфиг, исполняемые файл и geoip файл. 
```bash
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) ASSET="pizdos-scanner-linux-x86_64" ;;
  aarch64|arm64) ASSET="pizdos-scanner-linux-arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH"
    echo "Use Docker or build from sources"
    exit 1
    ;;
esac

curl -L -o pizdos-scanner \
  "https://github.com/momai/pizdos-scanner/releases/latest/download/${ASSET}"
curl -L -o geoip.dat \
  https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat  
curl -L -o config.toml \
  https://raw.githubusercontent.com/momai/pizdos-scanner/main/config.toml
chmod +x pizdos-scanner
```

Так же, полезно будет скачать mmdb для заполнения полей ASN и City в результатах.
```bash
mkdir -p db

curl -L -o db/GeoLite2-City.mmdb \
  https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb
curl -L -o db/GeoLite2-ASN.mmdb \
  https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb
```

Запустите сканер:

```bash
./pizdos-scanner geoip-scan ru
```
Если видите ошибку вида `GLIBC_2.38/2.39 not found`, используйте Docker-раздел ниже или соберите бинарь из исходников на своей машине (раздел `Сборка из исходников`).

### Из Docker

```bash
git clone https://github.com/momai/pizdos-scanner
cd pizdos-scanner

docker compose pull

docker compose run --rm pizdos-scanner geoip-scan ru
```

Образ: `ghcr.io/momai/pizdos-scanner:latest`

## Набор команд запуска

### Для бинаря

```bash
./pizdos-scanner geoip-list                         # показать группы из geoip.dat
./pizdos-scanner geoip-scan ru                      # скан одной группы
./pizdos-scanner geoip-scan cn private telegram     # скан нескольких групп
./pizdos-scanner finalize results/<scan>.jsonl      # пересобрать *_alive.txt и *_rejected.txt
./pizdos-scanner test 1.1.1.1 80 443                # TCP-проверка IP/портов
./pizdos-scanner test 1.1.1.1 443 --sni example.com # TCP/TLS-проверка с SNI
```

Если бинарь установлен в `PATH`, просто используйте `pizdos-scanner ...`.

### Для Docker

```bash
docker compose run --rm --no-build pizdos-scanner geoip-list
docker compose run --rm --no-build pizdos-scanner geoip-scan ru
docker compose run --rm --no-build pizdos-scanner geoip-scan cn private
docker compose run --rm --no-build pizdos-scanner geoip-scan telegram
docker compose run --rm --no-build pizdos-scanner finalize results/<scan>.jsonl
docker compose run --rm --no-build pizdos-scanner test 1.1.1.1 80 443
docker compose run --rm --no-build pizdos-scanner test 1.1.1.1 443 --sni example.com
```

- Команды делают то же самое, что и в разделе для бинаря, но выполняются внутри контейнера.
- `--no-build` ускоряет запуск, если образ уже собран/скачан.

Если остались старые контейнеры:

```bash
docker compose down --remove-orphans
```

## Сборка из исходников (Ubuntu/Debian)

Подготовка:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

Сборка и установка:

```bash
./build.sh
export PATH="$HOME/.local/bin:$PATH"
```

Чтобы добавить в `PATH` навсегда:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

Системная установка:

```bash
INSTALL_DIR=/usr/local/bin sudo ./build.sh
```

И запустите:
```bash
pizdos-scanner geoip-scan ru
```


### ICMP без `sudo` (Linux, `DGRAM`)

```bash
sudo sysctl -w net.ipv4.ping_group_range="0 1000"
```

```toml
socket_type = "DGRAM"
```

В Docker используется `network_mode: host`, capability `NET_RAW` и RAW-сокеты.

## Конфигурация (`config.toml`)

Основные параметры:

```toml
geoip_dat_path = "geoip.dat"
geoip_codes = ["ru"]

ping_type = ["ICMP", "TCP"]
tcp_ports = [80, 443]

results_dir = "results"
resume_state_dir = "results/state"
resume = true

console = "plain" # plain | tui | auto
```

- `geoip-scan` без аргументов берет коды из `geoip_codes`.
- Аргументы команды переопределяют конфиг.
- `console = "plain"` — progress bar (по умолчанию, удобно для Docker).
- `console = "tui"` — дашборд для интерактивного локального терминала.

TCP считается живым, если соединение прошло или порт быстро ответил отказом до общего таймаута 2 секунды.
Быстрый отказ отдельно попадает в `tcp_<port>_rejected_hosts` в CSV и `tcp_rejected` в JSONL.

### Дополнительные параметры

TLS-проверка с SNI:

```toml
tcp_sni_host = "example.com"
```

Принудительный исходящий интерфейс:

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

Для уже готового JSONL текстовые списки можно пересобрать:

```bash
pizdos-scanner finalize results/<scan>.jsonl
```

### Endpoint и ротация IP

После каждой `/24` сканер проверяет контрольный endpoint.
Если endpoint не отвечает — `Stop` остановит скан, `ChangeIp` дернет HTTP-хук:

```toml
endpoint = "77.88.8.8"
endpoint_failure_action = "Stop"   # или ChangeIp
```

Для `ChangeIp`:

```toml
[task]
change_ip_url = "http://127.0.0.1:8080/change-ip"
delay_seconds = 10
```

Плановая ротация после N подсетей:

```toml
[task]
stop_every_times = 10
stop_action = "ChangeIp"           # Delay | ChangeIp | Prompt
change_ip_url = "http://192.168.1.1/changeIp"
delay_seconds = 10
```

### Stop on available (whitelist)

Пока whitelist-ресурс недоступен — скан продолжается. Как только стал доступен — скан останавливается.

```toml
[stop_on_available]
enabled = true
target = "google.com"
port = 443
check_before_subnet = true
check_after_subnet = true
```

Если stop сработал после скана подсети, результат этой подсети не пишется и не попадает в resume.

### MaxMind GeoIP (опционально)

`GeoLite2` `.mmdb` нужны только для колонок `city`, `asn`, `as_name`.
Без них скан работает, но эти поля будут `N/A`.

```bash
curl -L -o db/GeoLite2-City.mmdb \
  https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb

curl -L -o db/GeoLite2-ASN.mmdb \
  https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb
```
