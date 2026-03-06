# SenseCAP M1 Setup Guide

## 1. Back up the original SD

Before opening the case, note your hotspot credentials and back up the SD.

```bash
# From any Linux machine with SD reader:
dd if=/dev/sdX of=~/sensecap-backup.img bs=4M status=progress
```

Copy `config.json` from the `resin-boot` partition — this is your Helium identity.

## 2. Open the case

- Remove 4 screws from the bottom
- Slide out the SD card (under yellow tape, near the Pi4 board)

## 3. Flash Raspbian Lite 64-bit

```bash
# Download: https://www.raspberrypi.com/software/operating-systems/
# Flash with Balena Etcher or dd
# Enable SSH: touch /boot/ssh on the boot partition
# Set WiFi or use Ethernet
```

## 4. First boot — basic setup

```bash
ssh pi@<ip>   # default pass: raspberry
sudo raspi-config
# Enable: SPI, I2C, SSH
# Expand filesystem
# Change password

sudo apt update && sudo apt upgrade -y
sudo apt install -y git docker.io python3 python3-pip
sudo usermod -aG docker pi
```

## 5. Install sx1302_hal

```bash
git clone https://github.com/Lora-net/sx1302_hal.git
cd sx1302_hal
make all

# Copy SenseCAP M1 config (SX1302, AU915)
cp tools/reset_lgw.sh packet_forwarder/
# Edit global_conf.json.sx1250.AU915 for your settings
```

## 6. Run ckb-light-client (Docker)

```bash
# Pull ARM64 image
docker pull nervos/ckb-light-client:latest

# Create config
mkdir -p ~/ckb-light
cat > ~/ckb-light/config.toml << 'EOF'
[network]
listen_addresses = ["/ip4/0.0.0.0/tcp/8115"]
bootnodes = []

[[peers]]
address = "/ip4/192.168.68.87/tcp/8115"  # your ckbnode

[store]
path = "data"
EOF

docker run -d \
  --name ckb-light \
  --restart unless-stopped \
  -v ~/ckb-light:/data \
  -p 9000:9000 \
  nervos/ckb-light-client:latest \
  run --config /data/config.toml
```

## 7. Run the LoRa gateway bridge

```bash
git clone https://github.com/toastmanAu/ckb-lora-gateway.git
cd ckb-lora-gateway
pip3 install -r requirements.txt
python3 gateway.py
```
