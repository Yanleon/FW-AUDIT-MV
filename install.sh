#!/bin/bash
set -e

echo "[+] Instalando dependencias del sistema..."
sudo apt update
sudo apt install -y nmap netcat-openbsd testssl.sh python3 python3-pip python3-venv

echo "[+] Creando entorno virtual..."
python3 -m venv .venv

echo "[+] Activando entorno virtual..."
source .venv/bin/activate

echo "[+] Instalando dependencias Python..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[+] Preparando carpetas..."
mkdir -p evidence reports logs

echo "[+] Instalación finalizada."
echo "Ejecuta:"
echo "source .venv/bin/activate"
echo "cp config.example.yaml config.yaml"
echo "python3 fw_audit.py --config config.yaml --mode full"
