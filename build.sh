#!/bin/bash
# ============================================================
#  NetView - deploy ke sistem (Artix/OpenRC)
#  Jalankan sebagai root:  sudo ./build.sh
# ============================================================
set -e

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Butuh root. Jalankan: sudo ./build.sh"
    exit 1
fi

echo "[*] Deploy aplikasi ke /opt/netview ..."
rm -rf /opt/netview
mkdir -p /opt/netview
cp -a "$SRC_DIR/netview" /opt/netview/netview
cp -a "$SRC_DIR/server" /opt/netview/server
cp -a "$SRC_DIR/assets" /opt/netview/assets
cp "$SRC_DIR/netview.desktop" /opt/netview/
rm -rf /opt/netview/netview/__pycache__ /opt/netview/server/__pycache__

echo "[*] Install launcher /usr/bin/netview ..."
cp "$SRC_DIR/launcher" /usr/bin/netview
chmod 755 /usr/bin/netview

echo "[*] Install service /etc/init.d/netviewd ..."
cp "$SRC_DIR/server/netviewd.init" /etc/init.d/netviewd
chmod 755 /etc/init.d/netviewd
rc-update add netviewd default 2>/dev/null || true

echo "[*] Install desktop entry & ikon ..."
cp "$SRC_DIR/netview.desktop" /usr/share/applications/netview.desktop
cp "$SRC_DIR/assets/ninja_32.png" /usr/share/pixmaps/netview.png

echo "[*] Siapkan direktori log ..."
mkdir -p /var/log/netview

echo "[*] Restart service ..."
rc-service netviewd restart || rc-service netviewd start

echo "[+] Selesai. Jalankan GUI dengan:  sudo netview"
