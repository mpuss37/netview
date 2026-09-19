# NetView

Alat **monitoring jaringan** dan **deteksi ARP spoofing** untuk Linux, sekaligus
**melindungi device Anda sendiri** dari serangan ARP spoof / MITM.

NetView adalah "kebalikan" dari NetControl: NetControl *menyerang* (cut/limit/flood),
NetView *bertahan* (monitor/deteksi/proteksi). Keduanya bisa berjalan bersamaan.

Antarmuka grafis berbasis **PyQt5** dengan tema **gelap & terang**.

---

## Fitur

### Monitoring
- Sniffer ARP **real-time** (scapy) + **scan berkala** tiap beberapa detik.
- Peta host lengkap: IP, MAC, hostname, vendor, IPv6, status ancaman, MAC alternatif.
- Tab **Live ARP** — log paket ARP secara langsung.

### Deteksi ARP Spoof (8 aturan)
| Kode | Deteksi | Tingkat |
|------|---------|---------|
| `GATEWAY_MAC_CHANGED` | MAC gateway berubah dari baseline (MITM) | critical |
| `IP_MULTIPLE_MACS` | Satu IP diklaim >1 MAC | warning |
| `MAC_MULTIPLE_IPS` | Satu MAC mengklaim banyak IP | warning |
| `GARP_FLOOD` | Gratuitous ARP flood dari satu MAC | critical |
| `GATEWAY_RANDOM_MAC` | Gateway pakai MAC acak/privat | warning |
| `OUT_OF_SUBNET_CLAIM` | ARP mengklaim IP di luar subnet | info |
| `DUPLICATE_MAC_OUI` | MAC sama dipakai gateway & host lain | info |
| `UNSOLICITED_REPLY` | ARP reply tak diminta | info |

Alert disimpan, dapat difilter, dan diekspor (JSON).

### Proteksi Device Sendiri
- **Hardening (pasif)**: kunci ARP gateway statis (`ip neigh ... nud permanent`)
  + `arptables` default DROP yang hanya mengizinkan gateway MAC benar.
- **Auto-Defense (aktif, opsional, default MATI)**: saat terdeteksi ancaman
  critical, NetView otomatis memblokir MAC penyerang di arptables dan
  memulihkan ARP gateway.

### GUI
- **Tab Hosts** — tabel host dengan status ancaman (normal / curiga / PENYERANG)
- **Tab Alerts** — daftar kejadian (waktu, tingkat, jenis, keterangan)
- **Tab Live ARP** — log ARP real-time
- Toolbar: Refresh, Scan, Monitor ON/OFF, Proteksi, Auto-Defense,
  **Notifikasi desktop (toggle)**, Pengaturan, Clear Alerts, Export,
  **Topology View**, Tema, Exit
- Whitelist MAC/IP (abaikan dari deteksi)

### Topology View (browser)
Visualisasi graf jaringan 2D **real-time** di browser (`http://127.0.0.1:8015/tv`):
- **Router/gateway** di pusat, host mengelilingi (radial / cluster).
- Penempatan berbasis kedekatan (RTT mirip → cincin sama).
- Anti-tumpuk + estimasi jarak per perangkat (berbasis RTT, akurasi ±2–5 m).
- Warna node: router (biru), perangkat ini (hijau), normal (abu),
  mencurigakan (oranye), **penyerang (merah + berdenyut)**.
- Panel samping kanan: info host + tombol whitelist.
- Hover tooltip, zoom (scroll), pan (drag), toggle garis/cincin.

> ⚠️ Posisi & jarak node adalah **estimasi topologi** dari **RTT/latency** —
> **BUKAN lokasi fisik**. ARP tidak membawa informasi lokasi; ini bukan GPS.

---

## Arsitektur
```
netview/                 GUI PyQt5
    app.py               entry point
    main_window.py       window utama (3 tab)
    host_model.py        model tabel host
    alert_model.py       model tabel alert
    dialogs.py           dialog detail & pengaturan
    api.py               klien HTTP
    theme.py             stylesheet gelap/terang
server/
    server.py            daemon (bottle+waitress, port 8015)
    monitor.py           sniffer ARP + scanner + RTT + topology()
    detector.py          8 aturan deteksi ARP spoof
    defense.py           hardening + auto-defense
    utils.py             scan, ARP table, vendor, hostname
    netviewd.init        service OpenRC (Artix)
    web/                 Topology View (browser)
        index.html
        style.css
        topology.js      canvas 2D render + real-time poll
```

GUI dan daemon terpisah lewat HTTP API di **`127.0.0.1:8015`**.
Topology View diserve sebagai halaman web dari daemon yang sama (`/tv`).

---

## Dukungan Platform

| OS | GUI (PyQt5) | Daemon (monitor / deteksi / proteksi) | Catatan |
|----|:-----------:|:-------------------------------------:|---------|
| **Arch Linux** | ✅ | ✅ full | systemd |
| **Ubuntu 22.04+** | ✅ | ✅ full | systemd |
| **Linux Mint 21/22** | ✅ | ✅ full | systemd |
| **Artix / OpenRC** | ✅ | ✅ full | sudah ada `build.sh` + `netviewd.init` |
| **Windows (WSL2)** | ✅ | ✅ full | Jalankan di dalam WSL2 — **cara disarankan** |
| **Windows (native)** | ✅ | ❌ tidak bisa | Butuh `fcntl`, `arptables`, raw socket → tidak ada |
| **Termux (Android)** | ⚠️ | ❌ non-root / ✅ root | Butuh **root** + XServer |

> **Penting:** Daemon **wajib root** dan **wajib Linux** (sniffer ARP raw socket
> + `arptables` + `ip neigh`). Di Windows native `fcntl` tidak ada → daemon gagal.
> **Gunakan WSL2** di Windows.

---

## Dependensi

**Python (via `requirements.txt`):**
`PyQt5`, `bottle`, `waitress`, `scapy`, `netifaces`, `setproctitle`,
`requests`, `psutil`

**Alat sistem:**
`arptables`, `arp-scan` / `arping`, `ip` (iproute2), `nginx`? (tidak perlu),
`nmap` (opsional), `arp` (net-tools, opsional).

---

## Instalasi

### Arch Linux

```bash
sudo pacman -S --needed python python-pip python-pyqt5 \
    iproute2 arptables arp-scan nmap net-tools git

git clone https://github.com/mpuss37/netview.git
cd netview

python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Deploy
sudo mkdir -p /opt/netview
sudo cp -a netview server assets /opt/netview/
sudo cp launcher /usr/bin/netview && sudo chmod 755 /usr/bin/netview
```

### Ubuntu 22.04 / 24.04

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv python3-pyqt5 \
    iproute2 arptables arp-scan nmap net-tools git

git clone https://github.com/mpuss37/netview.git
cd netview

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

sudo mkdir -p /opt/netview
sudo cp -a netview server assets /opt/netview/
sudo cp launcher /usr/bin/netview && sudo chmod 755 /usr/bin/netview
```

> Pada Ubuntu 24.04 `arptables` bisa bernama `arptables-nft`
> (`sudo apt install arptables-nft`).

### Linux Mint 21 / 22

Sama seperti Ubuntu:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv python3-pyqt5 \
    iproute2 arptables arp-scan nmap net-tools git
git clone https://github.com/mpuss37/netview.git
cd netview
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
sudo mkdir -p /opt/netview && sudo cp -a netview server assets /opt/netview/
sudo cp launcher /usr/bin/netview && sudo chmod 755 /usr/bin/netview
```

### Windows (disarankan: WSL2)

Daemon tidak bisa jalan di Windows native → pakai **WSL2** (Ubuntu penuh):

```powershell
wsl --install -d Ubuntu     # sekali saja, di PowerShell (admin)
```

Lalu **di dalam WSL2**, ikuti langkah **Ubuntu** di atas. GUI tampil lewat
**WSLg** (Windows 11 / 10 terbaru). Jalankan: `sudo netview`.

### Windows (native — GUI saja)

```powershell
# Pasang Python 3.11+ (https://python.org) dan Npcap (https://npcap.com/)
pip install PyQt5 bottle waitress scapy netifaces requests psutil
```

> Daemon gagal start (`fcntl` tidak ada). Fitur proteksi/deteksi butuh Linux.

### Termux (Android)

```bash
pkg update && pkg upgrade
pkg install -y python clang git x11-repo python-pyqt5
pip install bottle waitress scapy netifaces requests psutil
```

- **Monitor/deteksi/proteksi butuh root** (raw socket + arptables).
  Tanpa root hanya GUI tampil.
- GUI: jalankan **Termux:X11** / **XServer XSDL**, set `export DISPLAY=:0`.

---

## Service (auto-start daemon)

### systemd (Arch / Ubuntu / Mint)

Buat `/etc/systemd/system/netviewd.service`:

```ini
[Unit]
Description=NetView daemon (ARP monitor & spoof detector)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/netview/server/server.py
WorkingDirectory=/opt/netview/server
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

```bash
sudo mkdir -p /var/log/netview
sudo systemctl daemon-reload
sudo systemctl enable --now netviewd
sudo systemctl status netviewd
```

### OpenRC (Artix)

```bash
sudo ./build.sh     # menyediakan build.sh + server/netviewd.init
```

---

## Menjalankan

```bash
sudo systemctl start netviewd      # daemon (systemd)
sudo netview                       # buka GUI (auto-start daemon bila perlu)
```

OpenRC:

```bash
sudo rc-service netviewd start
sudo netview
```

Topology View: buka `http://127.0.0.1:8015/tv` atau klik tombol
**Topology View** di toolbar GUI.

---

## Konfigurasi

- Whitelist: `~/.netview/whitelist.json`
- Preferensi tema: `~/.netview/netview.conf`
- Preferensi notifikasi: `~/.netview/notify.conf`
- Log daemon: `/var/log/netview/`

---

## Catatan & Batasan

- Daemon butuh **root** (sniffer ARP + arptables).
- Pada beberapa AP yang mem-bridge trafik klien secara langsung, sniffer
  mungkin tidak melihat semua ARP unicast; **broadcast ARP & gratuitous ARP
  tetap terlihat** — cukup untuk deteksi.
- **Konflik dengan NetControl/TuxCut**: keduanya memakai `arptables` polos.
  Jika Anda memakai NetControl untuk spoof *pada device yang sama* dengan
  NetView proteksi aktif, arptables bisa saling memengaruhi. Praktik terbaik:
  jalankan NetView proteksi di device Anda, dan NetControl di device lain
  (atau matikan proteksi NetView saat melakukan uji spoof).
- `arptables` NetView memakai policy **DROP** saat proteksi aktif — pastikan
  gateway terdeteksi dengan benar sebelum mengaktifkan.
- **Windows native & Termux non-root tidak dapat menjalankan daemon.**

---

## Troubleshooting

| Masalah | Penyebab / Solusi |
|---|---|
| `NameError: QApplication is not defined` | Versi lama; sudah diperbaiki. `git pull`. |
| `ModuleNotFoundError: fcntl` (Windows) | Daemon tidak untuk Windows native → WSL2. |
| Daemon gagal start | Cek `/var/log/netview/netviewd.out`; jalankan sebagai root. |
| `arptables: command not found` | Pasang `arptables` / `arptables-nft`. |
| Proteksi memblokir internet | Gateway salah terdeteksi → matikan proteksi, refresh, cek gateway. |
| Topology kosong | Pastikan daemon jalan & monitoring ON; buka `/tv`. |
| GUI tidak muncul di WSL2 | `wsl --update`; pastikan WSLg aktif. |
| GUI tidak muncul di Termux | Jalankan XServer, set `DISPLAY`. |

---

## Etika & Legal

NetView memantau paket ARP di jaringan. Gunakan hanya di jaringan yang
**Anda miliki / kelola** atau dengan izin. Sniffing jaringan pihak lain
tanpa izin **melanggar hukum**.
