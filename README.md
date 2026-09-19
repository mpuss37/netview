# NetView

NetView memantau jaringan dan mendeteksi ARP spoofing. Selain itu, ia melindungi
device Anda sendiri dari serangan ARP spoof dan MITM.

NetView adalah kebalikan dari NetControl. NetControl menyerang (cut, limit, flood),
NetView bertahan (monitor, deteksi, proteksi). Keduanya bisa jalan bersamaan.

Antarmuka grafisnya memakai PyQt5, dengan tema gelap dan terang.

## Fitur

### Monitoring

- Sniffer ARP real-time lewat scapy, ditambah scan berkala tiap beberapa detik.
- Peta host lengkap: IP, MAC, hostname, vendor, IPv6, status ancaman, MAC alternatif.
- Tab Live ARP untuk melihat paket ARP secara langsung.

### Deteksi ARP spoof

Ada delapan aturan deteksi:

| Kode | Deteksi | Tingkat |
|------|---------|---------|
| `GATEWAY_MAC_CHANGED` | MAC gateway berubah dari baseline, indikasi MITM | critical |
| `IP_MULTIPLE_MACS` | Satu IP diklaim lebih dari satu MAC | warning |
| `MAC_MULTIPLE_IPS` | Satu MAC mengklaim banyak IP | warning |
| `GARP_FLOOD` | Gratuitous ARP flood dari satu MAC | critical |
| `GATEWAY_RANDOM_MAC` | Gateway memakai MAC acak atau privat | warning |
| `OUT_OF_SUBNET_CLAIM` | ARP mengklaim IP di luar subnet | info |
| `DUPLICATE_MAC_OUI` | MAC yang sama dipakai gateway dan host lain | info |
| `UNSOLICITED_REPLY` | ARP reply yang tidak diminta | info |

Alert disimpan, bisa difilter, dan bisa diekspor ke JSON.

### Proteksi device sendiri

- Hardening pasif: kunci ARP gateway secara statis lewat `ip neigh ... nud permanent`,
  plus `arptables` dengan default DROP yang hanya mengizinkan MAC gateway yang benar.
- Auto-Defense yang aktif saat ada ancaman critical. Fitur ini opsional dan
  defaultnya mati. Saat menyala, MAC penyerang diblokir di arptables dan ARP
  gateway dipulihkan.

### GUI

- Tab Hosts: tabel host dengan status ancaman (normal, curiga, PENYERANG).
- Tab Alerts: daftar kejadian berisi waktu, tingkat, jenis, dan keterangan.
- Tab Live ARP: log ARP real-time.
- Toolbar: Refresh, Scan, Monitor, Proteksi, Auto-Defense, Notifikasi desktop,
  Pengaturan, Clear Alerts, Export, Topology View, Tema, Exit.
- Whitelist MAC/IP untuk mengabaikan host tertentu dari deteksi.

### Topology View

Visualisasi graf jaringan 2D secara real-time di browser, di
`http://127.0.0.1:8015/tv`.

- Router atau gateway ada di pusat, host mengelilinginya. Bisa dipilih mode radial
  atau cluster.
- Penempatan berbasis kedekatan. Host dengan RTT mirip diletakkan pada cincin yang sama.
- Ada penanganan anti-tumpuk, dan estimasi jarak per perangkat berbasis RTT dengan
  akurasi sekitar 2 sampai 5 meter.
- Warna node: biru untuk router, hijau untuk perangkat ini, abu untuk host normal,
  oranye untuk yang mencurigakan, merah berdenyut untuk penyerang.
- Panel kanan menampilkan info host dan tombol whitelist.
- Ada hover tooltip, zoom dengan scroll, pan dengan drag, dan toggle garis atau cincin.

Posisi dan jarak node di Topology View adalah estimasi dari RTT, bukan lokasi
fisik. ARP tidak membawa informasi lokasi, jadi ini bukan GPS.

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
    web/                 Topology View di browser
        index.html
        style.css
        topology.js      canvas 2D, render + poll real-time
```

GUI dan daemon terpisah, berkomunikasi lewat HTTP API di `127.0.0.1:8015`.
Topology View dilayani sebagai halaman web dari daemon yang sama, di `/tv`.

## Dukungan platform

| OS | GUI (PyQt5) | Daemon (monitor, deteksi, proteksi) | Catatan |
|----|:-----------:|:-----------------------------------:|---------|
| Arch Linux | bisa | bisa, full | systemd |
| Ubuntu 22.04+ | bisa | bisa, full | systemd |
| Linux Mint 21/22 | bisa | bisa, full | systemd |
| Artix / OpenRC | bisa | bisa, full | ada `build.sh` dan `netviewd.init` |
| Windows lewat WSL2 | bisa | bisa, full | cara yang disarankan untuk Windows |
| Windows native | bisa | tidak bisa | butuh `fcntl`, `arptables`, raw socket yang tidak ada |
| Termux Android | dengan usaha ekstra | butuh root | perlu device root dan XServer untuk GUI |

Daemon wajib root dan wajib Linux, karena memakai raw socket ARP, `arptables`,
dan `ip neigh`. Di Windows native modul Python `fcntl` tidak tersedia, jadi
daemon tidak akan start. Untuk Windows, pakai WSL2.

## Dependensi

Paket Python (lihat `requirements.txt`):
`PyQt5`, `bottle`, `waitress`, `scapy`, `netifaces`, `setproctitle`,
`requests`, `psutil`

Alat sistem:
`arptables`, `arp-scan` atau `arping`, `ip` (iproute2),
`nmap` (opsional), `arp` (net-tools, opsional).

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

Di Ubuntu 24.04, `arptables` bisa ada di paket `arptables-nft`.

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

### Windows

Daemon tidak bisa jalan di Windows native. Pakai WSL2, yang menjalankan Ubuntu
penuh di dalam Windows. Di PowerShell sebagai admin, sekali saja:

```powershell
wsl --install -d Ubuntu
```

Setelah itu, di dalam WSL2, ikuti langkah Ubuntu di atas. GUI muncul lewat WSLg,
yang sudah ada di Windows 11 dan Windows 10 versi terbaru. Jalankan dengan
`sudo netview`.

Kalau hanya ingin mencoba GUI di Windows native:

```powershell
# Pasang Python 3.11+ dari python.org dan Npcap dari https://npcap.com/
pip install PyQt5 bottle waitress scapy netifaces requests psutil
```

Daemon akan gagal start karena `fcntl` tidak ada. Deteksi dan proteksi butuh Linux.

### Termux (Android)

```bash
pkg update && pkg upgrade
pkg install -y python clang git x11-repo python-pyqt5
pip install bottle waitress scapy netifaces requests psutil
```

Monitor, deteksi, dan proteksi butuh root karena memakai raw socket dan arptables.
Tanpa root, hanya GUI yang tampil. Untuk GUI, jalankan Termux:X11 atau
XServer XSDL, lalu set `export DISPLAY=:0`.

## Service (auto-start daemon)

### systemd (Arch, Ubuntu, Mint)

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

Aktifkan dengan:

```bash
sudo mkdir -p /var/log/netview
sudo systemctl daemon-reload
sudo systemctl enable --now netviewd
sudo systemctl status netviewd
```

### OpenRC (Artix)

`build.sh` dan `server/netviewd.init` sudah disiapkan untuk OpenRC:

```bash
sudo ./build.sh
```

## Menjalankan

Di Linux dengan systemd:

```bash
sudo systemctl start netviewd
sudo netview
```

Launcher `netview` akan menyalakan daemon kalau belum jalan. Dengan OpenRC, ganti
baris pertama dengan `sudo rc-service netviewd start`.

Topology View dibuka lewat `http://127.0.0.1:8015/tv`, atau klik tombol
Topology View di toolbar GUI.

## Konfigurasi

- Whitelist: `~/.netview/whitelist.json`
- Preferensi tema: `~/.netview/netview.conf`
- Preferensi notifikasi: `~/.netview/notify.conf`
- Log daemon: `/var/log/netview/`

## Catatan dan batasan

- Daemon butuh root untuk sniffer ARP dan arptables.
- Di sebagian access point yang membridge trafik klien secara langsung, sniffer
  mungkin tidak melihat semua ARP unicast. ARP broadcast dan gratuitous ARP tetap
  terlihat, dan itu cukup untuk deteksi.
- NetView dan NetControl sama-sama memakai arptables polos. Kalau NetControl
  melakukan spoof di device yang sama dengan NetView proteksi aktif, arptables
  keduanya bisa saling memengaruhi. Praktik yang lebih aman: jalankan proteksi
  NetView di device Anda, dan NetControl di device lain. Atau matikan proteksi
  NetView saat menguji spoof.
- Saat proteksi aktif, arptables NetView memakai policy DROP. Pastikan gateway
  terdeteksi dengan benar sebelum menyalakan proteksi.
- Windows native dan Termux tanpa root tidak bisa menjalankan daemon.

## Troubleshooting

| Masalah | Penyebab dan solusi |
|---|---|
| `NameError: QApplication is not defined` | Versi lama. Jalankan `git pull`. |
| `ModuleNotFoundError: fcntl` di Windows | Daemon memang bukan untuk Windows native. Pakai WSL2. |
| Daemon gagal start | Cek `/var/log/netview/netviewd.out`. Pastikan dijalankan sebagai root. |
| `arptables: command not found` | Pasang `arptables` atau `arptables-nft`. |
| Proteksi memblokir internet | Gateway salah terdeteksi. Matikan proteksi, refresh, lalu cek gateway. |
| Topology kosong | Pastikan daemon jalan dan monitoring aktif. Buka `/tv`. |
| GUI tidak muncul di WSL2 | Jalankan `wsl --update` dan pastikan WSLg aktif. |
| GUI tidak muncul di Termux | Jalankan XServer, lalu set `DISPLAY`. |

## Etika dan legal

NetView memantau paket ARP di jaringan. Pakai hanya di jaringan yang Anda miliki
atau kelola, atau yang sudah ada izinnya. Sniffing jaringan pihak lain tanpa izin
melanggar hukum.
