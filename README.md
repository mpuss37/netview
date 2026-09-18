# NetView

Alat **monitoring jaringan** dan **deteksi ARP spoofing** untuk Linux, sekaligus
**melindungi device Anda sendiri** dari serangan ARP spoof / MITM.

NetView adalah "kebalikan" dari NetControl: NetControl *menyerang* (cut/limit/flood),
NetView *bertahan* (monitor/deteksi/proteksi). Keduanya bisa berjalan bersamaan.

Antarmuka grafis berbasis **PyQt5** dengan tema **gelap & terang**.

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
- **Router/gateway** di pusat, host mengelilingi (radial).
- Warna node: router (biru), perangkat ini (hijau), normal (abu),
  mencurigakan (oranye), **penyerang (merah + berdenyut)**.
- Garis: hub ke gateway + overlay komunikasi ARP nyata.
- **Garis putus merah berdenyut** dari penyerang ke gateway (indikasi MITM).
- Panel samping kanan: info host + tombol whitelist.
- Hover tooltip, zoom (scroll), pan (drag), toggle garis/cincin.

> ⚠️ **Penting:** posisi node adalah **estimasi topologi** berdasarkan **RTT** &
> aktivitas ARP — **BUKAN lokasi fisik** sebenarnya. ARP tidak membawa informasi
> lokasi; ini bukan GPS. Label ini juga ditampilkan di UI.

Buka dari browser: `http://127.0.0.1:8015/tv`
Atau klik tombol **Topology View** di toolbar GUI desktop.
- Tema gelap/terang (tersimpan di `~/.netview/`)

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
    web/                 Topology View (browser)
        index.html
        style.css
        topology.js      canvas 2D render + real-time poll
```

GUI dan daemon terpisah lewat HTTP API di `127.0.0.1:8015`.
Topology View diserve sebagai halaman web dari daemon yang sama (`/tv`).

## Instalasi (sistem ini)
Sudah terpasang:
- Aplikasi: `/opt/netview/`
- Launcher: `/usr/bin/netview`
- Service: `/etc/init.d/netviewd` (aktif saat boot, port 8015)
- Menu: `/usr/share/applications/netview.desktop`

## Menjalankan
```bash
sudo rc-service netviewd start      # jalankan daemon
sudo netview                        # buka GUI (auto-start daemon bila perlu)
```

## Konfigurasi
- Whitelist: `~/.netview/whitelist.json`
- Preferensi tema: `~/.netview/netview.conf`
- Preferensi notifikasi: `~/.netview/notify.conf`
- Log daemon: `/var/log/netview/`

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

## Dependensi
Python 3, PyQt5, bottle, waitress, scapy, netifaces, setproctitle, requests.
Alat sistem: `arptables`, `arp-scan`/`arping`, `nmap` (opsional), `ip`.

Lihat `requirements.txt`.

## Terkait
- **NetControl** — alat *ofensif* (cut / limit bandwidth / ping flood).
  NetView adalah pasangan defensifnya.
