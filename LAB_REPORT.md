# Hasil lab localhost — normal vs port scan

Pengujian ini dijalankan di mesin lokal dengan Wireshark/TShark 4.6.8. Kedua capture direkam pada **Adapter for loopback traffic capture** dengan filter `host 127.0.0.2`. Traffic normal dibuat dengan 12 HTTP GET ke server lokal. Traffic scan dibuat dengan 120 percobaan koneksi TCP ke port 1–120 pada alamat lokal yang sama. Ini **connect scan Python**, bukan Nmap; pola paketnya relevan untuk membandingkan trafik normal dan scan TCP tanpa menyentuh jaringan luar.

## Bukti paket dari TShark

| Pengamatan | Normal | Scan |
|---|---:|---:|
| Total paket TCP | 153 | 240 |
| HTTP request / response | 12 / 12 | 0 / 0 |
| SYN awal | 12 | 120 |
| Port tujuan SYN yang unik | 1 | 120 |
| TCP RST | 0 | 120 |
| TCP FIN | 26 | 0 |
| Paket per detik, jendela 5 s | 30,6 | 48,0 |

Normal: contoh paket nomor 4 adalah `127.0.0.1 → 127.0.0.2:58181`, HTTP `GET /`. Scan: paket nomor 1, 3, 5, 7, 9 adalah SYN ke port 1, 2, 3, 4, 5. Setiap port yang ditutup membalas dengan RST. Kolom `unique_dst_ports` mentah mencakup **dua arah** dan karena itu 13 vs 240; kolom `unique_syn_dst_ports` (1 vs 120) lebih tepat untuk membaca target scan.

## Keputusan pada dua jendela yang sama

| Label asli | Rules | Laya `choice` | Prob. label tertinggi Laya | Laya `score` 0–3 | Laya `noul` review |
|---|---|---|---:|---:|---:|
| normal | normal | normal | 0,3367 | 0,8864 | 0,8480 |
| port_scan | port_scan | normal | 0,3146 | 0,8055 | 0,8915 |

Rules benar 2/2; Laya benar 1/2. Laya memilih `normal` untuk scan walaupun 120 port SYN terlihat jelas di fitur. Nilai `noul` review tinggi pada **kedua** capture sehingga belum membantu memisahkan kasus ini. Runtime Laya juga memberi peringatan bahwa temperature checkpoint untuk sebagian pilihan berada di luar rentang valid dan confidence yang terdampak harus dianggap belum terkalibrasi. `confidence` internal Laya di CSV adalah 0,0453 dan 0,0383; itu **bukan** probabilitas label tertinggi di tabel ini.

Sampel hanya **satu capture per kelas, satu jendela per capture**. Accuracy 100% vs 50% di sini adalah hasil uji kecil, bukan estimasi performa deteksi umum. Jendela dan contoh ini juga sudah dilihat saat mengembangkan pipeline, jadi jangan dipakai sebagai holdout untuk tuning berikutnya.

## File yang bisa dibuka

- Dashboard siap lihat: [`out/isolated-laya/dashboard.html`](out/isolated-laya/dashboard.html)
- Tabel: [`out/isolated-laya/predictions.csv`](out/isolated-laya/predictions.csv)
- Metrik lengkap: [`out/isolated-laya/metrics.json`](out/isolated-laya/metrics.json)
- Capture normal: [`captures/isolated/normal-local.pcapng`](captures/isolated/normal-local.pcapng)
- Capture scan: [`captures/isolated/scan-local.pcapng`](captures/isolated/scan-local.pcapng)

Capture dan folder `out` disimpan lokal serta diabaikan Git karena PCAP bisa mengandung telemetri mesin.

## Ulangi sendiri

```powershell
py -3.11 lab_traffic.py --tshark 'C:\Program Files\Wireshark\tshark.exe' --interface 5 --out-dir captures/isolated
.\.venv\Scripts\python.exe netwatch.py evaluate --manifest lab_manifest.csv --out-dir out/isolated-laya --tshark 'C:\Program Files\Wireshark\tshark.exe' --engine both
```

Nomor interface bisa berubah; cek dulu dengan `& 'C:\Program Files\Wireshark\tshark.exe' -D`, lalu pilih nomor **Adapter for loopback traffic capture**. Untuk memeriksa di Wireshark, buka salah satu PCAP dan pakai display filter `tcp.flags.syn == 1 && tcp.flags.ack == 0`, `tcp.flags.reset == 1`, atau `http.request`.
