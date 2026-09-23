# Laya NetWatch

PCAP/PCAPNG → TShark → fitur per jendela → Laya → evaluasi dengan label. Ini alat eksperimen **sekaligus testing**, bukan klaim akurasi keamanan.

## Pasang

Di Windows, pasang Wireshark dengan TShark. Pastikan `& 'C:\Program Files\Wireshark\tshark.exe' --version` berhasil. Lalu di PowerShell dari folder proyek:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install 'git+https://github.com/NandhaKishorM/laya.git'
.\.venv\Scripts\python.exe -I -c 'import laya; print(laya.__version__)'
```

Mengikuti [API resmi Laya](https://github.com/NandhaKishorM/laya), program memakai `Router.predict()` dengan pertanyaan `choice`, `score`, dan `noul`. Model `english` dipakai karena prompt dan state-nya berbahasa Inggris. Model diunduh dari Hugging Face saat pemakaian pertama; perlu internet, ruang disk, dan RAM. `--engine rules` dapat dipakai tanpa Laya.

## Coba satu PCAP

```powershell
.\.venv\Scripts\python.exe netwatch.py extract --pcap .\captures\normal.pcapng --out .\out\normal.jsonl --tshark 'C:\Program Files\Wireshark\tshark.exe'
.\.venv\Scripts\python.exe netwatch.py predict --input .\out\normal.jsonl --out .\out\normal-predictions.jsonl --engine both
```

`--window 5` adalah default; boleh ganti ke 1 atau 10 detik. Hasil JSONL memuat fitur, keputusan rules/Laya, confidence, score 0–3, probabilitas review, dan jawaban mentah Laya. Untuk memilih checkpoint lain, pakai `--model typed-decisions` atau `--model multilingual`.

## Testing berlabel

Rekam PCAP terpisah dengan satu perilaku dominan per file. Buat `manifest.csv`:

```csv
pcap,label
captures/normal-01.pcapng,normal
captures/scan-01.pcapng,port_scan
captures/dns-01.pcapng,dns_activity
captures/burst-01.pcapng,connection_burst
```

Path PCAP relatif ke lokasi manifest. Label yang tersedia: `normal`, `port_scan`, `dns_activity`, `connection_burst`, `unknown`. Semua jendela di suatu file mewarisi label file itu. Potong bagian idle atau campuran sebelum testing supaya labelnya masuk akal.

```powershell
.\.venv\Scripts\python.exe netwatch.py evaluate --manifest .\manifest.csv --out-dir .\out\eval --tshark 'C:\Program Files\Wireshark\tshark.exe' --engine both
```

Hasil: `observations.jsonl`, `predictions.jsonl`, `predictions.csv`, `metrics.json`. Metrik berisi accuracy, precision, recall, F1 per kelas, macro F1 untuk kelas yang hadir, dan confusion matrix. Bandingkan Laya dengan rules pada jendela yang sama. Periksa baris salah klasifikasi lalu buka rentang waktunya di Wireshark. Jangan atur threshold pada capture uji yang sama lalu mengklaim hasil akhirnya; sisihkan PCAP uji independen.

Untuk traffic scan contoh, jalankan `nmap -sT -p 1-500 127.0.0.1` hanya pada localhost/lab milik sendiri sambil merekam interface loopback. Rekam normal browsing dan DNS berulang sebagai PCAP lain. Ulangi evaluasi pada beberapa PCAP independen, kemudian coba `--window 1`, `5`, dan `10` ke folder hasil berbeda.

## Dashboard

Buka [dashboard/index.html](dashboard/index.html) di browser. Pilih `metrics.json` dan `predictions.jsonl` hasil `evaluate`. Semua data diproses lokal di browser. Ada ringkasan metrik, distribusi prediksi, confusion matrix, dan tabel jendela dengan filter engine/status. Untuk hasil `predict` tanpa label, pilih `predictions.jsonl` saja; metrik akan kosong tapi tabel tetap tampil.

## Catatan metode

Jendela dimulai dari timestamp paket pertama per PCAP, panjang default 5 detik; jendela kosong tidak dikeluarkan. `frame.len` adalah ukuran frame, SYN dihitung hanya SYN tanpa ACK, DNS query dihitung bila `dns.flags.response=0`, dan laju dibagi durasi nominal jendela. `unique_dst_ports` mencakup TCP/UDP; IP mencakup IPv4/IPv6. Fitur ini tidak melakukan rekonstruksi koneksi atau inspeksi payload terenkripsi.

Baseline rules memakai threshold sederhana dalam `netwatch.py`, hanya sebagai pembanding awal. Confidence Laya dan probabilitas review bukan tingkat akurasi empiris. Jendela dari satu PCAP saling berkaitan; angka dari sedikit capture bukan estimasi kinerja umum. Untuk klaim performa, butuh lebih banyak PCAP independen dan label yang diperiksa manual.

Cek kode tanpa TShark dan model: `py -3.11 -m unittest discover -s tests -v`.
