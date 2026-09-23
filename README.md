# Laya NetWatch

PCAP/PCAPNG → TShark → fitur per jendela → Laya → evaluasi dengan label. Ini alat eksperimen **sekaligus testing**, bukan klaim akurasi keamanan.

## Mulai dari nol: PCAP dapat dari mana?

PCAP/PCAPNG adalah **rekaman traffic jaringan**. Cara paling mudah: buat sendiri dengan Wireshark yang sudah terpasang.

1. Buat folder `captures` di proyek ini.
2. Buka Wireshark. Untuk traffic browser biasa pilih interface **Ethernet** di halaman awal, lalu mulai capture (klik dua kali interface atau ikon sirip hiu).
3. Buka beberapa situs di browser sekitar 20–30 detik. Kembali ke Wireshark, klik tombol Stop (kotak merah).
4. Pilih **File → Save As**, simpan sebagai `captures/normal-01.pcapng`. Pastikan daftar paketnya tidak kosong.
5. Sekarang file itu bisa dipakai oleh `netwatch.py`. TShark membaca file tersebut; ia bukan sumber PCAP. Dashboard membaca hasil JSON dari Python.

Untuk uji scan localhost, pilih **Adapter for loopback traffic capture** di Wireshark sebelum merekam, lalu jalankan `nmap -sT -p 1-500 127.0.0.1` dari terminal dan simpan rekamannya sebagai `captures/scan-01.pcapng`. Hanya lakukan ini pada localhost atau lab yang km kelola. Wireshark dapat menyimpan capture melalui **File → Save/Save As**; lihat [panduan resminya](https://www.wireshark.org/docs/wsug_html_chunked/ChapterIO.html).

Alur singkatnya: **Wireshark merekam → `.pcapng` tersimpan → Python memanggil TShark → Laya/rules menilai → dashboard membuka hasil**.

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

Perintah `evaluate` juga membuat `dashboard.html` **di folder hasil**; file itu sudah berisi data dan dapat dibuka langsung tanpa memilih JSON. Contoh uji localhost yang benar-benar dijalankan pada proyek ini tercatat di [LAB_REPORT.md](LAB_REPORT.md), bersama PCAP dan tabel hasil lokal. Untuk mengulanginya, jalankan `lab_traffic.py` pada interface loopback yang ditunjukkan oleh `tshark -D`, lalu jalankan `evaluate` memakai `lab_manifest.csv`.

## Catatan metode

Jendela dimulai dari timestamp paket pertama per PCAP, panjang default 5 detik; jendela kosong tidak dikeluarkan. `frame.len` adalah ukuran frame, SYN dihitung hanya SYN tanpa ACK, DNS query dihitung bila `dns.flags.response=0`, dan laju dibagi durasi nominal jendela. `unique_dst_ports` mencakup TCP/UDP; IP mencakup IPv4/IPv6. Fitur ini tidak melakukan rekonstruksi koneksi atau inspeksi payload terenkripsi.

Baseline rules memakai threshold sederhana dalam `netwatch.py`, hanya sebagai pembanding awal. `unique_dst_ports` menghitung kedua arah paket sehingga mencakup port balasan; `unique_syn_dst_ports` hanya menghitung tujuan SYN awal dan dipakai rules untuk mendeteksi scan. Confidence Laya dan probabilitas review bukan tingkat akurasi empiris. Jendela dari satu PCAP saling berkaitan; angka dari sedikit capture bukan estimasi kinerja umum. Untuk klaim performa, butuh lebih banyak PCAP independen dan label yang diperiksa manual.

Cek kode tanpa TShark dan model: `py -3.11 -m unittest discover -s tests -v`.
