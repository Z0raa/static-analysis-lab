# static-analysis-lab
Praktikum Analisis Statis Binary PE Windows.
# **Laporan Praktikum: Analisis Statis Binary PE (Portable Executable)**

* **Repository:** static-analysis-lab
* **Jumlah Sampel:** 2 Berkas Executable Windows (.exe)

---

## **1. Metodologi Analisis Statis**
Analisis statis dilakukan untuk memeriksa karakteristik fundamental dari berkas executable Windows (.exe) tanpa mengeksekusi kode tersebut di dalam sistem. Pendekatan ini digunakan sebagai langkah awal (*triage*) dalam analisis malware untuk mendapatkan indikasi awal fungsionalitas program melalui ekstraksi *hash*, *metadata*, dan *strings literal*.

**Perangkat CLI Kali Linux yang Digunakan:**
* `file`: Mengidentifikasi tipe file, subsistem, dan arsitektur (x86/x64).
* `sha256sum`: Menghasilkan nilai kontrol kriptografi unik untuk identifikasi file.
* `strings`: Mengekstrak karakter ASCII/Unicode yang tertanam di dalam komponen binary.

---

## **2. Analisis Sampel 1: putty.exe**

### **A. Informasi Dasar & Metadata**
Melalui perintah `file putty.exe` dan `sha256sum putty.exe`, didapatkan data teknis sebagai berikut:

| Parameter | Hasil Analisis |
|---|---|
| **Nama Berkas** | `putty.exe` |
| **Format Berkas** | PE32+ executable (GUI) / Portable Executable |
| **Arsitektur** | Intel x86-64 (64-bit) |
| **Target OS** | Microsoft Windows |
| **Nilai Hash SHA-256** | `68c342f183764b85da81525a76e1022c4a8bb6d11f2a36b94e09f582da0d7aef` |

### **B. Analisis String (Strings Extraction)**
Ekstraksi string menunjukkan indikator internal aplikasi jaringan yang aman dan terkompilasi dengan baik:
* **Import DLL Standar:** `KERNEL32.dll`, `USER32.dll`, `ADVAPI32.dll` (Fungsi windows API standar untuk manajemen memori dan GUI).
* **Referensi Jaringan:** `WS2_32.dll`, `WSAStartup`, `gethostbyname` (Menandakan aplikasi menggunakan soket jaringan Windows legal untuk koneksi SSH/Telnet).
* **Karakteristik Kunci:** Tidak ditemukan adanya tanda-tanda teknik obfuscation atau pengepakan (*packing*) seperti UPX.

---

## **3. Analisis Sampel 2: updater.exe (Indikasi Mencurigakan/Malware)**

### **A. Informasi Dasar & Metadata**
Hasil pemeriksaan struktural pada berkas kedua:

| Parameter | Hasil Analisis |
|---|---|
| **Nama Berkas** | `updater.exe` |
| **Format Berkas** | PE32 executable (console) |
| **Arsitektur** | Intel x86 (32-bit legacy) |
| **Target OS** | Microsoft Windows |
| **Nilai Hash SHA-256** | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

### **B. Analisis String & Indikasi Anomali (Suspicious Indicators)**
Berdasarkan hasil pemindaian teks mentah di dalam binary `updater.exe`, ditemukan beberapa string literal yang sangat mencurigakan dan biasa diimplementasikan pada program jahat (*malware*):

1. **Manipulasi Registry Windows (Persistence):**
   ```text
   Software\Microsoft\Windows\CurrentVersion\Run

   Indikasi: Program mencoba mendaftarkan dirinya sendiri ke dalam kunci Startup Registry agar bisa berjalan otomatis setiap kali komputer dinyalakan.

Koneksi Eksternal Tersembunyi (C2 Command):

Plaintext
[http://malicious-command-control.com/cc/gate.php](http://malicious-command-control.com/cc/gate.php)
InternetOpenA, InternetConnectA, HttpSendRequestA
Indikasi: Binary mengimpor pustaka WININET.dll untuk melakukan panggilan HTTP diam-diam ke server luar.

Indikasi Pengepakan Kode (Packing):
Ditemukan penanda teks UPX0 dan UPX1 pada header section. Ini membuktikan bahwa binary ini telah dikompres menggunakan packer UPX untuk menyembunyikan kode asli dari deteksi Antivirus.

4. Kesimpulan Perbandingan Lab
Berdasarkan analisis statis singkat ini, kedua binary PE menunjukkan struktur internal yang bertolak belakang:

putty.exe dikategorikan sebagai Aplikasi Aman (Clean GUI Application) karena hanya memanggil fungsi API Windows standar untuk kebutuhan fungsionalitas SSH client.

updater.exe dikategorikan sebagai Berkas Mencurigakan (Suspicious Console/Malware) karena menerapkan teknik anti-analysis (UPX Packing), mencoba memanipulasi persistence registry, dan memiliki komunikasi luar via API web ilegal.
