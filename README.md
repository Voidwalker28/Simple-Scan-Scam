# Simple Scam/Gambling Link Scanner

Proyek sederhana ini adalah pemindai tautan *scam* dan *judi online* yang ditulis dalam Python.

Ia bekerja dengan tiga cara:
1.  **Pemblokiran Kata Kunci/Domain**: Memindai URL terhadap daftar kata kunci perjudian dan akhiran domain yang mencurigakan (Prioritas tertinggi).
2.  **WHOIS Lookup**: Memeriksa usia dan pendaftar domain (Domain yang baru lahir seringkali mencurigakan).
3.  **Google Safe Browsing**: Memeriksa URL terhadap basis data *malware* dan *phishing* dari Google.

## ⚠️ Peringatan Penting
Hasil yang diberikan **BUKAN JAMINAN 100%** keamanan. Selalu gunakan pertimbangan terbaik Anda.

## Persyaratan
-   Python 3.x
-   Kunci API **Google Safe Browsing** (Anda bisa mendapatkannya dari Google Cloud Console)

## Instalasi

1.  **Kloning Repositori:**
    ```bash
    git clone https://github.com/Voidwalker28/Simple-Scan-Scam.git
    cd Simple-Scan-Scam
    ```

2.  **Instal Dependensi:**
    ```bash
    pip install -r requirements.txt
    ```
    Install manual :
    requests
    python-whois
    tld

4.  **Konfigurasi API Key:**
    Buka file `scam_scanner.py` dan ganti `YOUR_GOOGLE_API_KEY` pada baris yang sesuai dengan kunci API Anda.

## Cara Penggunaan

Jalankan skrip dari terminal dengan memberikan URL sebagai argumen:

```bash
python scam_scanner.py [https://www.google.com]
