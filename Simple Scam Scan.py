import requests
import argparse
import whois
from urllib.parse import urlparse
from tld import get_fld, TldDomainNotFound
from datetime import datetime, date

# --- INFORMASI AUTHOR & TOOLS ---
AUTHOR = "Void Walker IDN"
INSTAGRAM = "Void Walker IDN"
VERSION = "1.2"
# --------------------------------

# Daftar Kata Kunci Judi Online (untuk pemblokiran)
GAMBLING_KEYWORDS = [
    "slot", "togel", "casino", "judi", "poker", "taruhan", "bandar",
    "deposit", "jackpot", "gacor", "rtp", "maxwin", "parlay", "bola"
]
# Daftar Domain yang Dikenal (Contoh)
GAMBLING_DOMAIN_SUFFIXES = [
    ".live", ".poker", ".slot", ".bet", ".win", ".fun"
]

# API Key dan URL Google Safe Browsing
# GANTI 'YOUR_GOOGLE_API_KEY' DENGAN KUNCI API ANDA!
GOOGLE_SAFE_BROWSING_API_KEY = "YOUR_GOOGLE_API_KEY"
API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

def check_google_safe_browsing(url):
    """Memeriksa URL menggunakan Google Safe Browsing API."""
    
    payload = {
        "client": {"clientId": "SimpleScamScanner", "clientVersion": VERSION},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(
            f"{API_URL}?key={GOOGLE_SAFE_BROWSING_API_KEY}",
            json=payload,
            timeout=10
        )
        response.raise_for_status()
        data = response.json()
        
        return not bool('matches' in data) # True jika aman (tidak ada matches)

    except requests.exceptions.RequestException as e:
        return None

def check_gambling_keywords(url):
    """Memeriksa URL terhadap kata kunci judi online."""
    url_lower = url.lower()
    parsed = urlparse(url)
    
    # 1. Cek Kata Kunci di URL
    for keyword in GAMBLING_KEYWORDS:
        if keyword in url_lower:
            return f"Kata kunci judi ('{keyword}') terdeteksi di URL."
            
    # 2. Cek Suffix Domain (TLD/Subdomain)
    for suffix in GAMBLING_DOMAIN_SUFFIXES:
        if parsed.netloc.endswith(suffix):
            return f"Akhiran domain mencurigakan ('{suffix}') terdeteksi."
            
    return None

def get_whois_info(url):
    """Mengambil informasi WHOIS dari domain utama."""
    try:
        domain_name = get_fld(url, fix_protocol=True)
    except TldDomainNotFound:
        return {"error": "Domain tidak valid atau TLD tidak dikenal."}

    print(f"\n🔍 WHOIS LOOKUP untuk: {domain_name}")
    try:
        w = whois.whois(domain_name)
        
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        
        age_status = "Tidak Diketahui"
        domain_age_days = None

        if creation_date and isinstance(creation_date, datetime):
            domain_age_days = (date.today() - creation_date.date()).days
            
            age_status = f"{domain_age_days} hari ({domain_age_days // 365} tahun)"
            if domain_age_days < 180:
                age_status += " [!! SANGAT BARU! Waspada Scam]"
            elif domain_age_days < 365:
                age_status += " [! Baru, perlu diverifikasi]"
        elif creation_date:
             age_status = str(creation_date) # Tampilkan tanggal jika tidak bisa dihitung usianya

        return {
            "status": "Ditemukan",
            "Domain": domain_name,
            "Registrar": w.registrar[0] if isinstance(w.registrar, list) else w.registrar,
            "Creation Date": creation_date,
            "Domain Age": age_status,
            "Raw_Age_Days": domain_age_days
        }
    except Exception as e:
        return {"error": f"Gagal mengambil data WHOIS: {e}"}

def main():
    parser = argparse.ArgumentParser(
        description="Pemindai Tautan Scam/Judi Sederhana. Memeriksa URL menggunakan Blacklist, WHOIS, dan Google Safe Browsing API."
    )
    parser.add_argument("url", help="Tautan (URL) yang akan dipindai.")
    args = parser.parse_args()
    
    # --- HEADER TOOLS ---
    print(f"\n====================================")
    print(f"Simple Scam/Gambling Link Scanner - v{VERSION}")
    print(f"Author: {AUTHOR} | IG: @{INSTAGRAM}")
    print(f"====================================")
    
    # 1. Pastikan API Key telah diatur
    if GOOGLE_SAFE_BROWSING_API_KEY == "YOUR_GOOGLE_API_KEY":
        print("\nFATAL ERROR: Harap ganti 'YOUR_GOOGLE_API_KEY' di dalam skrip dengan kunci API Anda yang valid.")
        return

    print(f"\n▶️ MEMULAI SCAN URL: {args.url}")
    print(f"====================================")
    
    # 2. Jalankan Pemeriksaan Judi Online (Prioritas Tinggi)
    gambling_reason = check_gambling_keywords(args.url)
    
    # 3. Jalankan pemeriksaan WHOIS
    whois_result = get_whois_info(args.url)
    
    if "error" in whois_result:
        print(f"   [X] WHOIS Error: {whois_result['error']}")
    else:
        for key, value in whois_result.items():
            if key in ["Domain", "Registrar", "Domain Age"]:
                print(f"   - {key}: {value}")

    # 4. Jalankan pemeriksaan Google Safe Browsing
    is_safe_google = check_google_safe_browsing(args.url)
    
    print("\n------------------------------------")
    print("🚦 HASIL AKHIR PEMINDAIAN KEAMANAN")
    print("------------------------------------")

    # Tampilkan Keterangan Author
    print(f"Tool Dibuat Oleh: {AUTHOR} | Instagram: @{INSTAGRAM}")
    
    # 5. Analisis dan Kesimpulan Akhir
    if gambling_reason:
        print(f"❌ KESIMPULAN: BLOKIR (JUDI ONLINE)!")
        print(f"   - ALASAN BLOKIR: {gambling_reason}")
        print("   🛑 URL INI DIBLOKIR KARENA MENGANDUNG INDIKASI JUDI ONLINE.")
        
    elif is_safe_google is False:
        print(f"🚨 KESIMPULAN: BERBAHAYA (SCAM/MALWARE)!")
        print("   🛑 JANGAN PERNAH KLIK ATAU MASUKKAN INFORMASI PRIBADI.")
        
    elif is_safe_google is True:
        # Cek WHOIS sebagai indikator terakhir
        if "Raw_Age_Days" in whois_result and whois_result["Raw_Age_Days"] is not None and whois_result["Raw_Age_Days"] < 180:
             print(f"⚠️ KESIMPULAN: MENCURIGAKAN!")
             print("   - PERINGATAN: URL bersih, tetapi domain SANGAT BARU. Mohon verifikasi sumbernya.")
        else:
             print("✅ KESIMPULAN: AMAN")
             print("   💡 Catatan: Tidak terdaftar sebagai ancaman. Selalu waspada.")
    else:
        print("⚠️ KESIMPULAN: TIDAK DAPAT DITENTUKAN (Error API/Jaringan).")
        
    print("====================================")
        
if __name__ == "__main__":
    main()
