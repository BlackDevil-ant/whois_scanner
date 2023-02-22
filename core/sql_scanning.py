import requests
import re

# Fungsi untuk melakukan request dan mendapatkan response


def get_response(url):
    response = requests.get(url)
    return response.text

# Fungsi untuk melakukan scanning SQL injection dengan payload tertentu


def scan_sql_injection(url, payload):
    # Melakukan request ke URL dengan payload yang ditambahkan
    response = get_response(url + payload)

    # Mencari pola dari response yang menandakan adanya SQL injection
    pattern = re.compile(
        r"SQL syntax|mysql_fetch|mysqli_fetch|mysql_num_rows|pg_query|pg_exec|mysql_result")
    match = pattern.search(response)

    # Jika ditemukan pola, maka SQL injection terdeteksi
    if match:
        print("SQL injection ditemukan di URL: ", url)


# Input URL dan payload
url = input("Masukkan URL: ")
payload = input("Masukkan payload: ")

# Memanggil fungsi scan_sql_injection dengan input URL dan payload
scan_sql_injection(url, payload)
