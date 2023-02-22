# whois_scanner
Program ini adalah program untuk melakukan analisis terhadap sebuah domain, melakukan scanning terhadap subdomain, mengetahui informasi tentang sebuah domain, dan memeriksa adanya celah SQL injection. Program ini menggunakan library yang telah tersedia pada python seperti requests, socket, whois, os, subprocess, dan re.

![gambar](https://user-images.githubusercontent.com/124701434/220729490-cede1bdd-02ba-4f8f-ae5a-896e4ce2e208.png)

output
![gambar](https://user-images.githubusercontent.com/124701434/220733696-374c6139-dd96-4f04-be0a-34f809c19770.png)

    Library yang digunakan pada program ini antara lain:

    requests: digunakan untuk mengirimkan permintaan HTTP dan menerima respons dari server.
    socket: digunakan untuk memetakan nama domain ke alamat IP dan sebaliknya.
    whois: digunakan untuk memperoleh informasi tentang nama domain seperti registrar, tanggal pembuatan, tanggal kadaluarsa, dan status.
    os: digunakan untuk memberikan interaksi dengan sistem operasi dalam hal ini untuk menjalankan Nikto.
    subprocess: digunakan untuk menjalankan proses shell dan menangani keluaran dan masukan.

    Nikto adalah tool scanner keamanan web yang open source. Beberapa fitur Nikto antara lain:

    Mampu mendeteksi kerentanan, server dan platform yang sudah usang.
    Mampu memindai seluruh situs atau situs yang telah ditentukan sebelumnya.
    Dapat melakukan pengujian SSL server untuk mengidentifikasi kerentanan SSL dan memberikan masukan pada file konfigurasi SSL.
    Mampu melakukan pengujian server proxy.
    Dapat melakukan audit otomatis untuk direktori dan file yang terlindungi secara default.
    Dapat melakukan pengujian otomatis untuk kerentanan terkait web dan protokol server.
    Mampu mendeteksi backdoors dan file hidden secara otomatis.

