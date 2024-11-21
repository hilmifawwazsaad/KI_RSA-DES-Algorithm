# KI_RSA-DES-Algorithm
Program for DES algorithm using Python Information Security class

### Nama Anggota Kelompok
| Nama  | NRP |
| ------------- | ------------- |
| Amanda Illona Farrel  | 5025221056  |
| Hilmi Fawwaz Sa'ad  | 5025221103  |

### Pembagian Kerja
#### Amanda Illona Farrel
1. Membuat algoritma DES
2. Membuat socket
3. Cleaning code
4. Fix issue encrpyt

#### Hilmi Fawwaz Sa'ad
1. Membuat repo
2. Membuat logika RSA
3. Membuat server PKA (Public Key Authority)
4. Fix issue decrypt

### How to Run
1. Buka 3 terminal
2. Jalankan `python .\server.py` di terminal pertama
3. Jalankan `python .\clientA.py` di terminal kedua
4. Jalankan `python .\clientB.py` di terminal ketiga
5. Enter message apapun dari clientA di terminal kedua, kemudian pesan encrypt akan dikirimkan ke clientB
    - Di terminal ketiga, clientB akan menerima pesan dari clientA berupa
    - Hasil dekripsi dalam biner
    - Ciphertext yang diterima
    - Plaintext yang diterima
6. Dari clientB, Enter message apapun untuk balasan pesan clientA di terminal ketiga, kemudian pesan encrypt akan dikirimkan ke clientA
