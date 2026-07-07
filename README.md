# AES-128 Simulator

Web simulasi algoritma Advanced Encryption Standard (AES-128).

## Struktur Project

```
aes-app/
├── index.html   ← tampilan utama
├── style.css    ← semua styling
├── aes.js       ← implementasi algoritma AES-128
└── app.js       ← logika UI dan rendering
```

## Fitur

- Enkripsi & Dekripsi AES-128
- Input: hex 32 karakter atau teks biasa (maks 16 karakter)
- Kunci: 32 karakter hex (128-bit)
- Visualisasi State Matrix 4×4 setiap tahap
- Semua 10 round ditampilkan (SubBytes, ShiftRows, MixColumns, AddRoundKey)
- Key Expansion W[0]–W[43] dengan detail RK0–RK10
- Toggle show/hide setiap section

## Cara Menjalankan

Buka `index.html` di browser — tidak perlu server/backend, semua berjalan di sisi klien.

## Test Vector (NIST Standard)

- Plaintext: `00112233445566778899aabbccddeeff`
- Key:       `000102030405060708090a0b0c0d0e0f`
- Ciphertext: `69c4e0d86a7b0430d8cdb78070b4c55a`

## Referensi

- NIST FIPS Publication 197 — Advanced Encryption Standard
- Stallings, W. (2017). Cryptography and Network Security (7th ed.)
