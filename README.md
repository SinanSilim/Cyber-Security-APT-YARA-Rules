# Cyber-Security-APT-YARA-Rules
# 🔐 Proje Adı
Kısa ve net açıklama: Projenin ne yaptığı, hangi problemi çözdüğü (1-2 cümle).

![License](https://img.shields.io/badge/license-MIT-blue.svg)

---

## 📌 Özellikler
- 🚀 Hızlı kurulum ve kullanım
- 🔍 Amaca özel güvenlik analizi
- 🛡️ Otomatik tespit ve raporlama
- ⚙️ Modüler yapı ile kolay geliştirme

---

## 📂 Proje Yapısı

## Kısaca kullanım:

JSON/YAML/CSV formatında IoC’leri ver → script tek tek ailelere ait YARA kuralları üretir.

Örnek şablon için:
python apt_yara_gen.py --example apt_iocs.json

Kural üretmek için:
python apt_yara_gen.py --in apt_iocs.json --out APT.yar --author "Sinan Silim" --min-strings 2 --rule-prefix APT --version 1.0
