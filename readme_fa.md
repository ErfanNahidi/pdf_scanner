# اسکنر تهدیدات PDF

![نسخه](https://img.shields.io/badge/Version-4.0.0-5865F2)
![پلتفرم](https://img.shields.io/badge/Platform-Windows%20%7C%20%20%20Linux-blue)
![لایسنس: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

یک نرم‌افزار مدرن و چندسکویی برای بررسی فایل‌های PDF از نظر تهدیدات امنیتی. این برنامه با استفاده از Python و PySide6 ساخته شده و رابط کاربری ساده و شیکی دارد که به شما کمک می‌کند قبل از باز کردن فایل‌های مشکوک، تهدیدات امنیتی را شناسایی کنید — مانند جاوااسکریپت‌های پنهان، اجرای خودکار، و لینک‌های خارجی.

ساخته‌شده توسط **عرفان ناهیدی**.

> 🔗 [See the English version of the README here](https://github.com/ErfanNahidi/pdf_scanner/blob/main/readme.md)
--
---

## ویژگی‌ها

* **تحلیل دقیق تهدیدات:** بررسی کلیدواژه‌های مشکوک مانند `/JS`، `/JavaScript`، `/OpenAction`، `/Launch`، `/EmbeddedFile` با استفاده از `pdfid.py`
* **رابط گرافیکی مدرن:** ساخته‌شده با PySide6
* **حالت شب و روز:** قابلیت سوییچ بین تم‌های تاریک و روشن
* **کشیدن و رها کردن:** اسکن آسان چند فایل با درگ‌کردن در پنجره
* **اسکن چندرشته‌ای:** رابط کاربری حتی هنگام اسکن سریع و روان باقی می‌ماند
* **طبقه‌بندی تهدیدات:** از Safe تا Critical با آیکون‌های مشخص
* **پیشنهادهای امنیتی عملی:** ارائه توصیه‌هایی برای هر تهدید شناسایی‌شده
* **چندسکویی:** اجرا روی ویندوز، مک و لینوکس

---

## دانلود و نصب (برای کاربران)

آخرین نسخه را از [صفحه Releases گیت‌هاب](https://github.com/ErfanNahidi/pdf_scanner/releases) دانلود کنید:

* **ویندوز:** فایل `.exe`
* **مک:** فایل `.dmg`
* **لینوکس:** فایل `.AppImage` یا `.deb`

---

## نصب و راه‌اندازی (برای توسعه‌دهندگان)

### ۱. دریافت سورس

```bash
git clone https://github.com/ErfanNahidi/pdf_scanner.git
cd pdf_scanner
```

### ۲. نصب پیش‌نیازها

نیازمند Python 3.9+ و PySide6 هست. پیشنهاد می‌شود از virtual environment استفاده کنید:

```bash
python -m venv venv
source venv/bin/activate  # در ویندوز: venv\Scripts\activate

pip install PySide6
```

### ۳. افزودن `pdfid.py`

اسکریپت `pdfid.py` را از وب‌سایت رسمی Didier Stevens دانلود کرده و در پوشه اصلی پروژه قرار دهید:

* [PDF Tools - Didier Stevens](https://blog.didierstevens.com/programs/pdf-tools/)

---

## نحوه استفاده

اجرای برنامه:

```bash
python gui.py
```

* فایل‌های PDF را به داخل پنجره بکشید
* یا روی **"انتخاب فایل"** کلیک کنید
* اسکن به‌صورت خودکار انجام می‌شود
* برای دیدن جزئیات کامل روی گزینه **"▼ نمایش کامل گزارش"** کلیک کنید

---

## ساختار پروژه

```
/
├── backend.py      # منطق تحلیل تهدیدات
├── gui.py          # رابط کاربری PySide6
├── pdfid.py        # ابزار تحلیل PDF (باید دستی اضافه شود)
└── README.md       # فایل توضیحات پروژه
```

---

## مجوز

این پروژه تحت لایسنس MIT منتشر شده است.
