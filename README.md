# Windows Event Log

Windows Event Log kayıtlarını toplayıp **gömülü SQLite**’ta saklayan ve canlı dashboard üzerinden izlemenizi sağlayan sistem.

## Mimari

```
Windows Event Logs          Collector              SQLite              FastAPI + Dashboard
(System / App / Security) → collector.py      →   data/events.db  →   main.py + static/
                            (her 5 sn)                                 REST + WebSocket
```

| Bileşen | Dosya | Görev |
|---------|--------|--------|
| Veritabanı | `database.py`, `schema_sqlite.sql` | Gömülü SQLite (`data/events.db`) |
| Toplayıcı | `collector.py` | Event Log okur, DB’ye yazar |
| API | `main.py` | REST + WebSocket |
| Arayüz | `static/index.html` | Canlı dashboard |
| Launcher | `launcher.py` | Tek tıkla hepsini başlatır |

## Özellikler

- System, Application, Security loglarını izleme
- Tam event içeriği: zaman, seviye, kategori, kaynak, Event ID, hata kodu, açıklama, mesaj, raw XML
- Filtreleme: seviye, log türü, zaman aralığı, arama, hata kodu, kaynak
- Özet kartları, grafikler, WebSocket canlı güncelleme
- Bugün vs dün karşılaştırması
- Docker **gerekmez**

## Gereksinimler

- Windows 10/11
- Python 3.11+ (yalnızca geliştirme / paket üretimi)
- Security log için Yönetici yetkisi

## Farklı PC’ye kurulum (exe / setup)

### 1) Bu PC’de paketi üret

```powershell
cd "Windows Event Log"
.\build.ps1
```

Çıktılar:
- **Portable:** `dist\WindowsEventLog\` (zip/USB ile taşı)
- **Setup.exe:** Inno Setup kuruluysa `dist\WindowsEventLog-Setup.exe`

### 2) Hedef PC’de

1. `WindowsEventLog.exe` çalıştır (veya Setup ile kur)
2. Tarayıcı: http://127.0.0.1:8000
3. Security için exe’yi **Yönetici olarak çalıştır**

Ayarlar: `config.ini` (port, DB yolu). Veriler: `data\events.db`

## Geliştirme

```powershell
cd "Windows Event Log"
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python launcher.py
```

Veya ayrı ayrı:

```powershell
python -m uvicorn main:app --host 127.0.0.1 --port 8000
python collector.py
```

## config.ini

```ini
[database]
path = data/events.db

[app]
host = 127.0.0.1
port = 8000
open_browser = true
```

## API özeti

| Endpoint | Açıklama |
|----------|----------|
| `GET /events` | Filtreli event listesi |
| `GET /events/{id}` | Event detayı (XML dahil) |
| `GET /stats/summary` | Özet istatistikler |
| `GET /stats/timeline` | Zaman dağılımı |
| `GET /stats/by-source` | Kaynak dağılımı |
| `GET /stats/by-log` | Log / kategori dağılımı |
| `GET /stats/top-events` | En sık event’ler |
| `GET /stats/day-comparison` | Bugün vs dün |
| `GET /stats/compare` | Karşılaştırma detayı |
| `GET /system-info` | Host / IP / MAC |
| `WS /ws/live` | Canlı event push |

## Bilinen notlar

- `Security` logu için collector / exe **Yönetici** olarak çalışmalı
- System / Application için admin gerekmez
- Eski Postgres/Docker dosyaları (`docker-compose.yml`, `init.sql`, `migrate.sql`) artık kullanılmaz; silinebilir
