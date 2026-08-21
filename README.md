# Windows Event Log

Windows Event Log kayıtlarını toplayıp PostgreSQL’de saklayan ve canlı bir dashboard üzerinden izlemenizi sağlayan sistem.

## Mimari

```
Windows Event Logs          Collector              PostgreSQL           FastAPI + Dashboard
(System / App / Security) → collector.py      →   event_monitor    →   main.py + static/
                            (her 5 sn)              (Docker)            REST + WebSocket
```

| Bileşen | Dosya | Görev |
|---------|--------|--------|
| Veritabanı | `docker-compose.yml`, `init.sql` | Postgres 16, `events` tablosu |
| Toplayıcı | `collector.py` | Event Log okur, DB’ye yazar |
| API | `main.py`, `database.py` | REST + WebSocket |
| Arayüz | `static/index.html` | Canlı dashboard |

## Özellikler

- System, Application, Security loglarını izleme
- Tam event içeriği: zaman, seviye, kategori, kaynak, Event ID, hata kodu, açıklama, mesaj, raw XML
- Filtreleme: seviye, log türü, zaman aralığı, arama, hata kodu, kaynak
- Özet kartları (tıklanabilir filtre / karşılaştırma)
- Grafikler: zaman çizelgesi, seviye, top event, log dağılımı
- WebSocket ile gerçek zamanlı güncelleme
- Bugün vs dün karşılaştırması

## Gereksinimler

- Windows 10/11
- Python 3.11+
- Docker Desktop
- Security log için Yönetici yetkisi

## Kurulum

```powershell
cd "Windows Event Log"
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Başlatma

Sıra: **1) DB → 2) API → 3) Collector**

### 1. PostgreSQL

```powershell
docker compose up -d
```

İlk kurulumda `init.sql` otomatik uygulanır.  
Mevcut bir volume varsa şema güncellemesi için:

```powershell
Get-Content -Raw .\migrate.sql | docker exec -i event_monitor_db psql -U event_admin -d event_monitor
```

### 2. API / Dashboard

```powershell
.\venv\Scripts\Activate.ps1
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Dashboard: http://localhost:8000

### 3. Collector

**Ayrı bir terminalde** (Security için Yönetici olarak):

```powershell
.\venv\Scripts\Activate.ps1
python collector.py
```

Collector kapalıyken yeni event’ler DB’ye yazılmaz. Yeniden açılınca DB’deki son kayıttan devam eder.

## Veritabanı ayarları

Varsayılan değerler (`docker-compose.yml`, `collector.py`, `database.py` ile aynı olmalı):

| Alan | Değer |
|------|--------|
| Host | `localhost` |
| Port | `5432` |
| DB | `event_monitor` |
| User | `event_admin` |
| Password | `change_this_password` |

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

## Dashboard kullanımı

- Üstteki kartlara tıklayınca ilgili filtre veya karşılaştırma uygulanır
- Grafik dilimlerine / barlarına tıklayınca filtre uygulanır
- Aktif filtre çubuğundan **Temizle** ile sıfırlanır
- Header’da **canlı** yazıyorsa WebSocket bağlıdır
- Satıra tıklayınca detay modalı açılır (açıklama, mesaj, XML)

## Bilinen notlar

- `Security` logu için collector **Yönetici** olarak çalışmalı; aksi halde `Erişim engellendi` hatası alınır
- System / Application için admin gerekmez
- Üretimde `change_this_password` değerini mutlaka değiştirin
- CORS şu an açıktır (`allow_origins=["*"]`); kurumsal ortamda kısıtlayın

## Bağımlılıklar

```
pywin32
psycopg2-binary
python-dotenv
fastapi
uvicorn[standard]
```

`requirements.txt` dosyasından yüklenir.
