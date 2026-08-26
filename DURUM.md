# Durum Günlüğü

> En üstteki kayıt en güncelidir. Her çalışma sonrası buraya kısa bir not düşülür.

---

## 2026-08-21 — CI gating için `--fail-below` eklendi

- Konu: `--fail-below {A..F}` bayrağı eklendi — sonuç grade eşiğin altındaysa çıkış kodu 1 (regresyon kontrolü: bir deploy bir header'ı sessizce düşürürse CI kırılır). Ağ isteği başarısız olursa zaten 1 dönüyordu, o davranış korunuyor.
- 4 yeni test eklendi (7 → 11), `requests.get` monkeypatch'lenerek `main()` uçtan uca test edildi. Ruff temiz.
- Durum: ✅ Henüz push edilmedi.

**Sıradaki iş:** GitHub'da `Web-Security-Header-Scanner` adıyla repo aç, git init + push.

---

## 2026-08-20 — Paketleme, JSON çıktı ve lint eklendi
- Konu: `pyproject.toml` ile pip kurulabilir hale getirildi (`pip install -e .` → `web-security-header-scanner` komutu), `--format json` eklendi, ruff lint + CI'da ayrı lint job'u eklendi.
- Durum: ✅ 7/7 test geçiyor (2 yeni JSON testi dahil), ruff temiz, `pip install -e .` ile kurulum ve `--format json` gerçek bir çalıştırmayla (github.com'a karşı) doğrulandı, sonra kaldırıldı.

**Sıradaki iş:** GitHub'da `Web-Security-Header-Scanner` adıyla repo aç, git init + push.

---

## 2026-08-20 — Test suite ve CI eklendi
- Konu: Header değerlendirme mantığı (`evaluate`/`build_report`) zaten network çağrısından ayrı, saf fonksiyonlardı — refactor gerekmedi. `tests/` altına 5 testlik tamamen offline bir pytest paketi ve `.github/workflows/ci.yml` ile GitHub Actions CI eklendi. README'ye CI/Python/License badge'leri ve `## Testing` bölümü eklendi.
- Durum: ✅ 5/5 test geçti (`pytest -v`). CLI sanity-check ile `--url https://github.com` hâlâ eskisi gibi çalışıyor (5/6, B).

**Sıradaki iş:** GitHub'da `Web-Security-Header-Scanner` adıyla repo aç, git init + push (CI ilk push'ta otomatik tetiklenecek).

## 2026-08-20 — Proje oluşturuldu ve gerçek çalıştırmayla doğrulandı

- Konu: HTTP güvenlik header'larını (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy) denetleyip puanlayan Python CLI aracı.
- Dosya: `web_security_header_scanner.py`
- Durum: ✅ Çalışıyor. `https://github.com` adresine karşı gerçek çalıştırıldı (bu ortamda internet erişimi vardı), sonuç 5/6 (B) — `Permissions-Policy` eksik çıktı. Çıktı `sample_report.md` içinde.
- Not: Uzun header değerleri (ör. CSP) rapor tablosunda okunabilirlik için 100 karaktere kısaltılıyor.

**Sıradaki iş:** GitHub'da `Web-Security-Header-Scanner` adıyla repo aç, `git init` + ilk commit + push.
