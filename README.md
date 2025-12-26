# 👁️ BMP Analyzer (BGP Monitoring Platform)

**BMP Analyzer**, Arista EVPN/VXLAN altyapıları için geliştirilmiş; ağ trafiğini analiz eden, izolasyon durumlarını doğrulayan ve olası rota sızıntılarını (Route Leak) tespit eden hafif bir **Gözlem (Observability)** aracıdır.

Karmaşık ticari yazılımlar yerine; **GoBGP** ve **Saf Python** gücüyle çalışır.


## 🚀 Ne İşe Yarar?

Ağ yöneticilerinin şu sorulara saniyeler içinde yanıt vermesini sağlar:
- *"Provider VRF'indeki Sunucu A, Secure VRF'indeki Sunucu B'ye erişebilir mi?"*
- *"Trafik doğrudan VXLAN üzerinden mi akıyor, yoksa Firewall'a mı yönleniyor?"*
- *"İzole olması gereken iki ağ arasında bir Route Leak (Sızıntı) var mı?"*

## 🧠 Çalışma Mantığı

Sistem, GoBGP'den aldığı ham veriyi 3 aşamalı bir analizden geçirir:

```mermaid
graph TD
    User((Kullanici))
    Analyzer[BMP Analyzer]
    Logic{Karar Motoru}
    
    User -- IP Sorgusu --> Analyzer
    Analyzer -- Veriyi Isle --> Logic
    
    Logic -- Rota Yok --> FW["FIREWALL_KONTROLU\n(Default Rota)"]
    
    Logic -- Rota Var & RT Eslesiyor --> Direct["IZINLI_DIRECT\n(EVPN Overlay)"]
    
    Logic -- Rota Var ama RT Yok --> Iso["FIREWALL_KONTROLU\n(Izolasyon)"]
    
    FW --> User
    Direct --> User
    Iso --> User

    style Direct fill:#bfb,stroke:#333
    style FW fill:#fbb,stroke:#333
    style Iso fill:#fbb,stroke:#333
```

1. LPM (Longest Prefix Match): Girilen IP'nin hangi Subnet'e ait olduğunu bulur.
2. RD (Route Distinguisher) Analizi: O Subnet'in hangi VRF'te yaşadığını kesin olarak tespit eder.
3. RT (Route Target) Kontrolü: İki VRF arasında BGP seviyesinde konuşma izni olup olmadığını denetler.

## 🛠️ Kurulum
Bu araç Python Standard Library ile yazılmıştır. Harici bir pip install gerektirmez.

### 1. Depoyu Klonlayın
```
git clone https://github.com/onrmdc/bmp-analyzer.git
cd bmp-analyzer
```
### 2. Veri Kaynaklarını Ayarlayın
Scriptin çalışması için GoBGP sunucunuzda aşağıdaki JSON dosyalarının sunuluyor olması gerekir (Script içindeki DATA_SOURCE_URL değişkenini düzenleyin):
```
gobgp_rib.json: GoBGP EVPN tablosu.
arista_vrf_rules.json: VRF Import/Export kuralları.
```
### 3. Servisi Başlatın
```
nohup python3 -u bmp_server.py &
```

## ⚙️ Konfigürasyon Örnekleri
### Arista Spine (BGP Ayarı)
Spine cihazının VRF bilgisini (Extended Community) GoBGP'ye göndermesi şarttır.

```
router bgp 65001
   neighbor 192.168.100.5 remote-as 65000
   neighbor 192.168.100.5 ebgp-multihop 3
   neighbor 192.168.100.5 send-community extended
```
### GoBGP (Rota Dışa Aktarma)
Rotaları analizöre beslemek için Cronjob ile şu komutu çalıştırın:

```
gobgp global rib -a evpn -j > /var/www/html/gobgp_rib.json
```

## 🔍 Kullanım Örnekleri
Servis ayağa kalktıktan sonra basit bir curl isteği ile analiz yapabilirsiniz.

**Senaryo 1: İzinli Trafik**

```
curl "http://localhost:5000/query?src=10.116.252.10&dst=10.118.38.0/24"
```
Sonuç: IZINLI_DIRECT (Trafik Overlay üzerinden akar).

**Senaryo 2: İzolasyon (Firewall)**
```
curl "http://localhost:5000/query?src=10.116.252.10&dst=10.118.192.11"
```
Sonuç: FIREWALL_KONTROLU (Doğrudan rota yok, trafik Firewall'a gider).
