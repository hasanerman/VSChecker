# VSChecker

[English](#english) | [Türkçe](#türkçe)

---

## English

A clean and lightweight local antivirus application written in Python. It features a modern, asynchronous graphical user interface built with CustomTkinter, a rule-based scan engine, a safe quarantine manager, and structured scan history log tracking using SQLite. All interface labels, diagnostics, and outputs are fully presented in English under the name **VSChecker**.

### Advanced Features
- **Heuristic Entropy Analysis**: Evaluates the Shannon Entropy of executable files. If a binary has an entropy score above `7.5`, it is flagged as `Suspicious file (High entropy)` due to potential packing, obfuscation, or encryption (common in ransomware and malware loaders).
- **VirusTotal Cloud Integration**: Perform checks on file hashes using the official VirusTotal API. Simply input your API key in the settings tab, right-click any item in the scan results list, and select **VirusTotal Check** to check detection rates instantly.
- **Dynamic Theme Switcher**: Toggle the interface appearance dynamically between **Dark**, **Light**, and **System** themes via the Settings & Statistics panel.
- **Local Persistence**: Automatically saves and loads your configurations (such as the VirusTotal API Key) in a local `config.json` file under `~/VSChecker/`.
- **File Scanning**: Scan individual files for malware hashes or suspicious properties.
- **Folder Scanning**: Recursively list and scan directories, with responsive progress tracking.
- **Quick Scan**: Rapidly scan common user directories (Desktop, Downloads) and driver folders.
- **Full Scan**: Scan entire system drives.
- **Process Scan**: List active system processes, checking for CPU/RAM usage spikes and suspicious process names.
- **Quarantine Manager**: Safely isolate threat files with cross-device support (using `shutil.move`) and store metadata in separate `.info` descriptors under `~/VSChecker/Quarantine/`. Easily restore files to their original directories or delete them permanently.
- **Scan History & Stats**: Persist results in a local SQLite database (`database.db` under `~/VSChecker/`), update user actions (e.g., Quarantined, Deleted), and view comprehensive scan statistics.
- **Safe Multithreading**: Prevents GUI freezing by performing heavy folder crawls and file analysis in a separate worker thread.
- **Responsive Design**: Scan buttons dynamically disable and enable, progress bars track progress, and results are visually color-coded (red for threats, green for clean, orange for quarantined).
- **Interactive Sorting**: Click any column header in the results or history trees to sort entries alphabetically or numerically.

---

### Architecture
1. **`VirusEngine`**: Handles hash checks (MD5 signatures), file path validation, Shannon Entropy computation, and read permission checks (`os.access(..., os.R_OK)`). Includes naming pattern filters and heuristics for file sizes and extensions.
2. **`QuarantineManager`**: Relocates threats securely to the `~/VSChecker/Quarantine` folder. Employs cross-drive move utilities and automatically recreates target directories when restoring.
3. **`DatabaseManager`**: Standard SQL storage for tracking past scans and updating logs when users choose to quarantine or delete items.
4. **`AntivirusGUI`**: Orchestrates thread creation, schedules UI updates on the main thread via event queues (`after()`), handles column sorting, and configures Treeview item styling tags.

---

### Installation & Run

#### Prerequisites
Ensure you have Python 3.x installed.

#### 1. Install Dependencies
Install the required packages using `pip`:
```bash
pip install customtkinter psutil
```

#### 2. Run the Application
Run the script with administrator privileges to ensure the scan engine has permissions to read system files and process trees:
```bash
python vs_checker.py
```

---

### Future Roadmap
- **Real-Time Protection**: Implement filesystem monitoring using the `watchdog` library to auto-scan newly created or modified files in real-time.
- **Advanced Heuristics**: Parse PE headers of Windows executables using `pefile` to analyze entropy, identify packer patterns, and check import table anomalies.
- **Zamanlanmış Taramalar (Scheduled Scans)**: Integrate with OS schedulers (such as Windows Task Scheduler) or build an automated daemon.
- **USB Shield**: Auto-detect inserted storage media and run instant quick scans on mount.

---

## Türkçe

Python ile geliştirilmiş temiz ve hafif bir yerel antivirüs uygulaması. CustomTkinter ile tasarlanmış modern ve asenkron grafik arayüz, kural tabanlı tarama motoru, güvenli karantina yöneticisi ve SQLite kullanan yapılandırılmış tarama geçmişi kaydı sunar. Tüm arayüz etiketleri ve çıktılar tamamen İngilizce olarak **VSChecker** ismi altında sunulmaktadır.

### Gelişmiş Özellikler
- **Hevristik Entropi Analizi**: Çalıştırılabilir dosyaların Shannon Entropisini hesaplar. Eğer bir dosya `7.5` değerinden yüksek bir entropiye sahipse, şifrelenmiş, paketlenmiş (packed) veya gizlenmiş olma ihtimaline karşı (zararlı yazılımlarda yaygındır) `Suspicious file (High entropy)` şeklinde işaretlenir.
- **VirusTotal Bulut Entegrasyonu**: Dosya hash değerlerini resmi VirusTotal API'si üzerinden kontrol edin. API anahtarınızı ayarlar sekmesine girdikten sonra, tarama sonuçlarında bir dosyaya sağ tıklayıp **VirusTotal Check** seçeneğini seçerek tespit oranlarını anında sorgulayabilirsiniz.
- **Dinamik Tema Seçici**: Arayüz görünümünü Ayarlar panelinden anlık olarak **Dark**, **Light** veya **System** temaları arasında değiştirebilirsiniz.
- **Yerel Ayar Kaydı**: Ayarlarınızı (VirusTotal API Key gibi) `config.json` dosyasına otomatik olarak kaydeder ve sonraki açılışlarda geri yükler.
- **Dosya Tarama**: Seçilen dosyaları bilinen zararlı hash imzaları veya şüpheli nitelikler açısından kontrol eder.
- **Klasör Tarama**: Dizinleri özyinelemeli olarak listeler ve arayüz donmadan hızlıca tarar.
- **Hızlı Tarama**: Sık kullanılan kullanıcı klasörlerini (Masaüstü, İndirilenler) ve sürücü dizinlerini hızlıca tarar.
- **Tam Tarama**: Tüm sistem sürücülerini ve kullanıcı dizinlerini tarar.
- **Süreç Tarama**: Çalışan sistem süreçlerini tarayıp CPU/RAM kullanımlarını ve şüpheli isimleri listeler.
- **Karantina Yöneticisi**: Sürücüler arası dosya taşıma desteğiyle (`shutil.move`) tehditleri `~/VSChecker/Quarantine` klasörüne taşır ve metadata dosyaları oluşturur. Dosyaları güvenle geri yükleyebilir veya kalıcı olarak silebilirsiniz.
- **Tarama Geçmişi ve İstatistikler**: Tarama sonuçlarını yerel SQLite veritabanına (`database.db`) kaydeder. Kullanıcı eylemlerini (Karantina, Silindi) veritabanında günceller.
- **Güvenli Çoklu İş Parçacığı (Multithreading)**: Klasör tarama ve dosya analizi işlemlerini arka planda çalıştırarak GUI arayüzünün kilitlenmesini engeller.
- **Dinamik Butonlar ve Arayüz**: Tarama sırasında butonlar devre dışı bırakılır, ilerleme durumu anlık güncellenir ve sonuçlar renk kodlarıyla (tehditler kırmızı, temizler yeşil, karantinaya alınanlar turuncu) listelenir.
- **Etkileşimli Sıralama**: Sonuçlar veya geçmiş listesindeki herhangi bir sütun başlığına tıklayarak verileri alfabetik veya nümerik olarak sıralayabilirsiniz.

---

### Mimari
1. **`VirusEngine`**: MD5 imza kontrollerini, dosya yolu doğrulamalarını, Shannon Entropi hesaplamalarını ve okuma izni denetimlerini (`os.access(..., os.R_OK)`) yönetir.
2. **`QuarantineManager`**: Tehdit dosyalarını güvenle taşır. Dosya geri yüklenirken özgün klasör yolu silinmişse hedef dizinleri otomatik olarak yeniden oluşturur.
3. **`DatabaseManager`**: Tarama geçmişini SQLite üzerinde tutar ve karantina/silme işlemlerinde ilgili kaydı günceller.
4. **`AntivirusGUI`**: Arka plan iş parçacıklarını yönetir, GUI güncellemelerini ana iş parçacığı döngüsüne (`after()`) yönlendirir ve Treeview renk etiketlerini atar.

---

### Kurulum ve Çalıştırma

#### Gereksinimler
Sisteminizde Python 3.x olduğundan emin olun.

#### 1. Kütüphaneleri Yükleyin
Gerekli kütüphaneleri `pip` ile yükleyin:
```bash
pip install customtkinter psutil
```

#### 2. Uygulamayı Başlatın
Sistem dosyalarına ve süreç listesine tam erişim sağlamak için programı yönetici haklarıyla başlatın:
```bash
python vs_checker.py
```

---

### Gelecek Yol Haritası
- **Gerçek Zamanlı Koruma**: `watchdog` kütüphanesi entegrasyonu ile dosya sistemi olaylarını (yeni oluşturma/değişiklik) anlık olarak izleyip arka planda otomatik tarama.
- **Gelişmiş Sezgisel (Heuristic) Analiz**: Windows çalıştırılabilir dosyalarının PE başlıklarını `pefile` ile okuyarak entropi analizi yapma, sıkıştırıcı tespiti ve şüpheli kütüphane çağrısı kontrolü.
- **Zamanlanmış Taramalar**: Windows Görev Zamanlayıcı veya arka planda çalışan bir servis aracılığıyla otomatik zamanlı tarama.
- **USB Koruması**: Bilgisayara takılan harici depolama birimlerini otomatik algılayıp tarama başlatma.
