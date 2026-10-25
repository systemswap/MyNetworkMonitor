# Architektur – MyNetworkMonitor

Wozu: Wer etwas ändern oder austauschen will, findet hier, wo er ansetzen muss und
warum es so gebaut ist. Bei jeder Struktur- oder Technikentscheidung aktualisieren.

MyNetworkMonitor findet Geräte im Netz und zeigt, was auf ihnen läuft: Ping, ARP und
Nachbartabelle, Namensauflösung, Portscan, Erkennung von Diensten (u. a. SSH, Datenbanken,
Fernwartung, SNMP, ONVIF, BACnet, S7, SECS/GEM), Topologie als 3D-Ansicht. Es läuft unter
Linux und Windows; unter Windows zusätzlich als Dienst und als „Satellit“ in einem anderen
Netzsegment (Entwurf und Stand: `SATELLIT.md`).

## Schichten

| Schicht | Ordner/Projekt | Aufgabe | darf benutzen |
|---|---|---|---|
| Oberfläche | `MyNetworkMonitor.Avalonia/Views` | Anzeige, Eingaben (Avalonia, Fluent) | ViewModels, `IDialogService`, `IWebViewHost` |
| Abläufe | `MyNetworkMonitor.Core/ViewModels` | Zustand, Befehle, Filter (CommunityToolkit.Mvvm) | Fachlogik, Dienste |
| Fachlogik | `MyNetworkMonitor.Core/Scanning`, `Model`, `Models`, `Network` | Scanverfahren, Dienst-Sonden, Gerätebestand, Dubletten | nur eigene Typen und die Schnittstellen unten |
| Dienste | `MyNetworkMonitor.Core/Services`, `Persistence`, `SatelliteLink`, `ServiceLink` | Speichern, Export, Topologie-Seiten, Herstellerliste, Verbindung zu Dienst und Satelliten | Fachlogik, fremde Bibliotheken |
| Zugriff aufs System | `MyNetworkMonitor.Platform.Windows`, `MyNetworkMonitor.Avalonia/Platform/Linux` | ARP, Nachbarn, Routen, Firewall, Registry, Dienststeuerung, WLAN, WebView | Betriebssystem |

`MyNetworkMonitor.Core` kennt keine Oberfläche und kein Betriebssystem; es arbeitet nur mit
den Schnittstellen unten. Welche Umsetzung gilt, legt der Programmstart fest
(`MyNetworkMonitor.Avalonia/Program.cs`, `PlatformServices`).

## Austauschbare Technik

| Technik | Schnittstelle | Umsetzung | Warum diese |
|---|---|---|---|
| ARP-Tabelle | `IArpProvider` | `WindowsArpProvider`, `LinuxArpProvider` | je System eigene Quelle (IP-Hilfs-API bzw. `/proc`/`ip`) |
| Nachbartabelle (IPv6) | `INeighborProvider` | `WindowsNeighborProvider`, `LinuxNeighborProvider` | wie oben |
| Routen | `IRoutingProvider` | `WindowsRoutingProvider`, `LinuxRoutingProvider` | wie oben |
| Firewall | `IFirewallInspector` | `WindowsFirewallInspector` (Linux: keine) | nur unter Windows abfragbar |
| Registry bzw. Gegenstück | `IRegistryReader` | `WindowsRegistryReader`, `LinuxRegistryReader` | Firmennetz-Erkennung, Systemangaben |
| Firmennetz | `IEnterpriseEnvironment` | `WindowsEnterpriseEnvironment`, `LinuxEnterpriseEnvironment` | Hinweis auf erlaubte Nutzung in Firmennetzen |
| Dienststeuerung | `IServiceControl` | `WindowsServiceControl` | Hintergrunddienst nur unter Windows |
| WLAN | `IWifiProvider` | `ScanningMethod_WiFi` (Windows) | |
| Eingebettete Webansicht | `IWebViewHost` | `NativeWebViewHost` (Avalonia.Controls.WebView: WebView2 bzw. WebKitGTK) | 3D-Ansicht als HTML mit 3d-force-graph |
| Dialoge, UI-Thread | `IDialogService`, `IUiDispatcher` | in `MyNetworkMonitor.Avalonia` | ViewModels ohne Avalonia testbar |
| Scanverfahren | `IScanMethod` | `Scanning/ScanningMethod_*` | jedes Verfahren für sich ein- und ausschaltbar |
| Dienst-Sonden | `IServiceProbe` | `Scanning/ServiceScans/*Probe` | je Protokoll eine Klasse |
| SNMP | – | Lextm.SharpSnmpLib (`Support/SnmpHelper`) | |
| DNS | – | DnsClient | SRV-Abfragen, Rückwärtsauflösung |

## Plattformunterschiede

Gebündelt in `MyNetworkMonitor.Platform.Windows` (eigenes Projekt, `net10.0-windows`) und
`MyNetworkMonitor.Avalonia/Platform/Linux`. Das Oberflächenprojekt baut unter Windows für
`net10.0-windows` (mit dem Windows-Projekt), sonst für `net10.0`. Was nur auf einer Plattform
getestet ist, steht in `PLATFORM_TESTING_NOTES.md`.

## Gespeicherte Daten

Ordner: `AppDataPaths.Root` = `Environment.SpecialFolder.ApplicationData/MyNetworkMonitor`
(Linux `~/.config/MyNetworkMonitor`, Windows `%APPDATA%\MyNetworkMonitor`).

| Datei | Inhalt | Format | Formatversion |
|---|---|---|---|
| `lastScanResult.json` | letzter Gerätebestand (`DeviceStoreFile`) | JSON | keine (offener Punkt) |
| `mainScanners.json` | Hauptscanner für Satelliten (`MainScannerFile`) | JSON | keine |
| `satellites.json` | bekannte Satelliten (`SatelliteFile`) | JSON | keine |
| `userSettings.txt` | Einstellungen (`UserSettings`) | Text | keine |
| IP-Gruppen | `IpGroupTable` | XML (DataTable mit Schema) | keine |
| `MacVendors/mac_vendors.csv` | erneuerte Herstellerliste; die mitgelieferte liegt neben dem Programm | CSV | – |

Scanergebnisse enthalten echte Adressen und Gerätenamen – nie in Repository, Doku oder Tests.

## Entscheidungen

Zeitlich geordnet, neue ans Ende.

### 25.10.2026 – Version vierstellig

- **Entschieden:** Die Version bleibt vierstellig (`7.3.0.x`) ohne `-beta`; jede Programmänderung
  zählt die letzte Stelle hoch.
- **Warum:** Die veröffentlichten Versionen sollen aufsteigend bleiben; der GitHub-Bau veröffentlicht
  genau dann, wenn sich `<Version>` ändert.

### 25.10.2026 – 3D-Ansicht: Bibliothek mitgeliefert, CDN nur auf Wunsch

- **Entschieden:** Die erzeugte Seite der 3D-Ansicht nimmt die mitgelieferte Bibliothek 3d-force-graph
  (in den Unterordner `libs/` neben der Seite kopiert). Nur mit dem Haken „library from CDN“ (ab Werk aus)
  verweist sie stattdessen auf cdn.jsdelivr.net.
- **Warum:** Offline und ohne Anfrage an Dritte als Vorgabe; der CDN-Verweis erlaubt, eine erzeugte Seite
  allein weiterzugeben. Gerätedaten gehen in keinem Fall hinaus.
