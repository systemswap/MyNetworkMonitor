# Offene Punkte – MyNetworkMonitor

Was als Nächstes ansteht, was bewusst zurückgestellt ist und was nicht wieder
vorgeschlagen werden soll. Erledigtes wird gestrichen (die Geschichte steht in Git und
im Fehlergedächtnis). Grundlage ist die Prüfung gegen die gemeinsamen Regeln vom 25.10.2026.

## Als Nächstes

### Lizenz und Herkunft

- **NetBIOS-Namensabfrage neu schreiben:** `ScanningMethod_NetBios.GetRemoteNetBiosName` beruht auf einer
  Stack-Overflow-Antwort (CC BY-SA, `THIRD-PARTY-NOTICES.md`). Neu nach RFC 1002, Abschnitt 4.2.17/4.2.18
  (NODE STATUS REQUEST/RESPONSE); den auskommentierten Block löschen. Danach unter Linux und Windows prüfen.
- **Nicht benutzten übernommenen Code entfernen:** `Support/SendReceiveDataUDP.cs` (Gist ohne Lizenz,
  .NET-Beispiel), `Support/SupportMethodes_IPRanges.cs` (`IPRange`, Stack Overflow),
  `Support/Supporter_NetworkInterfaces.cs` (Stack Overflow), auskommentierte Fremdreste in
  `Support/SupportMethods.cs` (`LanguageUtils.IgnoreErrors`, `IPComparer`).
- **Reste der Blog-Klasse IPInfo** in `ScanningMethod_ARP.cs` (Texte, `MacAddresstoString`) durch eigene ersetzen.
- **URL ohne Bezug** in `ScanningMethod_PortsTCP.cs` (CodeProject-Artikel; der Code folgt ihm nicht) entfernen.
- **Bilder unklarer Herkunft:**
  - `MyNetworkMonitor.Avalonia/Images/logo.png` ist ein fremdes Motiv mit Urheberangabe eines Künstlers
    (kein Bezug zum Programm, nicht benutzt, aber in jedem Paket) – entfernen, auch aus der Historie.
  - `Images/DevDonationCuted.jpg` (Hintergrund des Spendenfensters) und `Resources/NetworkScanner.ico`
    (Programmsymbol): Herkunft und Lizenz klären oder durch eigene ersetzen.
  - `Resources/paypalDonate.png` wird nicht benutzt – entfernen.
- **Herkunft der mitgelieferten Herstellerliste** `Assets/MacVendors/mac_vendors.csv` klären (Kopfzeile wie
  der CSV-Export eines Online-Dienstes); sonst mit dem vorhandenen Erneuern aus der Datei `manuf` neu erzeugen.
- **Portliste** `Support/zzz_DataStructure.cs`: einzelne Beschreibungen stammen aus öffentlichen Portlisten
  (u. a. Wikipedia, CC BY-SA) – eigene Beschreibungen schreiben. Dabei Fehler beheben: Port 7 „ICMP Echo“
  (gemeint ist der Dienst echo), Port 5060 „SID“ statt „SIP“.
- **Pakete aus Netzmitschnitten neutral machen** (wie schon beim RustDesk-Paket, alte Werte über
  `SupersededDefaults` in `ScanningMethod_Services.cs`):
  - `MsSqlServerProbe.cs`: PRELOGIN mit einem echten Instanznamen und fester TraceID;
  - `MongoDbProbe.cs`: Handshake mit Programm-, Laufzeit- und Windows-Version des mitschneidenden Rechners;
  - `OpcUaProbe.cs`: Hello mit der öffentlichen Adresse eines fremden Servers in der Endpoint-URL.
- **Lizenz des eigenen Programms:** `LICENSE` (MIT mit Commons Clause, gemeinsame Regeln `Regeln/Lizenzen.md`)
  und README anlegen.

### Privatsphäre

- **Protokoll des Satelliten:** `SatelliteLink/SatelliteRuntime.cs` schreibt Benutzer- und Rechnername in
  `satellite.log` – weglassen oder kürzen (Logs ohne persönliche Daten).
- **Beispieladressen** auf Dokumentationsbereiche umstellen: `192.0.2.*` (`DeviceFilter.cs`), `2003:*`
  (`DeviceFilter.cs`, `ScanScope.cs`), `10.20.4.x`/`10.20.5.x` (`ScanScope.cs`), dazu der Router-Hinweis in
  `ScanningMethod_ReverseLookupToHostAndAliases.cs` und `Ipv6StackInfo.cs`.
- **Firmennetz-Erkennung beim Start** fragt `_ldap._tcp.dc._msdcs.<Domäne>` bei den DNS-Servern des Systems –
  sind dort öffentliche Server eingetragen, geht der Domänenname nach außen. Im Info-Fenster erwähnen oder
  nur bei einer Domäne fragen.

### Bauen und Ausliefern

- **Lizenztexte in die Pakete:** Der GitHub-Bau legt `licenses/` und `THIRD-PARTY-NOTICES.md` noch nicht ins
  AppImage und ins Windows-Zip.
- **appimagetool** im GitHub-Bau aus dem aktuellen Projekt (`AppImage/appimagetool`) mit fester Version und
  Prüfsumme laden; die Fremd-Action `softprops/action-gh-release` auf eine feste Commit-Kennung festlegen.
- **Lokales Publish-Skript** nach den gemeinsamen Regeln (`Regeln/Veroeffentlichen.md`).

### Startprüfung

- Der Hinweis zu fehlenden WebKit-Paketen nennt nur `apt` – Befehle für Fedora ergänzen.
- `ip`, `ping`, `nmcli`, `xdg-open` und die Berechtigung `cap_net_raw` beim Start prüfen und mit Paketnamen
  für Debian und Fedora melden; heute liefern die Verfahren dann still leere Listen.
- `ProcessRunner.cs`: `stderr` wird umgeleitet, aber nie gelesen – ein voller Puffer kann den Prozess hängen lassen.

### Kommentare und Doku

- Kommentare auf Englisch (heute über 90 % deutsch, oft mit ae/oe/ue), Entstehungsgeschichte heraus (rund 250
  Stellen wie „Wörtlich aus dem alten Schalter übernommen“, Daten, Versionen, WPF-Vorgänger, veraltete
  Zukunftshinweise in den Schnittstellen) – mit Nachweis, dass das Programm gleich bleibt.
- Vergleiche mit fremden Programmen neutral fassen (u. a. `BacNetProbe.cs`, `WagoProbe.cs`, `SnmpHelper.cs`).
- `SATELLIT.md` auf den heutigen Stand bringen (Version, fehlender Abschnitt 8, widersprüchlicher Abschnitt 11).

## Vermutete Fehler

- **WLAN unter Windows** (`MyNetworkMonitor.Platform.Windows/ScanningMethod_WiFi.cs`): Struktur
  `WLAN_AVAILABLE_NETWORK` unvollständig, Umrechnung in dBm falsch (`(q - 100) * 2` statt `q / 2 - 100`),
  `WlanCloseHandle` in der Schleife, kein `WlanFreeMemory`, SSID immer aus dem ersten Eintrag. Unter Windows
  nachstellen, dann beheben.
- `Ipv6MulticastGroupScanMethod.cs`: `ff05::1:3` ist als LLMNR beschriftet, gemeint ist All-DHCP-Servers.

## Später

- **Tests:** ein Testprojekt für die Fachlogik (Auswertung von `arp`/`ip`-Ausgaben, Sonden-Antworten,
  Dubletten, Host/Domain-Trennung, Speichern und Laden) – heute gibt es keine automatischen Tests.
- **Gespeicherte Daten mit Formatversion** (`lastScanResult.json`, `mainScanners.json`, `satellites.json`,
  `userSettings.txt`, IP-Gruppen).

## Bewusst nicht (nicht wieder vorschlagen)

- 3D-Ansicht nur noch lokal ohne Haken „library from CDN“ – der Haken ist ab Werk aus und bleibt (25.10.2026).
