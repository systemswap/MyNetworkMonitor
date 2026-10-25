# Offene Punkte – MyNetworkMonitor

Was als Nächstes ansteht, was bewusst zurückgestellt ist und was nicht wieder
vorgeschlagen werden soll. Erledigtes wird gestrichen (die Geschichte steht in Git und
im Fehlergedächtnis). Grundlage ist die Prüfung gegen die gemeinsamen Regeln vom 25.10.2026.

## Als Nächstes

### Lizenz und Herkunft

- **Portliste** `Support/zzz_DataStructure.cs`: einzelne Beschreibungen stammen aus öffentlichen Portlisten
  (u. a. Wikipedia, CC BY-SA) – eigene Beschreibungen schreiben. Dabei Fehler beheben: Port 7 „ICMP Echo“
  (gemeint ist der Dienst echo), Port 5060 „SID“ statt „SIP“.
### Privatsphäre

- **Firmennetz-Erkennung beim Start** fragt `_ldap._tcp.dc._msdcs.<Domäne>` bei den DNS-Servern des Systems –
  sind dort öffentliche Server eingetragen, geht der Domänenname nach außen. Im Info-Fenster erwähnen oder
  nur bei einer Domäne fragen.

### Bauen und Ausliefern

- Die Fremd-Action `softprops/action-gh-release` im GitHub-Bau auf eine feste Commit-Kennung festlegen (die
  Actions von GitHub selbst hängen ebenfalls nur an Tags).

### Startprüfung

- `ProcessRunner.cs`: `stderr` wird umgeleitet, aber nie gelesen – ein voller Puffer kann den Prozess hängen lassen.
- Rechte für das Mitlesen unter IPv6 (`cap_net_raw`) werden erst gemeldet, wenn ein Verfahren scheitert; eine
  AppImage kann diese Rechte nicht bekommen (FUSE-Einhängung ohne setuid), nur die Paketform „einzeln“.

### Kommentare und Doku

- Kommentare auf Englisch (heute über 90 % deutsch, oft mit ae/oe/ue), Entstehungsgeschichte heraus (rund 250
  Stellen wie „Wörtlich aus dem alten Schalter übernommen“, Daten, Versionen, WPF-Vorgänger, veraltete
  Zukunftshinweise in den Schnittstellen) – mit Nachweis, dass das Programm gleich bleibt.
- Vergleiche mit fremden Programmen neutral fassen (u. a. `BacNetProbe.cs`, `WagoProbe.cs`, `SnmpHelper.cs`).
- `SATELLIT.md` auf den heutigen Stand bringen (Version, fehlender Abschnitt 8, widersprüchlicher Abschnitt 11).

## Vermutete Fehler

- **MongoDB-Erkennung hängt an der Antwortlänge** (`MongoDbProbe.Identify`): Die ersten vier Bytes der Antwort
  müssen `49 01 00 00` sein – das ist die Gesamtlänge 329 einer bestimmten Serverfassung; andere Fassungen
  werden nicht erkannt. Besser: Opcode `OP_REPLY`/`OP_MSG` und die Felder prüfen.

- **WLAN unter Windows** (`MyNetworkMonitor.Platform.Windows/ScanningMethod_WiFi.cs`): Struktur
  `WLAN_AVAILABLE_NETWORK` unvollständig, Umrechnung in dBm falsch (`(q - 100) * 2` statt `q / 2 - 100`),
  `WlanCloseHandle` in der Schleife, kein `WlanFreeMemory`, SSID immer aus dem ersten Eintrag. Unter Windows
  nachstellen, dann beheben.
- `Ipv6MulticastGroupScanMethod.cs`: `ff05::1:3` ist als LLMNR beschriftet, gemeint ist All-DHCP-Servers.

## Später

- **Tests:** ein Testprojekt für die Fachlogik (zuerst die Prüfungen von `NetBiosNodeStatus` aus `docs/PRUEFUNGEN.md`) (Auswertung von `arp`/`ip`-Ausgaben, Sonden-Antworten,
  Dubletten, Host/Domain-Trennung, Speichern und Laden) – heute gibt es keine automatischen Tests.
- **Gespeicherte Daten mit Formatversion** (`lastScanResult.json`, `mainScanners.json`, `satellites.json`,
  `userSettings.txt`, IP-Gruppen).

## Bewusst nicht (nicht wieder vorschlagen)

- 3D-Ansicht nur noch lokal ohne Haken „library from CDN“ – der Haken ist ab Werk aus und bleibt (25.10.2026).
