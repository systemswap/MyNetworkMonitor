# Offene Punkte – MyNetworkMonitor

Was als Nächstes ansteht, was bewusst zurückgestellt ist und was nicht wieder
vorgeschlagen werden soll. Erledigtes wird gestrichen (die Geschichte steht in Git und
im Fehlergedächtnis). Grundlage ist die Prüfung gegen die gemeinsamen Regeln vom 25.10.2026.

## Als Nächstes

### Lizenz und Herkunft

### Privatsphäre

- **Firmennetz-Erkennung beim Start** fragt `_ldap._tcp.dc._msdcs.<Domäne>` bei den DNS-Servern des Systems –
  sind dort öffentliche Server eingetragen, geht der Domänenname nach außen. Im Info-Fenster erwähnen oder
  nur bei einer Domäne fragen.

### Bauen und Ausliefern

- Die Fremd-Action `softprops/action-gh-release` im GitHub-Bau auf eine feste Commit-Kennung festlegen (die
  Actions von GitHub selbst hängen ebenfalls nur an Tags).

### Startprüfung

- Rechte für das Mitlesen unter IPv6 (`cap_net_raw`) werden erst gemeldet, wenn ein Verfahren scheitert; eine
  AppImage kann diese Rechte nicht bekommen (FUSE-Einhängung ohne setuid), nur die Paketform „einzeln“.

### Kommentare und Doku

- Vergleiche mit fremden Programmen in Oberflächentexten prüfen (in Kommentaren erledigt).
- `SATELLIT.md` auf den heutigen Stand bringen (Version, fehlender Abschnitt 8, widersprüchlicher Abschnitt 11).
- Gemischte Sprache in Texten: einige Meldungen und Protokolltexte sind deutsch, die Oberfläche englisch
  (`Ipv6Readiness`, `PlatformServices`, `MacVendorUpdater`, `ServiceGroups`, `ServiceProbeBase`, `WagoProbe`,
  `SupportMethods.GetIPAddressByInterfaceName`, `PayPalDonationView`, `ScanningMethod_WiFi`); die erzeugten Seiten der
  3D-Ansicht haben `lang="de"`, „Unbekannt“ und deutsche Kommentare im eingebetteten HTML/JS. Einheitlich machen.
- Normabschnitte in den Kommentaren gegen die Texte prüfen (einige aus dem Gedächtnis: SEMI E5 S1F13, Modbus §6.13/§6.21,
  OPC UA Part 6 §5.2.2.x, ASHRAE 135 §20.1.2, RFC 4861/4291/3810).

## Vermutete Fehler

- **Satellitenkanal ohne Grenze für entpackte Daten** (`SatelliteLink/MessageChannel.ReceiveAsync`): begrenzt nur die
  gepackte Größe; eine kleine gepackte Nachricht kann beim Entpacken sehr groß werden (Gzip-Bombe). Entpackte Größe
  begrenzen.
- **DNS-Sonden fragen echte Domains** (`gotme.tcp.com`, `gotme.udp.com` in den DNS-Sonden): Namen unter einer
  registrierbaren Domain können auflösen und gehen an fremde Server. Besser ein Name unter `.invalid` (RFC 6761, 6.4).
- **Windows-Dienststeuerung** (`WindowsServiceControl.Run`): liest stdout und danach stderr nacheinander – dasselbe
  Blockier-Risiko wie Fehlergedächtnis Nr. 17. `Elevate` nennt „the log next to the settings“, das Protokoll liegt
  aber im Temp-Ordner.
- `TopologyLauncher.cs`: Ordnername `3dFoceGraph` (Tippfehler); `NullServiceControl` meldet „not supported on this
  platform yet“; in `zzz_DataStructure.cs` ist `portCounter` unbenutzt; `ScopeEditorViewModel` schlägt `192.168.1.1–254`
  als Bereich vor (besser aus der eigenen Schnittstelle ableiten).

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
