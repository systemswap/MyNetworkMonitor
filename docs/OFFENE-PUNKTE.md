# Offene Punkte – MyNetworkMonitor

Was als Nächstes ansteht, was bewusst zurückgestellt ist und was nicht wieder
vorgeschlagen werden soll. Erledigtes wird gestrichen (die Geschichte steht in Git und
im Fehlergedächtnis). Grundlage ist die Prüfung gegen die gemeinsamen Regeln vom 25.10.2026.

## Als Nächstes

### Privatsphäre

### Bauen und Ausliefern

### Startprüfung

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


## Später

- **WLAN-Signal anzeigen:** `IWifiProvider` misst unter Windows und Linux das verbundene Netz, das Programm zeigt die
  Messung aber nirgends an (Entscheidung des Nutzers, 25.10.2026: berichtigt lassen, Anzeige später).

- **Weitere Tests** in `MyNetworkMonitor.Core.Tests`: Auswertung von `arp`/`ip`-Ausgaben, Sonden-Antworten, Dubletten,
  Host/Domain-Trennung, Speichern und Laden.
- **Gespeicherte Daten mit Formatversion** (`lastScanResult.json`, `mainScanners.json`, `satellites.json`,
  `userSettings.txt`, IP-Gruppen).

## Bewusst nicht (nicht wieder vorschlagen)

- 3D-Ansicht nur noch lokal ohne Haken „library from CDN“ – der Haken ist ab Werk aus und bleibt (25.10.2026).
