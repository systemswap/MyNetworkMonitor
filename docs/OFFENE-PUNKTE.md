# Offene Punkte – MyNetworkMonitor

Was als Nächstes ansteht, was bewusst zurückgestellt ist und was nicht wieder
vorgeschlagen werden soll. Erledigtes wird gestrichen (die Geschichte steht in Git und
im Fehlergedächtnis). Grundlage ist die Prüfung gegen die gemeinsamen Regeln vom 25.10.2026.

## Als Nächstes

### Kommentare und Doku

- Normabschnitte in den Kommentaren gegen die Texte prüfen (einige aus dem Gedächtnis: SEMI E5 S1F13, Modbus §6.13/§6.21,
  OPC UA Part 6 §5.2.2.x, ASHRAE 135 §20.1.2, RFC 4861/4291/3810).

## Vermutete Fehler

Zurzeit keine.

## Später

- **WLAN-Signal anzeigen:** `IWifiProvider` misst unter Windows und Linux das verbundene Netz, das Programm zeigt die
  Messung aber nirgends an (Entscheidung des Nutzers, 25.10.2026: berichtigt lassen, Anzeige später).
- **Satellitenbetrieb:** die offenen Teile stehen in `SATELLIT.md`, Abschnitt 10 (Ergebnis auf der Platte,
  `ListenPortChanged`, Hauptscanner als Dienst, Zeitplan, Dienst unter Linux).
- **Weitere Tests** in `MyNetworkMonitor.Core.Tests`: Auswertung von `arp`/`ip`-Ausgaben, Sonden-Antworten, Dubletten,
  Host/Domain-Trennung, Speichern und Laden.
- **Gespeicherte Daten mit Formatversion** (`lastScanResult.json`, `mainScanners.json`, `satellites.json`,
  `userSettings.txt`, IP-Gruppen).

## Bewusst nicht (nicht wieder vorschlagen)

- 3D-Ansicht nur noch lokal ohne Haken „library from CDN“ – der Haken ist ab Werk aus und bleibt (25.10.2026).
