# Offene Punkte – MyNetworkMonitor

Was als Nächstes ansteht, was bewusst zurückgestellt ist und was nicht wieder
vorgeschlagen werden soll. Erledigtes wird gestrichen (die Geschichte steht in Git und
im Fehlergedächtnis). Grundlage ist die Prüfung gegen die gemeinsamen Regeln vom 25.10.2026.

## Als Nächstes

Zurzeit nichts – alle Punkte der Prüfung vom 25.10.2026 sind erledigt.

## Vermutete Fehler

Zurzeit keine.

## Später

- **WLAN-Signal anzeigen:** `IWifiProvider` misst unter Windows und Linux das verbundene Netz, das Programm zeigt die
  Messung aber nirgends an (Entscheidung des Nutzers, 25.10.2026: berichtigt lassen, Anzeige später).
- **Satellitenbetrieb:** die offenen Teile stehen in `SATELLIT.md`, Abschnitt 10 (Ergebnis auf der Platte,
  `ListenPortChanged`, Hauptscanner als Dienst, Zeitplan, Dienst unter Linux).
- **Weitere Tests** in `MyNetworkMonitor.Core.Tests`: Auswertung von `arp`/`ip`-Ausgaben, Sonden-Antworten, Dubletten,
  Host/Domain-Trennung, Speichern und Laden.
- **Kostenpflichtige Normen gegenprüfen:** Die Angaben zu SEMI E5/E30/E37 (SECS/GEM) und ASHRAE 135 (BACnet) sind
  nicht frei prüfbar; alle RFC- und OPC-UA-Abschnitte sind am 25.10.2026 gegen die Originale geprüft.
- **Gespeicherte Daten mit Formatversion** (`lastScanResult.json`, `mainScanners.json`, `satellites.json`,
  `userSettings.txt`, IP-Gruppen).

## Bewusst nicht (nicht wieder vorschlagen)

- 3D-Ansicht nur noch lokal ohne Haken „library from CDN“ – der Haken ist ab Werk aus und bleibt (25.10.2026).
