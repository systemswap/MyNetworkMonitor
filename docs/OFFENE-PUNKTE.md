# Offene Punkte – MyNetworkMonitor

Was als Nächstes ansteht, was bewusst zurückgestellt ist und was nicht wieder
vorgeschlagen werden soll. Erledigtes wird gestrichen (die Geschichte steht in Git und
im Fehlergedächtnis). Grundlage ist die Prüfung gegen die gemeinsamen Regeln vom 25.10.2026.

## Als Nächstes

- **Netzansicht unter Linux: „DHCP/static“ stimmt nicht** – .NET kann unter Linux nicht sagen, ob ein Adapter
  seine Adresse per DHCP bekommt; die Ansicht zeigt dort immer „static“ (`Network/NetworkAdapters.cs`, `IsDhcp`).
  Abhilfe wäre, die Angabe unter Linux aus NetworkManager (`nmcli`) zu lesen, das das Programm schon nutzt.

- **Gleiche MAC in mehreren Netzen – Gegenproben an echten Netzen** (umgesetzt in 7.3.0.41–7.3.0.44, siehe
  `docs/Architektur.md` und Fehlergedächtnis Nr. 36–39): Router oder L3-Switch mit mehreren VLANs über Satelliten,
  Gerät von Zentrale und Satellit gesehen, Server mit Zusatz-IP, Notebook nach DHCP-Wechsel und nach Wechsel
  LAN/WLAN (Hinweis „umgezogen“), VRRP/HSRP-Paar, geklonte VM, Bestand von vor 7.3.0.41, Windows `SendARP` bei einem
  Ziel hinter einem Router. (Messung mit 5000 Geräten erledigt, Fehlergedächtnis Nr. 36.)
  Bewusst nicht: gleiche private Netze an zwei Standorten (Adressabfragen und doppelte IP je Netz), zufällige MACs
  gesondert, Formatversion der Bestandsdatei, „bekannt und in Ordnung“-Markierung. Abgesichert durch
  `DeviceStoreTests`, `SameMacTests`, `NetworkIdTests`, `DuplicateDetectorTests` und `TopologyNetworkLabelTests`.

- **Gegenproben an echten Geräten** für die Korrekturen 7.3.0.38–7.3.0.40 (gefunden mit einem nachgebauten Netz aus
  Dokumentationsadressen): Hersteller mit Komma ohne Anführungszeichen, Bewertung „global“ unverändert für private und
  öffentliche Adressen, Netzbeschriftung der 3D-Ansicht bei Bereichen, die kein /24 sind. Was jeweils zu prüfen ist:
  `docs/FEHLERGEDAECHTNIS.md`, Nr. 33–35, Punkt „Gegenprobe an echten Geräten“.

## Vermutete Fehler

Zurzeit keine. (Die drei Beobachtungen aus dem nachgebauten Netz vom 18.11.2026 sind geklärt: Fehlergedächtnis
Nr. 40–43.)

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
