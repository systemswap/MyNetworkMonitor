# Offene Punkte – MyNetworkMonitor

Was als Nächstes ansteht, was bewusst zurückgestellt ist und was nicht wieder
vorgeschlagen werden soll. Erledigtes wird gestrichen (die Geschichte steht in Git und
im Fehlergedächtnis). Grundlage ist die Prüfung gegen die gemeinsamen Regeln vom 25.10.2026.

## Als Nächstes

- **Gleiche MAC in mehreren Netzen wieder sichtbar machen** (abgestimmt am 18.11.2026). Heute führt der Gerätebestand
  alles mit derselben MAC zu einem Gerät zusammen, über alle Bereiche und Satelliten hinweg; die 3D-Ansicht zeigt
  deshalb keine roten „same MAC“-Kanten mehr, der zweite Name geht verloren. Neue Regel: eine MAC kennzeichnet ein
  Gerät nur innerhalb ihres Netzes. Schritte, je eigene Version mit Tests (1–3 erledigt in 7.3.0.41–7.3.0.43, siehe
  Fehlergedächtnis Nr. 36–39; Satelliten-Zuordnung aus Schritt 4 schon mit Schritt 2):
  1. Netz-Kennung je Adresse (Kennung des Bereichs, bei „Local network“ samt tatsächlichem Subnetz), von allen
     Verfahren mitgegeben und gespeichert; ältere Bestände bekommen sie beim Laden über den passenden Bereich.
  2. Zuordnung: MAC nur im selben Netz; aus EUI-64 abgeleitete MAC nur weich; VRRP-, HSRP- und NLB-MACs nie als
     Kennung; Bereich eines Geräts aus dem Netz seiner Adresse statt „zuletzt gemeldet“; gilt auch für Satelliten.
  3. Befunde: „gleiche MAC in einem anderen Netz“ (Warnung; nur Hinweis „früher in … gesehen“, wenn nicht beide
     zugleich antworten – Umzug); mehrere IPv4 an einer MAC im selben Netz mit Text „Zusatzadresse, alte
     DHCP-Adresse, Repeater/Bridge oder Spoofing“, kritisch als Verdacht auf ARP-Spoofing, wenn das Gateway oder eine
     IP mit eigener anderer MAC betroffen ist; Titel und Schweregrad je Befundzeile (siehe „Vermutete Fehler“).
  4. Satelliten: Zentrale ordnet zurückkommende Geräte über den Auftrag ihrem Bereich zu; Bereichsname je Bereich im
     Auftrag; ältere Satelliten bleiben verwendbar.
  5. Anzeige: Hinweis in der Tabelle, rote Kanten und weitere IPv4-Adressen als eigene Knoten im 3D-Graphen.
  6. Doku (Architektur, SATELLIT.md, Fehlergedächtnis) und Gegenproben: Router mit mehreren VLANs über Satelliten,
     Server mit Zusatz-IP, Notebook nach DHCP-Wechsel, VRRP/HSRP-Paar, geklonte VM, Windows `SendARP` hinter einem
     Router, Messung mit einigen tausend Geräten.

  Bewusst nicht: gleiche private Netze an zwei Standorten (Adressabfragen und doppelte IP je Netz), zufällige MACs
  gesondert, Formatversion der Bestandsdatei, „bekannt und in Ordnung“-Markierung. Das heutige Verhalten halten
  `DeviceStoreTests` und `DuplicateDetectorTests` fest.

- **Gegenproben an echten Geräten** für die Korrekturen 7.3.0.38–7.3.0.40 (gefunden mit einem nachgebauten Netz aus
  Dokumentationsadressen): Hersteller mit Komma ohne Anführungszeichen, Bewertung „global“ unverändert für private und
  öffentliche Adressen, Netzbeschriftung der 3D-Ansicht bei Bereichen, die kein /24 sind. Was jeweils zu prüfen ist:
  `docs/FEHLERGEDAECHTNIS.md`, Nr. 33–35, Punkt „Gegenprobe an echten Geräten“.

## Vermutete Fehler

Beobachtet am 18.11.2026 in einem nachgebauten Netz (Hauptscanner und zwei Satelliten auf einem Rechner, verbunden
über 127.0.0.1); nicht untersucht, vor einer Änderung im echten Aufbau bestätigen:

- **Satellit verbindet sich nach dem Neustart nicht von selbst:** Eine Instanz mit eingeschaltetem Hauptscanner in
  `mainScanners.json` blieb nach dem Start bei „Not connected.“, bis „Connect“ gedrückt wurde – obwohl
  `SatelliteEditorViewModel.ConnectAllHosts` laut Kommentar beim Start läuft.
- **„Satellites are scanning“ bleibt stehen:** Nach einem Scan mit zwei zugewiesenen Satelliten meldete der
  Hauptscanner minutenlang „2 satellites are scanning“, beide Satelliten zeigten „Idle“; ihre Bereiche kamen nicht an.
- **Bereichsfilter der Gerätetabelle:** Die Gerätezahl steht ohne Abstand am Namen („Außenlager12 (12 up)“).

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
