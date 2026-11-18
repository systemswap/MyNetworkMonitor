# Fehlergedächtnis – MyNetworkMonitor

Jeder behobene Fehler bekommt hier einen Eintrag – auch kleine, sobald man aus ihnen
etwas lernen kann. Zweck: Wer später an derselben Stelle arbeitet, soll wissen, was schon
schiefging, warum, und warum die Lösung so aussieht – damit derselbe Fehler bei einem Umbau
nicht wiederkommt.

Regeln:

- Zeitlich geordnet nach der Behebung, neue Einträge ans Ende, fortlaufend nummeriert.
- Versionen aus `git log` nachsehen, nicht schätzen. Der Commit zu einer Version ist über seine
  Nachricht „Version x.y.z.w: …“ zu finden (Commit-Nummern ändern sich, wenn die Historie
  bereinigt wird).
- Einträge bleiben stehen, auch wenn der Code inzwischen anders aussieht.
- Ohne persönliche Daten: keine echten Adressen, Gerätenamen oder Netzbeschreibungen –
  Beispieladressen aus den Dokumentationsbereichen (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
- Vor Änderungen an einer Stelle hier nach ihr suchen (Datei- oder Klassenname).
- Die Einträge 1–8 sind am 25.10.2026 aus den früheren Testnotizen übernommen; ältere Fehler stehen
  nur in den Commit-Nachrichten.

Automatische Tests stehen in `MyNetworkMonitor.Core.Tests` (`docs/PRUEFUNGEN.md`); ältere Einträge nennen unter
„Abgesichert durch“ die Prüfung im Testnetz.

---

## Nr. 1 – Firmennetz: Erkennung über IP-Bereiche unzuverlässig

- **Behoben:** Version 5.1.0.31 (09.08.2026)
- **Wie bemerkt:** Hinweis „Firmennetz“ erschien bzw. fehlte unpassend.
- **Was passiert ist:** Die Erkennung schloss aus privaten Adressbereichen und Adapternamen auf ein
  Firmennetz; solche Bereiche kommen in Heimnetzen (Docker, VPN, WSL) genauso vor.
- **Warum:** Adressbereiche sagen nichts darüber, ob ein Netz von einer Firma verwaltet wird.
- **Lösung:** `ActiveDirectoryDetector.DomainControllerReachable()`: DNS-SRV-Abfrage
  `_ldap._tcp.dc._msdcs.<domain>` mit kurzen Zeitgrenzen; nur ein erreichbarer Domänencontroller zählt.
- **Warum diese Lösung:** Ein Domänencontroller ist das eindeutige Merkmal eines verwalteten Netzes;
  die Abfrage braucht keinen Scan.
- **Nicht tun:** wieder von Adressbereichen oder Adapternamen auf ein Firmennetz schließen.
- **Im Code:** `MyNetworkMonitor.Core/Services/ActiveDirectoryDetector.cs`, `WindowsEnterpriseEnvironment`,
  `LinuxEnterpriseEnvironment`.
- **Abgesichert durch:** unter Linux im Heimnetz geprüft (`false`, rund 75 ms); Windows-Test offen
  (`PLATFORM_TESTING_NOTES.md`).

## Nr. 2 – Diensterkennung: Antworten nicht geprüft, Sonden schickten TCP-SYN-Pakete

- **Behoben:** Version 6.0.0.0 (10.08.2026)
- **Wie bemerkt:** Durchsicht aller IPv4-Scanverfahren; Dienste wurden auf Geräten gemeldet, die sie
  nicht haben.
- **Was passiert ist:** Jede Antwort auf eine Sonde galt als Treffer. Vier Sonden schickten statt
  Anwendungsdaten rohe TCP-SYN-Pakete (aus einem Netzmitschnitt kopiert).
- **Warum:** Die Antwortprüfung fehlte; die Byte-Folgen der Sonden waren falsch übernommen.
- **Lösung:** Jede Sonde (`IServiceProbe`) prüft die Antwort nach dem Protokoll; Sonden senden echte
  Anwendungsdaten.
- **Nicht tun:** eine Antwort ohne Prüfung als erkannten Dienst werten; Byte-Folgen aus Mitschnitten
  ungeprüft als Sonde übernehmen.
- **Im Code:** `MyNetworkMonitor.Core/Scanning/ServiceScans/`.
- **Abgesichert durch:** im Testnetz gegen echte Server (SSH, FTP, Samba, DNS, Kamera) geprüft, nur
  unter Linux.

## Nr. 3 – SMB: SMB1 als unterstützt gemeldet

- **Behoben:** Version 6.0.0.0 (10.08.2026)
- **Was passiert ist:** SMB1 erschien als unterstützt, obwohl der Server es ablehnte.
- **Warum:** Die Ablehnung in der Antwort wurde nicht ausgewertet.
- **Lösung:** Die Antwort des Servers entscheidet, nicht der erfolgreiche Verbindungsaufbau.
- **Im Code:** SMB-Prüfung in `MyNetworkMonitor.Core/Scanning/`.
- **Abgesichert durch:** im Testnetz gegen einen Samba-Server ohne SMB1 geprüft.

## Nr. 4 – UDP-Portscan fragte nie das Ziel

- **Behoben:** Version 6.0.0.0 (10.08.2026)
- **Was passiert ist:** Der UDP-Portscan meldete die eigenen lokalen UDP-Listener statt der Ports des Ziels.
- **Lösung:** Neu geschrieben: verbundener UDP-Socket je Port; „zu“ heißt, eine ICMP-Meldung „Port
  nicht erreichbar“ kommt als `SocketException` mit `ConnectionReset`/`ConnectionRefused` zurück.
- **Nicht tun:** lokale Listener als Ergebnis eines Scans verwenden.
- **Offen:** Unter Windows hat der Socket-Stapel hier Eigenheiten (`SIO_UDP_CONNRESET`) – noch nicht
  dort geprüft (`PLATFORM_TESTING_NOTES.md`).
- **Abgesichert durch:** unter Linux mit einem offenen und einem geschlossenen Port geprüft.

## Nr. 5 – mDNS fand unter Linux nie ein Gerät

- **Behoben:** Version 6.0.0.0 (10.08.2026)
- **Was passiert ist:** 0 statt 14 Treffer im Testnetz.
- **Warum:** Der Socket war an die eigene Unicast-Adresse gebunden statt an `IPAddress.Any`; Antworten
  an die Multicast-Gruppe kamen so nie an.
- **Lösung:** Bindung an `IPAddress.Any`, Multicast-Schnittstelle über `SocketOptionName.MulticastInterface`.
- **Nicht tun:** Multicast-Empfänger an eine Unicast-Adresse binden.
- **Offen:** unter Windows gegenprüfen (`PLATFORM_TESTING_NOTES.md`).

## Nr. 6 – Reverse-DNS: zweiteilige Namen nicht in Host und Domäne getrennt

- **Behoben:** Version 6.0.0.1 (10.08.2026)
- **Was passiert ist:** Ein zweiteiliger PTR-Name (Muster `router.example`) landete komplett im Feld
  Hostname, die Domäne blieb leer.
- **Warum:** Getrennt wurde erst ab drei Teilen (`Count > 2`).
- **Lösung:** Schwelle `Count > 1`.
- **Im Code:** `ScanningMethod_ReverseLookupToHostAndAliases`, `ReverseLookupScanMethod`.
- **Abgesichert durch:** gegen den Heimrouter, öffentliche Server (IPv4 und IPv6) und den Fall „kein PTR“
  geprüft.

## Nr. 7 – Reverse-DNS verlor bei einem Scan des ganzen Netzes die meisten Antworten

- **Behoben:** Version 6.0.0.2 (10.08.2026)
- **Wie bemerkt:** Nutzer: Ein Gerät mit erkanntem Dienst stand in der Tabelle nur mit seiner Adresse.
- **Was passiert ist:** Bei einem /24-Netz mit rund 30 Geräten kamen 4 Namen zurück.
- **Warum:** (1) 50 gleichzeitige PTR-Abfragen – ein kleiner lokaler DNS-Server verliert unter so einem
  Ansturm die meisten UDP-Antworten. (2) Der äußere Abbruch nutzte dieselbe Zeit wie ein einzelner
  Versuch, die Wiederholungen des DNS-Clients kamen nie zum Zug.
- **Lösung:** 8 gleichzeitige Abfragen, je Versuch 1 s mit 3 Wiederholungen, äußeres Zeitbudget =
  Zeit × (Wiederholungen + 1) + Puffer. Ergebnis: praktisch alle Geräte in 37 s.
- **Nicht tun:** die Nebenläufigkeit wieder hochsetzen; das äußere Zeitbudget kürzer als alle
  Wiederholungen zusammen machen.
- **Im Code:** `ScanningMethod_ReverseLookupToHostAndAliases`.

## Nr. 8 – Namensauflösung über den Resolver des Systems langsam und unvollständig

- **Behoben:** Version 6.0.0.3 (Rückwärts) und 6.0.0.4 (Vorwärts), 10.08.2026
- **Wie bemerkt:** Wunsch des Nutzers, direkt beim DNS-Server zu fragen; der Vergleich bestätigte es.
- **Was passiert ist:** Ohne eigenen DNS-Server im Scan fragte der DNS-Client den Resolver des Systems
  (unter Linux mit systemd-resolved der Stub `127.0.0.53`), der weiterleitet: 21–32 Namen in 13–17 s
  statt aller Namen in unter 100 ms direkt beim Router.
- **Warum:** DnsClient ohne Serverangabe liest `/etc/resolv.conf`; ein Heimrouter ist für seinen lokalen
  Namensraum selbst zuständig, ein weiterleitender Server dazwischen kostet Zeit und Antworten.
- **Lösung:** `LegacyScanMethod.BuildTargets` trägt ohne eigenen DNS-Server das IPv4-Gateway der
  Schnittstelle als Server ein, für Rückwärts- und Vorwärtsauflösung (`ScanningMethod_LookUp`).
  Ein eigener DNS-Server im Scan geht vor. Ist das Gateway nur erraten (keine Angabe der Schnittstelle), fragt der
  Scan die DNS-Server, die an den Netzwerkkarten eingetragen sind – direkt, nicht über den Stub des Systems.
- **Warum diese Lösung:** Die meisten Heimrouter beantworten DNS selbst; wo nicht, bleibt die Adresse
  ohne Namen, ein stiller Rückfall auf das System würde den Fehler verdecken.
- **Nicht tun:** wieder auf den Resolver des Systems zurückfallen.
- **Im Code:** `LegacyScanMethod.BuildTargets`, `ScanningMethod_LookUp.cs`, `IPToScan.DNSServerList`.

## Nr. 9 – Bauen: Schalter gegen Nutzungsdaten fehlte im Repository

- **Entdeckt und behoben:** 25.10.2026, nach Version 7.3.0.11 (Commit „Bauen: keine Nutzungsdaten …“)
- **Wie bemerkt:** Prüfung des Projekts gegen die gemeinsamen Regeln.
- **Was passiert ist:** `Directory.Build.targets` mit dem leeren Ziel `AvaloniaStats` lag nur in einer
  lokalen Kopie, nicht im Repository. Ein frischer Klon und der GitHub-Bau meldeten bei jedem Bau
  Projekt, Version, System und eine Geräte-Kennung an Avalonia; der GitHub-Bau schaltete auch die
  Telemetrie der .NET-Werkzeuge nicht ab.
- **Lösung:** `Directory.Build.targets` eingecheckt; im Workflow `DOTNET_CLI_TELEMETRY_OPTOUT`,
  `DOTNET_NOLOGO`, `AVALONIA_TELEMETRY_OPTOUT`, `DO_NOT_TRACK`.
- **Nicht tun:** Schalter nur lokal oder nur als Umgebungsvariable setzen.
- **Im Code:** `Directory.Build.targets`, `.github/workflows/build-and-release.yml`.

## Nr. 10 – Doku: persönliche Angaben in Beispielen und Testnotizen

- **Entdeckt und behoben:** 25.10.2026, nach Version 7.3.0.11
- **Wie bemerkt:** Prüfung des Projekts gegen die gemeinsamen Regeln (Hooks, Durchsicht).
- **Was passiert ist:** Ein Beispieltext enthielt einen echten Vornamen; die Testnotizen beschrieben
  das eigene Heimnetz (Router, Adressbereich, Gerätenamen, Ausstattung) – im öffentlichen Repository.
- **Lösung:** Erfundene Namen; Testnotizen neutral, behobene Fehler hierher (Nr. 1–8); Historie bereinigt.
- **Nicht tun:** echte Adressen, Gerätenamen oder Netzbeschreibungen in Doku, Kommentare oder Commits.

## Nr. 11 – Pakete: fremdes Bild als Symbol der AppImage

- **Entdeckt und behoben:** 25.10.2026, Version 7.3.0.12
- **Wie bemerkt:** Prüfung der Herkunft aller Bilder (Urheberangabe in den Metadaten der Datei).
- **Was passiert ist:** `Images/logo.png` war ein fremdes Motiv mit der Urheberangabe eines Künstlers, ohne
  Bezug zum Programm und ohne Lizenz. Es kam in jedes Paket und diente im GitHub-Bau als Symbol der AppImage.
  `Resources/paypalDonate.png` war eingebettet, aber nicht benutzt.
- **Lösung:** Beide entfernt (auch aus der Historie); Symbol der AppImage ist jetzt
  `Images/MyNetworkMonitor.png`, die 512-px-Fassung des Programmsymbols `Resources/NetworkScanner.ico`.
- **Nicht tun:** Bilder aus dem Netz ohne Herkunft und Lizenz einbauen; vor dem Einchecken die Metadaten
  ansehen (`THIRD-PARTY-NOTICES.md`, gemeinsame Regel „Fremder Code und Bibliotheken“).
- **Im Code:** `MyNetworkMonitor.Avalonia.csproj`, `.github/workflows/build-and-release.yml`.

## Nr. 12 – Lizenz: übernommener Code ohne Herkunftsangabe

- **Entdeckt:** 25.10.2026, Version 7.3.0.11 (Prüfung des ganzen Codes auf übernommenen Code).
  **Behoben:** 7.3.0.13 (unbenutzter Code entfernt), 7.3.0.14 (Reste einer Blog-Klasse im ARP-Code ersetzt),
  7.3.0.18 (NetBIOS-Namensabfrage nach RFC 1002 neu geschrieben, `Core/Network/NetBiosNodeStatus.cs`).
- **Was passiert ist:** Mehrere Stellen waren aus fremden Quellen übernommen, ohne Herkunft und Lizenz:
  eine UDP-Klasse aus einem Gist ohne Lizenz, ein Beispiel aus der .NET-Dokumentation, eine IP-Bereichs-Klasse
  und eine Abfrage der lokalen Adresse von Stack Overflow (CC BY-SA), auskommentierte Hilfsklassen aus einer
  fremden Bibliothek – alle nicht benutzt. In Gebrauch: die NetBIOS-Namensabfrage (Stack Overflow).
- **Warum:** Beim Übernehmen wurde die Herkunft nicht festgehalten; toter Code blieb liegen.
- **Lösung:** Nicht benutzte Stellen entfernt (`Support/SendReceiveDataUDP.cs`, `Support/SupportMethodes_IPRanges.cs`,
  `Support/Supporter_NetworkInterfaces.cs`, Reste in `Support/SupportMethods.cs`); was bleibt, steht in
  `THIRD-PARTY-NOTICES.md`, Abschnitt „Übertragener Code“.
- **Nicht tun:** Code aus Foren, Gists oder Artikeln ohne Eintrag in `THIRD-PARTY-NOTICES.md` und ohne Lizenzprüfung
  übernehmen; CC-BY-SA- oder lizenzlosen Code in ein Programm mit eigener Lizenz einbauen.

## Nr. 13 – Satellit: Benutzer- und Rechnername im Protokoll

- **Entdeckt:** 25.10.2026, Version 7.3.0.11 (Prüfung gegen die gemeinsamen Regeln). **Behoben:** 7.3.0.16.
- **Was passiert ist:** Beim Start schrieb der Satellit „as <Benutzer> on <Rechner>“ in `satellite.log`.
- **Warum:** Zur Fehlersuche gedacht; Logs sollen aber keine persönlichen Daten enthalten.
- **Lösung:** Die Zeile nennt nur noch die Version. Den eigenen Namen, unter dem sich der Satellit beim
  Hauptscanner meldet, legt der Nutzer im Programm fest – das bleibt.
- **Im Code:** `MyNetworkMonitor.Core/SatelliteLink/SatelliteRuntime.cs` (`Start`).

## Nr. 14 – Diensterkennung: Sonden-Pakete mit Angaben aus Netzmitschnitten

- **Entdeckt:** 25.10.2026, Version 7.3.0.11 (Prüfung auf übernommene Daten). **Behoben:** 7.3.0.17.
- **Was passiert ist:** Drei Sonden schickten Pakete aus Netzmitschnitten an jedes Ziel: MS-SQL den Namen einer
  echten Instanz und feste Thread-/Trace-Kennungen, MongoDB Programm, Laufzeit und Windows-Version des
  mitschneidenden Rechners, OPC UA die Adresse eines fremden Servers.
- **Warum:** Die Pakete wurden aus Mitschnitten abgeschrieben, statt nach dem Protokoll gebaut.
- **Lösung:** Neu gebaut: PRELOGIN für die Standardinstanz mit Null-Kennungen, `isMaster` mit `helloOk` ohne die
  freiwilligen Client-Angaben, Hello mit `opc.tcp://localhost:4840/`. Alle übrigen Felder unverändert. Alte Werte in
  einer gespeicherten Dienstdatei ersetzt `SupersededDefaults` (Prüfsummen mit dem Algorithmus von `Fingerprint`
  nachgerechnet).
- **Warum diese Lösung:** Die Antwortprüfung achtet auf keinen der geänderten Werte (MS-SQL: Typ und Länge der
  Antwort, MongoDB: Antwortkopf und Felder `helloOk`/`topologyVersion`, OPC UA: `ACKF`/`HELF`).
- **Nicht tun:** Pakete aus Mitschnitten ungeprüft übernehmen – Instanz-, Rechner- und Programmnamen stecken darin.
- **Im Code:** `Scanning/ServiceScans/MsSqlServerProbe.cs`, `MongoDbProbe.cs`, `OpcUaProbe.cs`, `SupersededDefaults` in
  `Scanning/ScanningMethod_Services.cs`.
- **Abgesichert durch:** noch nicht gegen echte Server geprüft (`PLATFORM_TESTING_NOTES.md`).

## Nr. 15 – NetBIOS: Auswertung an festen Stellen, ohne Prüfung der Antwort

- **Entdeckt:** 25.10.2026 beim Neuschreiben der übernommenen Abfrage (Nr. 12). **Behoben:** 7.3.0.18.
- **Was passiert ist:** Die Antwort wurde an festen Stellen gelesen (Anzahl der Namen in Byte 56, Namen ab 57),
  ohne Transaktionsnummer, Antwort-Bit oder Fehlercode zu prüfen; die „MAC-Adresse“ waren die letzten sechs Bytes
  des Pakets statt der Kennung am Anfang der Statistik. Antworten mit komprimiertem Namen wurden falsch gelesen.
- **Lösung:** `NetBiosNodeStatus`: Anfrage und Auswertung Feld für Feld nach RFC 1002, Abschnitt 4.2.17/4.2.18
  (Name nach RFC 1001, 14.1), zufällige Transaktionsnummer, jede Länge gegen die Daten geprüft. Auswahl von
  Rechnername und Arbeitsgruppe wie vorher (eindeutig 0x20, sonst 0x00; Gruppe 0x00, sonst 0x1E).
- **Dabei gefunden:** Die erste Fassung las bei einer im Datenteil abgeschnittenen Antwort über das Ende hinaus
  (Prüfung mit 200 000 verdorbenen Antworten) – vor dem Commit behoben.
- **Nicht tun:** Pakete an festen Stellen lesen; Antworten ohne Transaktionsnummer annehmen.
- **Im Code:** `MyNetworkMonitor.Core/Network/NetBiosNodeStatus.cs`, `Scanning/ScanningMethod_NetBios.cs`
  (`GetRemoteNetBiosName`).
- **Abgesichert durch:** Prüfprogramm im lokalen Testordner (`docs/PRUEFUNGEN.md`): Anfrage byte-gleich zur
  bisherigen, fünf Namenslisten gleich ausgewertet wie bisher, komprimierter Name, falsche Nummer/Fehlercode/Anfrage
  abgelehnt, 200 000 verdorbene Antworten ohne Absturz; live gegen einen Samba-Namensdienst (7 Namen, Rechnername und
  Arbeitsgruppe erkannt). Seit dem Testprojekt: `NetBiosNodeStatusTests`.

## Nr. 16 – Start: fehlende Programme unter Linux nur still bemerkbar

- **Entdeckt:** 25.10.2026, Version 7.3.0.11 (Prüfung gegen die gemeinsamen Regeln). **Behoben:** 7.3.0.20.
- **Was passiert ist:** Fehlten `ip`, `ping`, `nmcli` oder `xdg-open`, lieferten die Verfahren still leere Listen;
  nur die Meldung zur Webansicht nannte einen Befehl, und der nur für Debian.
- **Lösung:** `SystemRequirements` (Liste an einer Stelle: Zweck, was ohne passiert, nötig/optional, Pakete für Debian
  und Fedora, nachgesehen am 25.10.2026) und `SystemCheckWindow`: öffnet nach dem Start, wenn etwas Nötiges fehlt
  oder etwas Optionales nicht mit „Don't show again at start“ weggeklickt ist; Befehle für das eigene System zuerst,
  je mit „Copy“; „Check again“ ohne Neustart; jederzeit über Settings → System check. Die Meldung zur Webansicht
  sagt, dass Fedora WPE WebKit nicht als Paket führt.
- **Nicht tun:** Programme selbst installieren; Paketnamen raten; den Start von der Prüfung abhängig machen.
- **Im Code:** `MyNetworkMonitor.Core/Services/SystemRequirements.cs`, `MyNetworkMonitor.Avalonia/Views/SystemCheckWindow.cs`,
  `ShellView.axaml(.cs)` (`ShowSystemCheckIfNeededAsync`, `bt_SystemCheck_Click`), `ShellViewModel` (`IsSystemCheckHidden`).
- **Abgesichert durch:** Start mit leerem Suchpfad (alle vier fehlen) – Fenster geöffnet, Inhalt geprüft; kein Test,
  weil es noch kein Testprojekt gibt.

## Nr. 17 – Kleinigkeiten aus der Prüfung: Portliste, Ausgabe externer Werkzeuge

- **Entdeckt:** 25.10.2026, Version 7.3.0.11 (Prüfung gegen die gemeinsamen Regeln). **Behoben:** 7.3.0.21.
- **Portliste** (`Support/zzz_DataStructure.cs`): Port 7 hieß „ICMP Echo Service Ping“ (Port 7 ist der TCP/UDP-Dienst
  echo, Ping ist ICMP ohne Port), 5060 „SID Phone“ statt SIP; zwei Beschreibungen stammten aus einer öffentlichen
  Portliste unter CC BY-SA (996, 3001) – ersetzt durch den IANA-Dienstnamen bzw. eine eigene Beschreibung. Wirkt
  für neue Portlisten; eine gespeicherte `portsToScan.xml` behält ihre Texte.
- **Externe Werkzeuge** (`Platform/Linux/ProcessRunner.cs`): `stderr` war umgeleitet, wurde aber nie gelesen; schreibt
  ein Werkzeug viel auf `stderr`, füllt sich der Puffer und es bleibt stehen. Jetzt wird `stderr` gleichzeitig gelesen.
- **Nicht tun:** Ausgaben umleiten, ohne sie zu lesen.

## Nr. 18 – Historie: persönliche und betriebliche Angaben in alten Ständen

- **Entdeckt:** 25.10.2026 (Prüfung der ganzen Historie). **Behoben:** 25.10.2026 durch Umschreiben der Historie
  (alle Commit-Nummern sind seitdem neu; Sicherung des alten Stands als Bundle im lokalen Testordner).
- **Was:** Alle Commits trugen Namen, private und betriebliche E-Mail-Adressen und einen Rechnernamen als Autor;
  alte Veröffentlichungsprofile enthielten Benutzer- und Firmenpfade und die Adresse eines internen Servers; alter
  Code und alte Notizen nannten interne Netzadressen, das eigene Heimnetz, einen echten SQL-Instanznamen und
  Hinweise auf das verwendete KI-Werkzeug.
- **Lösung:** Autor und Committer neutral (`MyNetworkMonitor <mynetworkmonitor@localhost>`); die Profile, ein fremdes
  Bild, eine unbenutzte Grafik und nicht benutzter übernommener Code aus allen Commits entfernt; Adressen auf
  Dokumentationsbereiche, Namen und Hinweise neutral ersetzt. Die Herstellerliste und die Lizenztexte blieben
  unverändert (Firmennamen und fremde Texte).
- **Nachweis:** Dateibaum des aktuellen Stands vorher und nachher gleich; Suche über alle Dateifassungen und
  Nachrichten von Zweig und Tags ohne Fund.
- **Nicht tun:** Veröffentlichungsprofile (`*.pubxml`) einchecken; mit persönlicher Git-Identität committen
  (`git config user.name/user.email` je Repository neutral).

## Nr. 19 – Lizenz: Hinweis im Programm und Lizenzdatei widersprachen sich

- **Entdeckt:** 25.10.2026, Version 7.3.0.21 (Lizenzprüfung vor einem möglichen Angebot an Firmen). **Behoben:** 7.3.0.22.
- **Was passiert ist:** Der Hinweis im Firmennetz sagte „free for private use only … a license is required“, die
  `LICENSE` (MIT mit Commons Clause) und die README erlaubten Firmen dagegen die freie Nutzung und verboten nur den
  Verkauf. Rechtlich gilt die Lizenzdatei – eine Firma hätte das Programm ohne Lizenz einsetzen dürfen. Der Hinweis
  sprach außerdem von „Open-Source developers“.
- **Warum:** Die Lizenzdatei wurde nach einer allgemeinen Vorgabe für kostenlose Programme gewählt, ohne den Hinweis im
  Programm mit ihr abzugleichen.
- **Lösung:** Eigene Lizenz (`docs/Architektur.md`, Entscheidung „Lizenz“): Firmen, Selbständige und Behörden brauchen
  für jede Nutzung eine Lizenz, auch nur im eigenen Netz. Hinweis, README und eine Kurzfassung in den Einstellungen
  sagen dasselbe; der volle Text ist über „Show license“ erreichbar.
- **Nicht tun:** Lizenzdatei, README und Texte im Programm getrennt ändern; das Programm „Open Source“ nennen.
- **Im Code:** `LICENSE`, `README.md`, `MyNetworkMonitor.Avalonia/Views/EnterpriseMessageView.axaml`, `LicenseWindow.cs`,
  `ShellView.axaml` (Einstellungen, Block „LICENSE“).
- **Abgesichert durch:** Testprogramm im lokalen Testordner, das den Hinweis öffnet und die Lage der Texte misst (der
  OK-Knopf endet bei 266 von 311 Bildpunkten, alle drei Zeilen sichtbar).

## Nr. 20 – Satellitenkanal: keine Grenze für entpackte Nachrichten

- **Entdeckt:** 25.10.2026, Version 7.3.0.21 (Durchsicht der Kommentare, als Verdacht in den offenen Punkten).
  **Behoben:** 7.3.0.23.
- **Was passiert ist:** `MessageChannel.ReceiveAsync` begrenzte nur die gepackte Größe eines Rahmens (32 MiB). Eine
  gepackte Nachricht von wenigen hundert Kilobyte kann beim Entpacken auf Gigabytes anwachsen („Gzip-Bombe“); der
  Kanal entpackte sie vollständig in den Speicher. Ein Gegenüber im Netz hätte so Hauptscanner oder Satellit zum
  Absturz bringen können, schon mit der ersten Nachricht.
- **Warum:** Die Grenze war als Schutz gegen eine falsche Längenangabe gedacht; dass die Daten danach noch wachsen,
  wurde nicht bedacht.
- **Lösung:** Entpacken in Stücken mit Abbruch, sobald `MaxPlainBytes` (das Vierfache der Rahmengrenze, 128 MiB)
  überschritten wird (`InvalidDataException`, die Verbindung endet wie bei einer falschen Länge). Der Sender prüft
  dieselbe Grenze vor dem Packen, damit er nichts schickt, was die Gegenseite ablehnt. Das Vierfache, weil
  JSON-Ergebnisse etwa um den Faktor zehn schrumpfen und die gepackte Grenze damit schon vorher greift.
- **Nicht tun:** `CopyToAsync` aus einem Entpack-Stream in einen Speicher ohne Grenze; eine Grenze nur für die
  gepackte Größe.
- **Im Code:** `MyNetworkMonitor.Core/SatelliteLink/MessageChannel.cs` (`DecompressAsync`, `MaxPlainBytes`).
- **Abgesichert durch:** `MessageChannelTests.GzipBomb_IsRejectedBeforeItFillsMemory` (schlägt mit dem alten Code
  fehl: die Nachricht wurde vollständig entpackt und gelesen), dazu Rundlauf, Längengrenze und sauberes Ende.

## Nr. 21 – DNS-Sonden: Anfrage nach Namen unter einer echten Domain

- **Entdeckt:** 25.10.2026, Version 7.3.0.21 (Durchsicht der Kommentare, als Verdacht in den offenen Punkten).
  **Behoben:** 7.3.0.24.
- **Was passiert ist:** Die DNS-Sonden fragten nach `gotme.tcp.com` und `gotme.udp.com`. Ein weiterleitender
  Namensserver gibt solche Anfragen an die Namensserver der Domain weiter; wer sie besitzt, sieht jede Prüfung samt
  der öffentlichen Adresse des Netzes – und könnte den Namen auch auflösen lassen.
- **Warum:** Gemeint war „ein Name, den es nicht gibt“; unter einer registrierbaren Domain ist das nicht sicher.
- **Lösung:** Ein Name an einer Stelle für beide Sonden, `DnsRequest.NonexistentName` = `probe.mynetworkmonitor.invalid`.
  Die Endung `invalid` ist reserviert und löst nie auf, zwischenspeichernde Server beantworten sie selbst mit
  NXDOMAIN (RFC 6761, Abschnitt 6.4). Eine NXDOMAIN-Antwort genügt der Sonde als Zeichen für einen Namensserver.
  Verworfen: `.example` und `.test` (ebenfalls reserviert, aber nicht ausdrücklich „nie weiterleiten“).
- **Nicht tun:** Prüfnamen unter `.com`, `.net` oder anderen registrierbaren Domains.
- **Im Code:** `MyNetworkMonitor.Core/Scanning/ServiceScans/DnsRequest.cs`, `DnsTcpProbe.cs`, `DnsUdpProbe.cs`.
- **Abgesichert durch:** `DnsRequestTests` (Name unter `.invalid`, Kodierung der Anfrage, Zuordnung der Antwort);
  der Namensserver des Testnetzes beantwortet den Namen mit NXDOMAIN.

## Nr. 22 – MongoDB-Erkennung hing an der Antwortlänge einer Serverfassung

- **Entdeckt:** 25.10.2026, Version 7.3.0.21 (Durchsicht der Kommentare, als Verdacht in den offenen Punkten).
  **Behoben:** 7.3.0.25.
- **Was passiert ist:** `MongoDbProbe.Identify` verlangte als erste vier Bytes `49 01 00 00` – das ist das Feld
  messageLength, also die Gesamtlänge 329 Byte einer bestimmten Antwort – und dazu die Wörter `helloOk` und
  `topologyVersion`. Server anderer Fassungen, mit Replica Set oder anderem Rechnernamen antworten länger oder kürzer;
  Server vor 4.4 senden `topologyVersion` gar nicht. Sie blieben „Open“ statt MongoDB.
- **Warum:** Die Prüfung war aus einer einzigen mitgeschnittenen Antwort abgeleitet.
- **Lösung:** Prüfung nach dem Aufbau des Protokolls: Kopf mit messageLength (plausibel, nicht kleiner als das
  Gelesene), responseTo = Request-ID des Erkennungspakets (1), opCode OP_REPLY (1) oder OP_MSG (2013); im BSON-Dokument
  `maxWireVersion` (Ganzzahl) und die Rolle als `ismaster` oder `isWritablePrimary` (Wahrheitswert) – die sendet
  jeder Server auf `isMaster`. Das Erkennungspaket ist unverändert.
- **Nicht tun:** Antworten an ihrer Länge oder an Feldern erkennen, die nur neuere Fassungen senden; das
  Erkennungspaket anpassen, um die Prüfung zu vereinfachen.
- **Im Code:** `MyNetworkMonitor.Core/Scanning/ServiceScans/MongoDbProbe.cs` (`Identify`).
- **Abgesichert durch:** `MongoDbProbeTests` – Antworten wie von 4.0, 4.4, 7.0 im Replica Set und 8.0 (OP_MSG) sowie
  eine vom Lesepuffer abgeschnittene Antwort werden erkannt (mit dem alten Code fünf Fehlschläge); Antworten auf eine
  andere Anfrage, Anfragen, Fehlerantworten und Text werden abgelehnt. Gegen echte Server noch offen
  (`PLATFORM_TESTING_NOTES.md`).

## Nr. 23 – Externe Werkzeuge: Fehlerausgabe nacheinander oder gar nicht gelesen (Windows-Dienst, ldconfig)

- **Entdeckt:** 25.10.2026, Version 7.3.0.21 (Durchsicht der Kommentare, als Verdacht in den offenen Punkten; die
  zweite Stelle beim Beheben). **Behoben:** 7.3.0.26.
- **Was passiert ist:** `WindowsServiceControl.Run` (für `sc.exe` und `icacls.exe`) las erst die Standardausgabe bis
  zum Ende und danach die Fehlerausgabe. Schreibt ein Werkzeug mehr in die Fehlerausgabe, als deren Puffer fasst
  (`icacls /T` über viele Dateien), wartet es auf einen Leser, während das Programm auf das Ende der Standardausgabe
  wartet – beide hängen. Die Bibliothekssuche der Webansicht (`ldconfig -p` in `ShellView`) leitete die
  Fehlerausgabe um und las sie nie. Dazu nannte `Elevate` bei einem Fehlschlag „the log next to the settings“; das
  Protokoll liegt aber im Temp-Ordner.
- **Warum:** Wie Nr. 17: Ausgaben umgeleitet, ohne beide gleichzeitig zu lesen.
- **Lösung:** Die Fehlerausgabe wird mit `ReadToEndAsync` neben der Standardausgabe gelesen (wie in `ProcessRunner`).
  Der Protokollort steht an einer Stelle, `AppPaths.CrashLog`; die Meldung nennt den vollen Pfad.
- **Nicht tun:** zwei umgeleitete Ausgaben nacheinander bis zum Ende lesen; eine Ausgabe umleiten und nicht lesen.
- **Im Code:** `MyNetworkMonitor.Platform.Windows/WindowsServiceControl.cs` (`Run`, `Elevate`),
  `MyNetworkMonitor.Avalonia/Views/ShellView.axaml.cs` (Suche über `ldconfig`), `MyNetworkMonitor.Core/Services/AppPaths.cs`
  (`CrashLog`), `MyNetworkMonitor.Avalonia/Program.cs`.
- **Abgesichert durch:** Bau für Linux und Windows; unter Windows noch nicht gelaufen (`PLATFORM_TESTING_NOTES.md`).
  Kein automatischer Test: die Stellen rufen Systemwerkzeuge auf.

## Nr. 24 – WLAN-Messung: falsche Struktur unter Windows, übersetzte Ausgabe unter Linux

- **Entdeckt:** 25.10.2026, Version 7.3.0.21 (Durchsicht der Kommentare; die Linux-Fehler beim Beheben). **Behoben:** 7.3.0.27.
- **Was passiert ist:** Unter Windows las `ScanningMethod_WiFi` `WLAN_AVAILABLE_NETWORK` mit einer Struktur aus drei
  Feldern statt 628 Byte – Signal und Name kamen aus falschen Stellen –, nahm den Namen immer aus dem ersten Eintrag,
  schloss das Handle mitten in der Schleife, gab die Listen nie frei und rechnete dBm als `(q - 100) * 2` (100 % wurden
  0 dBm, 0 % -200 dBm). Beim Beenden warf `StartScanningAsync` die Abbruch-Ausnahme nach außen. Unter Linux schrieb
  `nmcli` in einer deutschen Sitzung „ja“/„nein“ statt „yes“/„no“ – das verbundene Netz wurde nie erkannt –, Namen mit
  „:“ wurden zerschnitten, und dBm kam aus derselben falschen Formel. Aufgefallen war nichts, weil das Programm die
  Messung nirgends anzeigt.
- **Warum:** Strukturen nach Gefühl statt nach `wlanapi.h`; eine Formel für zwei verschiedene Skalen; maschinelles
  Lesen übersetzter Ausgaben.
- **Lösung:** Windows liest die Listen Feld für Feld an den Stellen aus `wlanapi.h`/`windot11.h` (Größen als Konstanten
  mit Herleitung), nimmt den ersten verbundenen Adapter und das Netz mit `WLAN_AVAILABLE_NETWORK_CONNECTED`, gibt mit
  `WlanFreeMemory` frei und schließt das Handle erst nach der Schleife. dBm je Skala: Windows 0–100 % = -100…-50 dBm
  (`WindowsQualityToDbm`), NetworkManager -100…-40 dBm (`NetworkManagerSignalToDbm`). `ProcessRunner` startet alle
  Werkzeuge mit `LC_ALL=C` (nmcli(1), „Internationalization notes“), `NmcliTerse` zerlegt die Zeilen mit Escapes.
- **Nicht tun:** Ausgaben von Werkzeugen in der Sprache des Nutzers auswerten; Windows-Strukturen kürzen, „weil nur der
  Anfang gebraucht wird“, wenn Einträge hintereinander in einer Liste liegen.
- **Im Code:** `MyNetworkMonitor.Platform.Windows/ScanningMethod_WiFi.cs`, `MyNetworkMonitor.Avalonia/Platform/Linux/LinuxWifiProvider.cs`,
  `ProcessRunner.cs`, `MyNetworkMonitor.Core/Models/WiFiSignalResult.cs`, `MyNetworkMonitor.Core/Network/NmcliTerse.cs`.
- **Abgesichert durch:** `WifiTests` (beide Umrechnungen, Zerlegen mit Escapes); im Testnetz `nmcli` mit und ohne
  `LC_ALL=C` verglichen („nein“ gegen „no“). Windows noch nicht gelaufen (`PLATFORM_TESTING_NOTES.md`).

## Nr. 25 – Kleinigkeiten: IPv6-Gruppen falsch benannt, Vorschlag für neue Bereiche, Ordnername

- **Entdeckt:** 25.10.2026, Version 7.3.0.21 (Durchsicht der Kommentare). **Behoben:** 7.3.0.28.
- **Was:** `Ipv6MulticastGroupScanMethod` nannte ein Gerät in der Gruppe `ff02::1:2` „DHCPv6 client (looking for a
  server)“ – Mitglied dieser Gruppe sind aber Server und Relays, Clients senden nur an sie (RFC 8415, Abschnitt 7.1) –
  und `ff05::1:3` LLMNR statt All-DHCP-Servers; `ff05::1:2` ist keine vergebene Gruppe. Ein neuer Bereich im
  Bereichseditor war immer `192.168.1.1–254`, auch in jedem anderen Netz. Der Ordner der 3D-Ansicht hieß
  `3dFoceGraph`. Unter Linux meldete die Dienststeuerung „not supported on this platform yet“, obwohl der Dienst
  nur für Windows vorgesehen ist. In `zzz_DataStructure` stand eine unbenutzte Variable.
- **Lösung:** Gruppen nach RFC 8415 und RFC 4795 benannt; ein neuer Bereich nimmt das eigene IPv4-Netz mit Gateway,
  größere Netze als /24 auf das /24 um die eigene Adresse begrenzt (`SiteInfo.SuggestedRange`), sonst wie bisher
  `192.168.1.1–254`; der Ordner heißt `3dForceGraph`, ein vorhandener alter Ordner wird beim ersten Öffnen
  umbenannt; die Meldung sagt „only available on Windows“.
- **Nicht tun:** Gruppenadressen nach Gefühl beschriften; feste Beispielnetze als Vorgabe.
- **Im Code:** `Scanning/Engine/Methods/Ipv6MulticastGroupScanMethod.cs` (`ServiceBehind`), `Network/SiteInfo.cs`,
  `ViewModels/ScopeEditorViewModel.cs` (`Add`), `Services/TopologyLauncher.cs`, `Services/IServiceControl.cs`.
- **Abgesichert durch:** `SiteInfoTests` (Netze /8 bis /32, IPv6, ungültige Eingabe).

## Nr. 26 – Firmennetz-Erkennung: Domänenname auch an öffentliche Resolver und für Router-Domänen

- **Entdeckt:** 25.10.2026, Version 7.3.0.21 (Prüfung gegen die gemeinsamen Regeln, als offener Punkt „Privatsphäre“).
  **Behoben:** 7.3.0.29.
- **Was passiert ist:** Bei jedem Start fragte `ActiveDirectoryDetector` `_ldap._tcp.dc._msdcs.<Domäne>` für die globale
  Domäne und jedes Adapter-Suffix bei den Namensservern des Systems. Im Heimnetz ist das Suffix die Domäne des Routers
  (z. B. `fritz.box`), die Abfrage kann nie einen Domänencontroller finden; ist ein großer öffentlicher Resolver
  eingetragen, erfuhr dieser bei jedem Start den Domänennamen des Netzes.
- **Warum:** Die Erkennung kannte keine Fälle, in denen die Frage sinnlos ist.
- **Lösung:** Keine Abfrage für Router-Domänen als ganzer Name (`fritz.box`, `speedport.ip`, `lan`, `home`,
  `localdomain`, `local`), `home.arpa` und die reservierten Endungen `localhost`, `invalid`, `test`, `example`
  (`IsLocalSuffix`); keine Abfrage bei den großen öffentlichen Resolvern (Google, Cloudflare, Quad9, OpenDNS,
  `IsPublicResolver`), die nie einen internen Domänencontroller kennen. Alle anderen Namensserver aller aktiven
  Adapter bleiben, auch VPN-Adapter.
- **Verworfen:** nur Namensserver mit privater Adresse – große Firmen betreiben interne Namensserver auf eigenen
  öffentlichen Bereichen, dort wäre die Erkennung ausgefallen. Endungen `.local`/`.lan` überspringen – viele
  Active-Directory-Domänen heißen `firma.local`. Nur physische Adapter – der Namensserver eines Firmen-VPN fände den
  Domänencontroller aus dem Homeoffice nicht mehr. Die LDAP-Prüfung in Firmennetzen soll bleiben (Wunsch des Nutzers).
- **Nicht tun:** die Erkennung so einschränken, dass Firmennetze durchrutschen; den Domänennamen an Dienste schicken,
  die ihn nie beantworten können.
- **Im Code:** `MyNetworkMonitor.Core/Services/ActiveDirectoryDetector.cs`; Hinweis in `README.md` („Privatsphäre“).
- **Abgesichert durch:** `ActiveDirectoryDetectorTests` (Resolver, Suffixe, darunter `company.local` und `company.lan`
  als geprüft); im Testnetz „kein Firmennetz“ nach 26 ms ohne Abfrage. Ein Firmennetz steht noch aus
  (`PLATFORM_TESTING_NOTES.md`).

## Nr. 27 – Startprüfung: Rechte für Rohsockets erst beim Fehlschlag gemeldet, Befehl für die AppImage wirkungslos

- **Entdeckt:** 25.10.2026, Version 7.3.0.21 (Prüfung gegen die gemeinsamen Regeln, Abschnitt Startprüfung).
  **Behoben:** 7.3.0.30.
- **Was passiert ist:** Dass die IPv6-Verfahren zum Mitlesen (Router Advertisement, MLD) `CAP_NET_RAW` brauchen, erfuhr
  man erst, wenn sie nichts fanden. Die Meldung schlug `sudo setcap cap_net_raw+ep $(which MyNetworkMonitor.Avalonia)`
  vor: `which` findet das Programm nicht, wenn es nicht im Suchpfad liegt, und bei der AppImage wirkt `setcap` nicht –
  sie läuft aus einer FUSE-Einhängung, in der Datei-Rechte keine Wirkung haben.
- **Lösung:** `RawSocketRights` liest das wirksame Recht aus `/proc/self/status` (Zeile `CapEff`, Bit 13) bzw. erkennt
  root, und baut den Befehl für die Art, wie das Programm läuft: `setcap` auf `Environment.ProcessPath`, bei einer
  AppImage (`APPIMAGE` gesetzt) erst `--appimage-extract` neben der AppImage und `setcap` auf das entpackte Programm.
  Die Startprüfung zeigt den Punkt als optional (abschaltbar mit „Don't show again at start“), die Meldung der
  Verfahren nimmt denselben Text.
- **Nicht tun:** Befehle mit `$(which …)` vorschlagen; Datei-Rechte für eine AppImage empfehlen.
- **Im Code:** `MyNetworkMonitor.Core/Services/RawSocketRights.cs`, `MyNetworkMonitor.Avalonia/Views/SystemCheckWindow.cs`,
  `MyNetworkMonitor.Core/Scanning/Engine/Methods/Ipv6MethodBase.cs` (`NoRawSocketReason`).
- **Abgesichert durch:** `RawSocketRightsTests` (Lesen von `CapEff`, Befehl für Programmdatei und AppImage,
  Anführungszeichen im Pfad). Der ganze Weg mit der AppImage steht noch aus (`PLATFORM_TESTING_NOTES.md`).

## Nr. 28 – Texte: deutsche Meldungen in der englischen Oberfläche, veralteter Hinweis zur Herstellerliste

- **Entdeckt:** 25.10.2026, Version 7.3.0.21 (Durchsicht der Kommentare; der Hinweis beim Prüfen der Oberflächentexte).
  **Behoben:** 7.3.0.31.
- **Was:** Rund 55 Meldungen waren deutsch, obwohl die Oberfläche englisch ist – vor allem die Protokolltexte der Sonden
  („Port ist offen, aber keine Antwort …“), die im Portprotokoll erscheinen, dazu die Gruppen des Dienst-Managers, Fehler
  beim Herunterladen der Herstellerliste und die Seiten der 3D-Ansicht (`lang="de"`, „Unbekannt“, deutsche Kommentare im
  eingebetteten JavaScript). Der Hinweis neben „Update from Wireshark“ sagte, die mitgelieferte Liste enthalte nur
  MA-L-Blöcke; seit 7.3.0.19 enthält sie auch MA-M und MA-S. Port 135 hieß „Transact-SQL-Debugger oder net send ersatz
  für 139“ (IANA: epmap, DCE/RPC-Endpunktzuordnung).
- **Lösung:** Alle Texte englisch, Gruppen nur noch in `ServiceGroups` (`GetServiceGroup` nimmt die Konstanten statt
  eigener Texte). Die Detailansicht erkennt die bloße Bestätigung einer Sonde in beiden Fassungen
  (`ProtocolMatched`, `ProtocolMatchedGerman`), weil gespeicherte Ergebnisse älterer Fassungen den deutschen Text tragen.
  Die Gruppen werden beim Laden aus dem Code gesetzt, nicht aus `services.xml` – gespeicherte Dateien brauchen nichts.
- **Nicht tun:** einen angezeigten Text zugleich als Schlüssel für einen Vergleich nehmen, ohne alte Fassungen
  mitzudenken; Gruppennamen an zwei Stellen schreiben.
- **Im Code:** u. a. `Scanning/ServiceScans/ServiceProbeBase.cs`, `WagoProbe.cs`, `ServiceGroups.cs`,
  `Scanning/ScanningMethod_Services.cs`, `Scanning/Engine/Methods/LegacyScanMethod.cs` (`IsDeviceInfo`),
  `Services/TopologyGraph.cs`, `ServiceTopologyGraph.cs`, `MyNetworkMonitor.Avalonia/Views/ShellView.axaml`.
- **Abgesichert durch:** `PortLogTests` (beide Fassungen der Bestätigung), `TopologyPageTests` (Seiten vollständig,
  englisch, ohne CDN-Verweis ab Werk).

## Nr. 29 – Rechte-Hinweis: kam bei jedem Start wieder, Befehl für die AppImage half nicht

- **Entdeckt:** 26.10.2026, Version 7.3.0.32 (Nutzer: Fenster der Startprüfung kam nach dem Ausführen des Befehls bei
  jedem Start wieder). **Behoben:** 7.3.0.33.
- **Was passiert ist:** Seit 7.3.0.30 (Nr. 27) öffnete die Startprüfung bei jedem Start, wenn `CAP_NET_RAW` fehlte, und
  schlug für die AppImage vor, sie zu entpacken und dem entpackten Programm das Recht zu geben. Das Recht hatte danach
  nur die entpackte Kopie; das Menü startet weiter die AppImage, die es nie bekommt – die Meldung kam also immer wieder.
  Dazu liegt die entpackte Kopie in `published/`, das der nächste Bau neu anlegt, und `setcap` fehlte auf dem
  Rechner (Paket libcap2-bin nicht installiert), so dass der letzte Schritt scheiterte.
- **Warum:** Ein Recht für zwei Spezialverfahren wurde wie ein fehlendes Programm behandelt, und der Befehl war nur
  bis zum Entpacken durchdacht, nicht bis zum nächsten Start.
- **Lösung:** Der Hinweis öffnet das Fenster nicht mehr beim Start; er steht unter Settings → System check und in der
  Meldung der beiden Verfahren. Für eine AppImage gibt es keinen Befehl mehr (`GrantCommand` liefert null), nur den
  Rat, sie mit sudo zu starten oder die lose Paketform mit `setcap` zu nehmen. Der Haken „Don't show again“ für
  diesen Punkt entfällt.
- **Nicht tun:** Optionale Rechte beim Start melden; Befehle vorschlagen, deren Wirkung der nächste Start oder Bau
  aufhebt.
- **Im Code:** `MyNetworkMonitor.Core/Services/RawSocketRights.cs`, `MyNetworkMonitor.Avalonia/Views/SystemCheckWindow.cs`
  (`NeedsAttention`, `RawSocketItem`), `MyNetworkMonitor.Core/Scanning/Engine/Methods/Ipv6MethodBase.cs`.
- **Abgesichert durch:** `RawSocketRightsTests.AppImage_GetsNoCommand` (schlägt mit dem alten Code fehl); Start der
  AppImage im Testordner ohne Fenster der Startprüfung.

## Nr. 30 – Dienst-Sonden: DHCP nannte unter Umständen einen falschen Server, BACnet eine falsche oder gar keine Kennung

- **Entdeckt:** 01.11.2026, Version 7.3.0.33 (Durchsicht der
  Auswertung gegen RFC 2132 und ASHRAE 135, Test mit einer nachgespielten Ablehnung). **Behoben:** 7.3.0.34.
- **Was:**
  - DHCP: Die Server-Kennung (Option 54) wurde als erstes Byte mit dem Wert 54 irgendwo in der Antwort gesucht. Steht
    54 in der Transaktionsnummer, in einer Adresse oder in den Daten einer anderen Option, wurden die vier Bytes danach
    als Server genommen – ein Gerät, das gar kein DHCP-Server ist, oder keines im Netz.
  - BACnet: Die Nummer des Herstellers (VendorID) wurde aus dem vorletzten Byte *jeder* Antwort gelesen, auch einer
    Ablehnung (Reject) – aus dem Ablehnungsgrund wurde so „VendorID: 1“. War die Antwort auf die ObjectID-Abfrage
    kürzer als 22 Bytes, warf die Auswertung eine Ausnahme, und das ganze Gerät galt als „keine Antwort“, obwohl es
    schon als BACnet geantwortet hatte. Ebenso bei einem Empfangsfehler für eine einzelne Eigenschaft.
- **Warum:** Beide Auswertungen nahmen feste Stellen bzw. einen Bytewert an, statt den Aufbau der Antwort zu lesen.
- **Lösung:** DHCP liest nur BOOTP-Antworten (op 2) und geht die Optionsliste nach dem Magic Cookie Eintrag für Eintrag
  durch; ohne Option 54 bleibt es bei giaddr, dann siaddr. BACnet liest Werte nur aus einer ComplexACK (APDU-Typ 3,
  NPDU mit optionaler Ziel- und Quelladresse übersprungen); zu kurze Antworten ergeben „0“ und fehlen in der Ausgabe;
  ein Empfangsfehler für eine Eigenschaft lässt nur diese weg. Die gesendeten Pakete sind unverändert.
- **Nicht tun:** Felder einer Antwort über die Suche nach einem Bytewert finden; Ausnahmen der Detail-Auswertung den
  Fund selbst verwerfen lassen.
- **Im Code:** `MyNetworkMonitor.Core/Scanning/ServiceScans/DhcpProbe.cs` (`GetDhcpServerIp`),
  `BacNetProbe.cs` (`IsComplexAck`, `ExtractBacnetObjectInstanceAsString`, `ExtractBacnetAsciiString`,
  `QueryBacnetProperty`).
- **Abgesichert durch:** `DhcpProbeTests` (Byte 54 in Transaktionsnummer und Netzmaske, Relay, Anfrage statt Antwort,
  jede abgeschnittene Länge), `BacNetProbeTests` (Reject ohne VendorID, kurze Antwort ohne Ausnahme, Text nur aus
  ComplexACK, NPDU mit Quelladresse). Die Methoden waren vorher privat; gegen den alten Code laufen die Tests nicht,
  der alte Code hätte für die Antwort mit 54 in der Transaktionsnummer die Bytes 6–9 als Server genannt und für den
  Reject „1“ geliefert.

## Nr. 31 – SMB-Versionsprüfung: SMB 3.1.1 wurde nie erkannt

- **Entdeckt:** 01.11.2026, Version 7.3.0.34 (kein Gerät im Testnetz meldete 3.1.1, obwohl aktuelle Server es können;
  Gegenprobe mit einer Anfrage nach [MS-SMB2] 2.2.3). **Behoben:** 7.3.0.35 (Änderung des Pakets mit Zustimmung des
  Nutzers).
- **Was:** Die Anfrage für 3.1.1 war die Einzel-Dialekt-Anfrage der anderen Versionen mit dem Dialekt 0x0311, ohne
  Liste der Verhandlungsangaben (NegotiateContextOffset und -Count 0). Ein Server antwortet darauf mit
  `STATUS_INVALID_PARAMETER` (0xC000000D) – an zwei Geräten des Testnetzes gemessen –, die Prüfung sah „nicht
  unterstützt“.
- **Warum:** [MS-SMB2] 2.2.3 verlangt, dass eine Anfrage, die 3.1.1 anbietet, Verhandlungsangaben trägt, mindestens
  SMB2_PREAUTH_INTEGRITY_CAPABILITIES (2.2.3.1.1).
- **Lösung:** eigene Anfrage `GetSMB311NegotiationRequest`: gleicher Kopf, gleicher Sicherheitsmodus und dieselbe
  Client-GUID wie die anderen, dazu Versatz 104 und Anzahl 1 der Verhandlungsangaben, zwei Bytes Füllung auf eine
  8-Byte-Grenze und die Angabe zur Vorab-Integrität (SHA-512, 32 Byte Salt). Salt fest statt zufällig, damit das Paket
  in jedem Lauf gleich ist und sich abgleichen lässt. Beide Geräte nehmen die Anfrage an und wählen 0x0311. Die
  Pakete der anderen Versionen sind unverändert.
- **Nicht tun:** den Dialekt 0x0311 ohne Verhandlungsangaben anbieten.
- **Im Code:** `MyNetworkMonitor.Core/Scanning/ScanningMethod_SMBVersionCheck.cs` (`GetSMB311NegotiationRequest`,
  Aufruf in `CheckProtocolsCoreAsync`).
- **Abgesichert durch:** `SmbNegotiationTests` (Längenfeld, nur 0x0311 angeboten, Verhandlungsangabe an der
  angegebenen, ausgerichteten Stelle bis zum Paketende). Gegenprobe an echten Servern: Status 0 und Dialekt 0x0311.

## Nr. 32 – Suche per SSDP, ONVIF und mDNS: Angaben verworfen, unnütze Abrufe, eigene Anfragen als Gerät

- **Entdeckt:** 01.11.2026, Version 7.3.0.35 (Durchsicht der Verfahren gegen UPnP Device Architecture 2.0, ONVIF Core
  und RFC 6762, Gegenprobe im Testnetz). **Behoben:** 7.3.0.36. Die gesendeten Pakete sind unverändert.
- **Was:**
  - SSDP: Die Gerätebeschreibung (Name, Hersteller, Modell) wurde geladen und verworfen; gemeldet wurde nur „hat
    geantwortet“. Geladen wurde sie bei *jeder* Antwort eines Geräts – meist ein Dutzend je Gerät, bis zu 5 s je
    Abruf, während die Empfangsschleife ruhte –, und von jeder Adresse, die LOCATION nannte, auch fremden.
  - ONVIF: Nach jeder Antwort folgten zwei GET-Abrufe unter der Adresse des Gerätedienstes (`…/media_service`,
    `…/network_service`), die ONVIF nicht kennt (die Angaben gibt es nur per SOAP an den Adressen aus
    GetCapabilities); ihr Ergebnis wurde nie gemeldet, sie kosteten bis zu 10 s je Antwort. Bei mehreren
    Dienstadressen (IPv4 und IPv6) scheiterte die Auswertung an der ganzen Liste als URI, die Kamera fehlte.
  - mDNS: Jedes Paket galt als Antwort – die eigenen, zurückgespiegelten Anfragen machten den eigenen Rechner zum
    Fund, Anfragen anderer Geräte ebenso. Die Fragen eines Pakets wurden als Einträge gelesen (Zählerfelder
    übergangen), ein Adresseintrag überschrieb die Adresse des Absenders, ein beschädigter TXT-Eintrag verschob die
    folgenden.
- **Lösung:** SSDP liest nur die erste Antwort je Adresse, lädt die Beschreibung nur vom Gerät selbst
  (`IsOwnLocation`) und meldet Name, Hersteller und Modell als Detail „UPnP“ und als Dienst UPnP auf Port 1900.
  ONVIF ohne Folgeabrufe; von mehreren Dienstadressen gilt die erste, der Name aus dem Scope wird dekodiert. mDNS
  wertet nur Antworten (QR-Bit) aus, nicht die eigenen; Fragen werden über ihre Anzahl übersprungen, Einträge über
  ihre Länge; die Adresse bleibt die des Absenders, ein Adresseintrag für genau diese liefert den Namen (Zeile
  „Host“ in den mDNS-Angaben, nicht als Gerätename, damit er keinem Namen aus DNS widerspricht).
- **Nicht tun:** Antworten ohne Prüfung ihrer Art als Fund nehmen; Folgeabrufe einbauen, deren Ergebnis niemand
  liest; Daten aus einer Antwort die Adresse ihres Absenders überschreiben lassen.
- **Im Code:** `MyNetworkMonitor.Core/Scanning/ScanningMethod_SSDP_UPNP.cs` (`IsOwnLocation`, `ParseDescription`,
  `SSDPDeviceInfo.ToDetail`), `ScanningMethod_ONVIF_IPCam.cs` (`ParseONVIFResponse`), `ScanningMethod_mDNS.cs`
  (`IsAnswer`, `ParseResponse`), `Scanning/Engine/Methods/LegacyScanMethod.cs` (Detail und Dienst UPnP),
  `Support/zzz_DataStructure.cs` (`SSDPDescription`).
- **Abgesichert durch:** `DiscoveryAnswerTests` (Beschreibung, Abruf nur vom Gerät selbst, mehrere Dienstadressen,
  fehlende Dienstadresse, Frage übersprungen und Adresse des Absenders, Anfrage ist keine Antwort, jede
  abgeschnittene Länge).

## Nr. 33 – MAC-Herstellerliste: Hersteller mit Komma im Namen in Anführungszeichen

- **Entdeckt:** 18.11.2026, Version 7.3.0.37 (Bildschirmfotos für die Startseite: nach einem ARP-Scan stand in der
  Spalte VENDOR `"Super Micro Computer, Inc."` statt `Super Micro Computer, Inc.`). Vorhanden mindestens seit Commit
  0a408e3. **Behoben:** 7.3.0.38.
- **Was:** Jeder Hersteller, dessen Name in `mac_vendors.csv` ein Komma enthält (z. B. „Cisco Systems, Inc“,
  „VMware, Inc.“), wurde mit Anführungszeichen angezeigt, in der Suche und im Export so geführt und so im
  gespeicherten Gerätebestand abgelegt. Hersteller ohne Komma waren nicht betroffen.
- **Warum:** `SupportMethods.LoadMacVendors` trennt die Zeilen mit einem regulären Ausdruck an den Kommas außerhalb
  von Anführungszeichen. Das hält das Feld zusammen, lässt aber die Anführungszeichen des CSV-Formats am Wert stehen.
- **Lösung:** `SplitCsvLine` entfernt nach dem Trennen die umschließenden Anführungszeichen und macht verdoppelte
  Anführungszeichen im Feld wieder einfach (RFC 4180, Abschnitt 2). Gespeicherte Bestände mit dem alten Wert
  bekommen den richtigen Namen beim nächsten ARP-Lauf. Verworfen: eine CSV-Bibliothek – für eine Datei mit fünf
  einfachen Spalten ein unnötiges Paket.
- **Nicht tun:** Felder einer CSV-Datei nach dem Trennen ungeprüft als Wert nehmen.
- **Im Code:** `MyNetworkMonitor.Core/Support/SupportMethods.cs` (`SplitCsvLine`, `LoadMacVendors`).
- **Abgesichert durch:** `MacVendorCsvTests` (Hersteller mit Komma, ohne Komma, verdoppeltes Anführungszeichen; mit
  dem alten Stand schlagen zwei der drei Tests fehl).
- **Gegenprobe an echten Geräten (offen):** im echten Netz einen Scan mit „ARP request“ laufen lassen und in der Spalte
  VENDOR Geräte von Herstellern mit Komma im Namen ansehen (z. B. Netzwerkgeräte von „Cisco Systems, Inc“, virtuelle
  Maschinen von „VMware, Inc.“, viele Laptops): Der Name muss ohne Anführungszeichen erscheinen, auch im CSV-Export
  und in der Suche. Ein vorher gespeicherter Bestand zeigt die Anführungszeichen, bis der nächste ARP-Lauf das Gerät
  erneut meldet.

## Nr. 34 – Adressbewertung: IPv4-Dokumentations- und Benchmark-Bereiche galten als global erreichbar

- **Entdeckt:** 18.11.2026, Version 7.3.0.38 (Bildschirmfotos für die Startseite mit einem erfundenen Netz aus den
  Dokumentationsbereichen: in den Befunden 90 Warnungen „Open ports on a globally routable address“, im
  Detailbereich „Global“ an jeder Adresse). **Behoben:** 7.3.0.39.
- **Was:** 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (RFC 5737) und 198.18.0.0/15 (RFC 2544) zählten als global
  erreichbar: Filter „globally reachable“, Befund „Open ports on a globally routable address“ und die Angabe am
  Gerät. Für IPv6 waren die entsprechenden Bereiche (2001:db8::/32, 2001:2::/48) schon richtig ausgenommen.
- **Warum:** `AnalyzeV4` kannte nur Loopback, Broadcast, Link-local, Multicast und die privaten Bereiche; alles andere
  galt als global. Die Ausnahme, die `DetectV6Scope` mit Begründung macht, fehlte für IPv4.
- **Lösung:** `DetectSpecialV4` erkennt die Bereiche (Sonderform `Documentation` bzw. `Benchmarking`), der Bereich wird
  wie bei IPv6 `Unknown` statt `Global` – nach dem IANA IPv4 Special-Purpose Address Registry („Globally Reachable:
  False“). Bewusst nur diese Bereiche: weitere reservierte Bereiche (z. B. 240.0.0.0/4) wären eine eigene Entscheidung.
- **Nicht tun:** eine Regel nur für eine Adressfamilie einbauen, wenn die andere dieselben Fälle hat.
- **Im Code:** `MyNetworkMonitor.Core/Network/IpAddressAnalyzer.cs` (`AnalyzeV4`, `DetectSpecialV4`),
  `Network/IpAddressEnums.cs` (Beschreibung der Sonderformen).
- **Abgesichert durch:** `IpAddressScopeTests` (Dokumentation und Benchmark nicht global, Nachbaradressen weiter global,
  private Adressen; mit dem alten Stand schlagen die fünf IPv4-Fälle fehl).
- **Gegenprobe an echten Geräten (offen):** in einem echten Netz mit privaten Adressen (10.x, 172.16–31.x, 192.168.x)
  muss sich nichts ändern – Befunde, Filter „globally reachable“ und die Angabe an der Adresse wie vor 7.3.0.39. Ein
  Gerät mit öffentlicher IPv4-Adresse (z. B. die WAN-Seite eines Routers, falls im Scan) muss weiter „Global“ zeigen und
  bei offenen Ports den Befund „Open ports on a globally routable address“ auslösen.

## Nr. 35 – 3D-Netzansicht: Netzbeschriftung nur für /24 und /16 richtig

- **Entdeckt:** 18.11.2026, Version 7.3.0.39 (Bildschirmfotos für die Startseite: vier Bereiche aus /27-Netzen trugen
  alle die Beschriftung „192.0.2.0/24“). **Behoben:** 7.3.0.40.
- **Was:** Jede Gerätegruppe bekommt in der Netzansicht eine Beschriftung mit ihrem Netz. Die Seite las es aus den
  Adressen der Geräte und kannte nur zwei Fälle: alle im selben /24, sonst alle im selben /16. Kleinere Netze
  (/25 … /30) erschienen als das umgebende /24, ein /23 als /16 – in Firmennetzen häufig, und die Angabe sah
  verlässlich aus.
- **Warum:** Die Seite kannte die eingestellten Bereiche nicht, nur die Geräte; aus einzelnen Adressen lässt sich die
  Netzgröße nicht ablesen.
- **Lösung:** Das Hauptfenster gibt je Bereich (IPv4, von–bis) eine Beschriftung mit: `TopologyGraph.DescribeRange`
  nennt das Netz in CIDR-Schreibweise, wenn der Bereich genau dessen Hosts umfasst (mit oder ohne Netz- und
  Broadcast-Adresse), sonst den Bereich selbst („a – b“). Gruppen ohne eingestellten Bereich behalten die bisherige
  Schätzung. Verworfen: die Schätzung über das gemeinsame Bitpräfix der Geräte – sie liefert je nach belegten
  Adressen ein zu kleines Netz.
- **Nicht tun:** eine Netzgröße aus den gefundenen Adressen ableiten und als Tatsache anzeigen.
- **Im Code:** `MyNetworkMonitor.Core/Services/TopologyGraph.cs` (`DescribeRange`, `BuildGraphJson` mit
  `groupNetworks`, Feld `network` am Knoten, `buildNetLabels` im Seitenskript), `Services/TopologyLauncher.cs`,
  `MyNetworkMonitor.Avalonia/Views/ShellView.axaml.cs` (Zeichnen der Netzansicht).
- **Abgesichert durch:** `TopologyNetworkLabelTests` (/27, /24, /23, /25, Teilbereich, Einzeladresse, verkehrte
  Reihenfolge, IPv6, leer; Netz im erzeugten Graphen).
- **Gegenprobe an echten Geräten (offen):** im Firmennetz mit Bereichen, die kein /24 sind (z. B. ein /23 oder ein
  Teilnetz /26), „Topology → Network topo → Draw“: Jede Gruppe muss ihr eingestelltes Netz zeigen (z. B. „…/23“),
  ein Bereich, der kein ganzes Netz ist, „erste – letzte Adresse“. Im Heimnetz (ein /24) muss die Beschriftung wie
  bisher „…/24“ lauten. Geräte ohne passenden Bereich (z. B. aus einer Zielliste) behalten die alte Schätzung.

## Nr. 36 – Gerätebestand: gleiche MAC in zwei Netzen wurde zu einem Gerät

- **Entdeckt:** 18.11.2026, Version 7.3.0.40 (Hinweis des Nutzers beim Erstellen der Startseite: die 3D-Ansicht zeigte
  früher rote „same MAC“-Kanten zwischen Netzen, damit wurden doppelte MACs und falsch abgeglichene DNS-Server
  gefunden; im nachgebauten Netz mit geklonter VM nachgestellt). Vorhanden seit dem Gerätemodell (Commit bfeb44c,
  August 2026); vorher war jede Adresse eine eigene Zeile mit eigenem Knoten. **Behoben (Zuordnung):** 7.3.0.42;
  **Befunde:** 7.3.0.43; **3D-Ansicht:** 7.3.0.44 (rote „same MAC“-Kanten zwischen Geräten verschiedener Netze und zu
  weiteren IPv4-Adressen eines Geräts, jeder Knoten in seinem Netz; `TopologyGraph.BuildGraphJson` mit
  `TopologyRange`, Tests in `TopologyNetworkLabelTests`).
- **Was:** Zwei Geräte mit derselben MAC in verschiedenen Bereichen (geklonte VM, Router mit einer MAC auf mehreren
  VLANs, über einen Satelliten aus einem anderen Segment gemeldet) wurden zu einem Gerät zusammengeführt: der zweite
  Name ging verloren, der Bereich sprang auf den zuletzt gemeldeten, die Tabelle zeigte nur die erste Adresse, die
  3D-Ansicht einen Knoten ohne Kante. Satelliten-Ergebnisse gingen über dieselbe Regel in Geräten anderer Netze auf.
- **Warum:** `DeviceStore` behandelte die MAC netzübergreifend als harte Kennung (`_byMac` mit einem Gerät je MAC,
  `FindCandidates`, `FindExisting`). Ein Netzbezug fehlte ganz: Beobachtungen und Adressen kannten nur den frei
  wählbaren Bereichsnamen.
- **Lösung:** Jede Adresse kennt ihr Netz (7.3.0.41, `NetworkIds`); eine MAC verbindet nur Geräte desselben Netzes
  (`SameNetworkOrUnknown`), der MAC-Index hält mehrere Geräte je MAC, gleiche MAC in verschiedenen bekannten Netzen ist
  ein Widerspruch (`ContradictsObservation`, `Contradicts`). Unbekanntes Netz (alte Bestände, Ziellisten) trennt nicht
  – so verhalten sich ältere Daten und das Nachscannen wie bisher. Satelliten-Ergebnisse bekommen vor dem Übernehmen
  die Bereiche der Zentrale (`NetworkIds.AdoptSatelliteResult`), sonst wäre ein von beiden gesehenes Gerät doppelt.
  Virtuelle Router- und Cluster-MACs (VRRP, HSRP, Windows NLB) zählen nie als Kennung (`IsIdentifying`), sonst
  verschmölzen die beiden Router eines redundanten Paars. Verworfen: Geräte je IP-Adresse trennen – jedes IPv6-Gerät
  zerfiele in viele Einträge, jede neue DHCP-Adresse erschiene als zweites Gerät.
- **Befunde (7.3.0.43):** gleiche MAC in einem anderen Netz – Warnung, wenn beide im selben Lauf antworten, sonst
  Hinweis „wohl umgezogen“; eine MAC für mehrere IPv4-Adressen im selben Netz – Warnung mit den möglichen Ursachen
  (Zusatzadresse, alte DHCP-Adresse, Repeater/Bridge, ARP-Spoofing) und dem Gateway, falls darunter; kritisch als
  „Suspected ARP spoofing“ nur, wenn eine dieser Adressen zugleich ein anderes Gerät mit eigener MAC hat. Bewusst
  nicht kritisch allein wegen des Gateways: ein Router mit einer zweiten Adresse auf derselben Schnittstelle sieht
  genauso aus und würde dauerhaft Alarm schlagen.
- **Messung (18.11.2026, A/B gegen den Stand vor 7.3.0.41):** 5000 Geräte mit IPv4, IPv6 und Nachscan (15 000
  Beobachtungen) 54 → 87 ms, Dublettenprüfung 6 → 9 ms (jeweils bester von fünf Läufen). Mehr Arbeit durch die
  Netzprüfung je Adresse, für einen Scan ohne Belang.
- **Nicht tun:** eine Kennung ohne ihren Geltungsbereich verwenden; eine MAC gilt nur im Segment, in dem sie gesehen
  wurde.
- **Im Code:** `MyNetworkMonitor.Core/Model/DeviceStore.cs` (`FindCandidates`, `ContradictsObservation`, `Contradicts`,
  `SameNetworkOrUnknown`, `IsIdentifying`, `WithMac`, `Reindex`, `RepointIndexes`, `FindExisting`),
  `Model/NetworkIds.cs` (`AdoptSatelliteResult`), `ViewModels/ShellViewModel.cs` (`MergeSatelliteResult`).
- **Abgesichert durch:** `SameMacTests` (zwei Netze, gleiches Netz mit anderer IP, IPv6, Ziellisten ohne Netz,
  abgeleitete MAC, virtuelle Router-MACs, Speichern und Laden, Satelliten-Ergebnisse); `DeviceStoreTests` für das
  Verhalten ohne bekanntes Netz.
- **Gegenprobe an echten Geräten (offen):** (1) Ein Router oder L3-Switch mit derselben MAC in mehreren VLANs, über
  Satelliten gescannt: je VLAN ein Eintrag mit dem Namen des Bereichs, nicht einer. (2) Ein Gerät, das von der
  Zentrale und vom Satelliten gesehen wird (Satellit vorher getrennt, Bereich von hier gescannt): danach ein Eintrag.
  (3) Ein VRRP- oder HSRP-Paar: zwei Router plus die virtuelle Adresse, nicht verschmolzen. (4) Ein Bestand von vor
  7.3.0.41 lädt vollständig und ordnet sich nach dem nächsten Scan richtig.

## Nr. 37 – IPv6: aus EUI-64 abgeleitete MAC wurde als harte Kennung gesetzt

- **Entdeckt:** 18.11.2026, Version 7.3.0.41 (Bestandsaufnahme für Nr. 36). **Behoben:** 7.3.0.42.
- **Was:** Die IPv6-Verfahren meldeten eine aus dem Interface-Identifier abgeleitete MAC als harte `Mac` – auch für
  geroutete globale Adressen von Geräten, die gar nicht im eigenen Segment stehen. So konnte sie Geräte anderer Netze
  zusammenführen oder einer echten, per ARP gesehenen MAC widersprechen.
- **Warum:** `Mac = mac ?? info.DerivedMac` in `Ipv6MethodBase.ReportAddress` und `entry.Mac ?? info.DerivedMac` in
  der Nachbartabelle – gegen die Regel im Gerätebestand, nach der eine abgeleitete MAC nur verbinden, nie trennen darf.
- **Lösung:** Hart ist nur die MAC, die im Segment gesehen wurde; die abgeleitete bleibt an der Adresse
  (`DerivedMac`) und verbindet weich, und nur im selben Netz.
- **Nicht tun:** einen erschlossenen Wert wie einen gemessenen behandeln.
- **Im Code:** `Scanning/Engine/Methods/Ipv6MethodBase.cs` (`ReportAddress`), `Ipv6NeighborCacheScanMethod.cs`.
- **Abgesichert durch:** `SameMacTests.DerivedMacConnectsOnlyWithinTheNetwork`, `DeviceStoreTests.Eui64AddressJoinsTheDeviceWithItsMac`.
- **Gegenprobe an echten Geräten (offen):** IPv6-Verfahren im echten Netz: Geräte mit EUI-64-Adressen erscheinen wie
  bisher bei ihrem per ARP gefundenen Eintrag, nicht als eigene Einträge.

## Nr. 38 – SSDP überschrieb den Bereichsnamen mit „not specified“

- **Entdeckt:** 18.11.2026, Version 7.3.0.41 (Bestandsaufnahme für Nr. 36). **Behoben:** 7.3.0.42.
- **Was:** Ein Gerät, das per SSDP antwortete, stand danach in der Tabelle unter dem Bereich „not specified“ statt
  unter seinem Bereich.
- **Warum:** `LegacyScanMethod.ReportResult` nahm zuerst den Wert des Moduls (`IPGroupDescription`), dann den des
  Bereichs; das SSDP-Modul setzt für jeden Fund den festen Text „not specified“.
- **Lösung:** Der Bereich des Ziels hat Vorrang; der Wert des Moduls gilt nur für Funde außerhalb der Ziele.
- **Nicht tun:** Platzhaltertexte als Daten weiterreichen.
- **Im Code:** `Scanning/Engine/Methods/LegacyScanMethod.cs` (`ReportResult`).
- **Abgesichert durch:** keinen automatischen Test (der Weg läuft über die Netzwerkmodule).
- **Gegenprobe an echten Geräten (offen):** Scan mit „SSDP / UPnP“ im echten Netz: UPnP-Geräte (Drucker, NAS,
  Fernseher) stehen unter ihrem Bereich.

## Nr. 39 – Befunde: Titel und Schweregrad galten für alle Zeilen eines Geräts

- **Entdeckt:** 18.11.2026, Version 7.3.0.40 (beim Schreiben der Tests `DuplicateDetectorTests`: ein Gerät mit doppelter
  IP und doppeltem Namen ergab zwei kritische Befunde „Duplicate address“). **Behoben:** 7.3.0.43.
- **Was:** Jede Zeile in den Befunden zu einem Gerät trug Titel und Schweregrad seines schwersten Konflikts: die Zeile
  zum doppelten Namen hieß „Duplicate address“ und war kritisch, die zu mehreren IPv4-Adressen ebenso.
- **Warum:** `FindingsViewModel.CollectDuplicates` teilte den Gesamttext `ConflictDetails` in Zeilen, wusste aber nicht
  mehr, welche Zeile zu welchem Konflikt gehört, und nahm `TitleFor(device.Conflicts)` für alle.
- **Lösung:** Die Dublettenprüfung legt jede Zeile mit ihrer Art ab (`ConflictReason`, `Device.ConflictReasons`); die
  Befundliste gibt jeder Zeile Titel und Schweregrad ihrer Art (`TitleOf`, `SeverityOf`). `ConflictDetails` bleibt
  für Tooltip und Detailbereich.
- **Nicht tun:** Information, die man später braucht, in einen Text zusammenfassen und daraus wieder herauslesen.
- **Im Code:** `Model/DuplicateDetector.cs` (`ConflictReason`, `Analyze`), `Model/Device.cs` (`ConflictReasons`),
  `ViewModels/FindingsViewModel.cs` (`CollectDuplicates`, `TitleOf`, `SeverityOf`).
- **Abgesichert durch:** `DuplicateDetectorTests.EachLineOfADeviceKeepsItsOwnTitle` (schlägt mit dem alten Stand fehl),
  `EachKindOfDuplicateBecomesAFinding`.
- **Gegenprobe an echten Geräten (offen):** keine nötig – reine Auswertung; im echten Netz bei einem Gerät mit mehreren
  Konflikten die Befundliste ansehen.

## Nr. 40 – Satellit: einzelnes „Connect“ verband nach dem Neustart nicht wieder

- **Entdeckt:** 18.11.2026, Version 7.3.0.44 (Prüfung einer Beobachtung aus dem nachgebauten Netz: nach Neustart blieb
  ein Satellit getrennt; nachgestellt – mit „Connect all“ verbindet er sich nach dem Neustart, mit „Connect“ nicht).
  **Behoben:** 7.3.0.45.
- **Was:** Wer in der Satelliten-Ansicht einen Hauptscanner auswählte und „Connect“ drückte, war verbunden – nach einem
  Neustart des Programms aber nicht mehr, obwohl der Eintrag eingeschaltet („On“) war.
- **Warum:** Beim Start verbindet das Programm nur, wenn der Satellitenbetrieb eingeschaltet ist
  (`SatelliteModeEnabled`). Diesen Schalter setzte nur „Connect all“, der Einzelknopf rief nur den Befehl auf.
- **Lösung:** Auch der Einzelknopf setzt den Schalter (`bt_SatelliteConnectOne_Click`) und verbindet dann.
- **Nicht tun:** zwei Knöpfe derselben Absicht unterschiedlich viel Zustand ändern lassen.
- **Im Code:** `MyNetworkMonitor.Avalonia/Views/ShellView.axaml(.cs)` (`bt_SatelliteConnectOne_Click`, `StartSatelliteLink`).
- **Abgesichert durch:** keinen automatischen Test (Oberfläche); im Nachbau geprüft, dass „Connect all“ nach dem
  Neustart verbindet.
- **Gegenprobe an echten Geräten (offen):** Satellit über „Connect“ (einzeln) verbinden, Programm neu starten – er
  verbindet sich selbst.

## Nr. 41 – Gerätetabelle: Gerätezahl im Bereichsfilter klebte am Namen

- **Entdeckt:** 18.11.2026, Version 7.3.0.39 (Bildschirmfotos für die Startseite: „Außenlager12 (12 up)“).
  **Behoben:** 7.3.0.45.
- **Was:** In der Bereichsauswahl über der Tabelle stand die Zahl der Geräte ohne Abstand direkt hinter dem Namen.
- **Warum:** Jede Zeile ist ein Raster „Name | Zahl“, die Checkbox streckte ihren Inhalt aber nicht über die Breite;
  das Raster wurde nur so breit wie sein Text. Bei der Dienstauswahl war das schon behoben, beim Bereichsfilter nicht.
- **Lösung:** Wie in der Dienstauswahl: Checkbox und Raster strecken sich, die Zahl steht rechtsbündig mit Abstand.
- **Nicht tun:** eine Korrektur nur an einer von zwei gleich gebauten Stellen machen.
- **Im Code:** `MyNetworkMonitor.Avalonia/Views/ShellView.axaml.cs` (`BuildScopeFacets`, vgl. `BuildServiceFacets`).
- **Abgesichert durch:** Sichtprüfung im Nachbau (Zahlen rechtsbündig).
- **Gegenprobe an echten Geräten (offen):** keine nötig.

## Nr. 42 – Statuszeile: „satellites are scanning“ blieb nach den Ergebnissen stehen

- **Entdeckt:** 18.11.2026, Version 7.3.0.40 (nachgebautes Netz mit zwei Satelliten; nachgestellt mit 7.3.0.44: Satellit
  nach 10 s fertig, die Zeile sagte minutenlang „2 satellites are scanning“). **Behoben:** 7.3.0.45.
- **Was:** Nach einem Scan mit Satelliten blieb in der Statuszeile „N satellites are scanning“ stehen, auch wenn alle
  geliefert oder einen Fehler gemeldet hatten.
- **Warum:** Die Notiz wurde beim Verschicken der Aufträge einmal gesetzt und nie gelöscht. Ein Ergebnis überschrieb
  zwar die Statuszeile; endete danach der eigene Scan der Zentrale (der meist länger dauert), setzte er die alte Notiz
  wieder dahinter. Fehler, „besetzt“ und Abbruch eines Satelliten erreichten die Statuszeile gar nicht.
- **Lösung:** `SatelliteRunTracker` führt je Lauf, welche Satelliten scannen, welche geliefert haben, welche nicht
  verbunden waren und welche mit Fehler endeten; die Statuszeile setzt sich bei jedem Schreiben daraus zusammen.
  Fehler, „besetzt“ und Abbruch meldet der Satelliten-Editor als `JobFailed` an die Zentrale.
- **Nicht tun:** einen Zwischenstand als festen Text ablegen, wenn andere ihn später neu schreiben.
- **Im Code:** `Core/SatelliteLink/SatelliteRunTracker.cs`, `ViewModels/ShellViewModel.cs` (`DispatchToSatellitesAsync`,
  `MergeSatelliteResult`, `WithSatelliteNotes`), `ViewModels/SatelliteEditorViewModel.cs` (`JobFailed`).
- **Abgesichert durch:** `SatelliteResultTests` (Notiz bis zum letzten Ergebnis, Fehler, Abbruch, Zurücksetzen).
- **Gegenprobe an echten Geräten (offen):** Scan mit Satelliten, deren Bereich kleiner ist als der der Zentrale: am Ende
  steht „… reported N device(s)“ für jeden Satelliten; einen Satelliten während des Auftrags stoppen – die Zeile nennt
  den Abbruch.

## Nr. 43 – Satelliten: gemeldete Geräte erschienen als nicht erreichbar

- **Entdeckt:** 18.11.2026, Version 7.3.0.44 (beim Nachstellen von Nr. 42: Geräte eines Satelliten-Bereichs grau,
  „reachable“ zählte nur die Geräte der Zentrale). **Behoben:** 7.3.0.45.
- **Was:** Alle Geräte, die ein Satellit gerade gefunden hatte, standen in der Zentrale als „antwortet nicht“ – grauer
  Punkt, nicht in „reachable“, nicht im Filter „only reachable“.
- **Warum:** Das Satelliten-Ergebnis läuft durch dasselbe Format wie die gespeicherte Bestandsdatei
  (`DeviceStoreFile.ToJson`/`FromJson`). Dort wird „antwortet gerade“ bewusst weder gespeichert noch geladen – ein Zustand
  von gestern sagt nichts über heute. Für ein frisches Ergebnis gilt das nicht.
- **Lösung:** Adressen tragen im Format ein optionales `Responding`; nur `FromJson(…, keepResponding: true)` übernimmt
  es, und nur für Satelliten-Ergebnisse. Das Laden der Bestandsdatei bleibt dabei: alles startet als „antwortet nicht“.
  Ältere Satelliten senden das Feld nicht – ihre Geräte erscheinen wie bisher grau.
- **Nicht tun:** ein Format für zwei Zwecke verwenden, ohne zu prüfen, ob jede Regel für beide gilt.
- **Im Code:** `Persistence/DeviceStoreFile.cs` (`FromJson`, `ToDevice`, `AddressRecord.Responding`),
  `ViewModels/ShellViewModel.cs` (`MergeSatelliteResult`).
- **Abgesichert durch:** `SatelliteResultTests` (Ergebnis behält Erreichbarkeit, gespeicherter Bestand nie, Übernahme in
  den Bestand der Zentrale).
- **Gegenprobe an echten Geräten (offen):** Zentrale und Satellit auf 7.3.0.45: nach einem Scan sind die Geräte des
  Satelliten-Bereichs grün und zählen in „reachable“.

## Nr. 44 – Statuszeile: Satellit ohne Verbindung galt weiter als „scanning“

- **Entdeckt:** 18.11.2026, Version 7.3.0.45 (Durchlauf des Satellitenbetriebs im Nachbau: Satellit mitten im
  Auftrag beendet – „Offline“ in der Liste, aber „Satellite "…" is scanning“ in der Statuszeile). **Behoben:** 7.3.0.46.
- **Was:** Fiel die Verbindung eines Satelliten während seines Auftrags weg, sagte die Statuszeile weiter, er scanne.
- **Warum:** Die Statusführung aus Nr. 42 kannte Ergebnis und Fehlermeldung des Satelliten, aber nicht den Abbruch der
  Verbindung: der Satelliten-Editor räumte nur den Fortschritt in der Liste auf.
- **Lösung:** Beim Abbruch einer Verbindung mit laufendem Auftrag meldet der Editor `JobFailed` mit „the connection was
  lost during the job - its ranges were not fully scanned“.
- **Nicht tun:** nur die Antworten einer Gegenstelle auswerten und ihr Verschwinden vergessen.
- **Im Code:** `ViewModels/SatelliteEditorViewModel.cs` (Ereignis `Disconnected` des Listeners).
- **Abgesichert durch:** Durchlauf im Nachbau (`docs/PRUEFUNGEN.md`, Satellitenbetrieb); kein Test ohne Netzverbindung.
- **Gegenprobe an echten Geräten (offen):** Satelliten während eines langen Auftrags trennen (Netzkabel, Dienst
  stoppen) – die Statuszeile nennt den Abbruch.

## Nr. 45 – Satelliten-Ansicht: „Offline since“ zeigte die Zeit der Verbindung, Herkunft als `::ffff:`-Adresse

- **Entdeckt:** 18.11.2026, Version 7.3.0.45 (Durchlauf im Nachbau: Satellit um 23:50 beendet, angezeigt „Offline since
  23:41“ – der Zeitpunkt des Verbindens; „Came from [::ffff:198.51.100.20]:41604“). **Behoben:** 7.3.0.46.
- **Was:** Ein getrennter Satellit stand mit der Uhrzeit seiner Anmeldung als „offline seit“; „Last seen“ blieb während
  der ganzen Verbindung bei der Anmeldung. Die Herkunft eines IPv4-Satelliten stand in der IPv6-Schreibweise.
- **Warum:** `LastSeen` wurde nur bei der Anmeldung gesetzt. Der Listener nimmt IPv4 und IPv6 auf einem Socket an,
  IPv4-Gegenstellen erscheinen dort als IPv4-gemappte IPv6-Adressen.
- **Lösung:** `LastSeen` auch bei Fortschritt, Ergebnis und Abbruch der Verbindung; die Herkunft wird als IPv4-Adresse
  angezeigt, wenn sie eine ist (`SatelliteListener.Describe`).
- **Nicht tun:** einen Zeitstempel „zuletzt gesehen“ nur an einer Stelle pflegen.
- **Im Code:** `ViewModels/SatelliteEditorViewModel.cs` (`Disconnected`, `ProgressReported`, `ResultReceived`),
  `SatelliteLink/SatelliteListener.cs` (`Describe`).
- **Abgesichert durch:** `SatelliteEndpointTests`; Zeitpunkt im Durchlauf geprüft.
- **Gegenprobe an echten Geräten (offen):** keine nötig.

## Nr. 46 – ARP: der scannende Rechner selbst stand ohne MAC und Hersteller

- **Entdeckt:** 18.11.2026, Version 7.3.0.45 (Durchlauf des Satellitenbetriebs im Nachbau: die Zeile des Satelliten in
  der Zentrale ohne MAC und Hersteller). **Behoben:** 7.3.0.47.
- **Was:** Die eigene Adresse des scannenden Rechners antwortete auf Ping, bekam aber keine MAC – bei einem Satelliten
  besonders auffällig, denn nur er sieht sein Segment, niemand sonst kann die MAC nachliefern. Auf der Zentrale ebenso,
  wenn ihre Adresse in einem Bereich liegt.
- **Warum:** Die MAC kommt aus ARP bzw. der Nachbartabelle (`ip neigh`); ein Rechner führt sich dort nicht selbst.
- **Lösung:** Das ARP-Verfahren nimmt für eine eigene IPv4-Adresse die MAC des Netzadapters, der sie trägt
  (`NetworkInterface.GetPhysicalAddress`), und fragt erst sonst das Netz. An einer Stelle für alle Plattformen, statt in
  jedem ARP-Anbieter. Adapter ohne MAC oder mit Nullen (Loopback, Tunnel) liefern nichts.
- **Nicht tun:** die eigene MAC beim Satelliten-Ergebnis von Hand nachtragen – dann fehlt sie auf der Zentrale weiter.
- **Im Code:** `Scanning/ScanningMethod_ARP.cs` (`OwnMacOf`, `OwnAdapterAddresses`, Aufruf in `ArpRequestTask`).
- **Abgesichert durch:** `OwnMacTests`; Nachbau mit zwei Satelliten (beide mit MAC und Hersteller in der Zentrale).
- **Gegenprobe an echten Geräten (offen):** Satellit unter Windows und Linux im echten Netz – MAC und Hersteller in
  seiner Zeile stimmen mit dem Adapter überein; ein Rechner mit mehreren Adaptern zeigt je Adresse die MAC ihres Adapters.
