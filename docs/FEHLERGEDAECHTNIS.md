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
