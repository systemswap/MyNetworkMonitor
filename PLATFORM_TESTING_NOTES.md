# Plattform-Testnotizen

Merkzettel für offene Tests, die nur auf der jeweils anderen Plattform
nachgeholt werden können. Wird von Claude gepflegt: neue Punkte kommen rein,
wenn auf einer Plattform entwickelt/getestet wurde und die andere noch
absteht; erledigte Punkte wandern nach unten in den Verlauf statt gelöscht zu
werden, damit nachvollziehbar bleibt, was wann geprüft wurde.

## Offen: braucht Test unter Windows

- **Firmennetz-Erkennung (`WindowsEnterpriseEnvironment`, Version 5.1.0.31, 2026-08-09).**
  `IsCompanyNetwork()` wurde auf `ActiveDirectoryDetector.DomainControllerReachable()`
  umgestellt (DNS-SRV-Abfrage `_ldap._tcp.dc._msdcs.<domain>` statt IP-Bereichs-Heuristik).
  Released und live auf GitHub (v5.1.0.31). Auf Linux gegen ein FRITZ!Box-Heimnetz
  getestet: korrekt `false`, ~75ms. Unter Windows noch nicht getestet:
  - Liefert `false` in einem normalen Windows-Heimnetz (auch mit Hyper-V/WSL2/VPN-Adaptern aktiv)?
  - Liefert `true` in einem echten AD-Netz?
  - Die Adapter-Filterliste (`docker`, `veth`, `virbr`, `br-`, `vmnet`, `vboxnet`,
    `tun`, `tap`, `wg`, `utun`, `zt`) ist Linux-lastig entstanden - Windows-typische
    virtuelle Adapternamen (Hyper-V "vEthernet (...)", Cisco AnyConnect, Tailscale,
    OpenVPN "TAP-Windows Adapter") sollten stichprobenartig gegengeprüft werden.
  - Siehe `MyNetworkMonitor.Core/Services/ActiveDirectoryDetector.cs`.

- **Diensterkennungs- und Discovery-Ueberarbeitung (Version 6.0.0.0, 2026-08-10).**
  Grosse Ueberarbeitung nach einem vollstaendigen Review aller IPv4-Scan-Verfahren
  (ARP, Ping, TCP/UDP-Portscan, Diensterkennung, SMB, mDNS, SSDP, ONVIF, NetBIOS,
  Reverse-DNS) - jeder einzelne Fix wurde live gegen echte Ziele in diesem Heimnetz
  getestet (Samba, echter SSH-/FTP-Server, echte ONVIF-Kamera, echter DNS-Server),
  aber ausschliesslich unter Linux. Am wichtigsten fuer einen Windows-Test:
  - **mDNS band vorher an die eigene Unicast-Adresse statt an `IPAddress.Any`** -
    unter Linux nachweislich der Grund, warum niemals ein Geraet gefunden wurde
    (0 statt 14 Treffer im Test). Windows' Netzwerkstapel behandelt das teils
    anders als Linux; moeglich, dass die alte Bindung dort zufaellig funktionierte
    und die neue (jetzt auch dort verwendete) Bindung an `IPAddress.Any` etwas
    anderes bewirkt. Unbedingt gegenpruefen, ob mDNS unter Windows weiterhin
    Geraete findet.
  - **UDP-Portscan wurde komplett neu geschrieben** (vorher fragte er nur die
    eigenen lokalen UDP-Listener ab, nie das Ziel). Die neue "zu"-Erkennung
    stuetzt sich auf `SocketException` mit `ConnectionReset`/`ConnectionRefused`
    bei einem verbundenen UDP-Socket, wenn ein ICMP-Port-unreachable ankommt -
    unter Linux live bestaetigt (echter Listener gefunden, echter geschlossener
    Port korrekt ausgeschlossen). Windows' Socket-Stack hat hier historisch
    Eigenheiten (`SIO_UDP_CONNRESET`); sollte gegengeprueft werden.
  - `SocketOptionName.MulticastInterface` (SSDP/ONVIF, jetzt mit `byte[]`-Adresse
    gesetzt, um das ausgewaehlte Interface zu respektieren) ist eine
    Standard-.NET-Socket-Option und sollte plattformneutral funktionieren, aber
    ungetestet unter Windows.
  - Alles Uebrige (ARP-Nebenlaeufigkeitsgrenze, TCP-Portscan-Grenze,
    Diensterkennung/SMB-Validierung, NetBIOS `Connect()` vor `Send()`,
    Reverse-DNS-Zeitbudget) ist reine .NET-Logik ohne plattformspezifische
    Sonderfaelle - geringeres Risiko, aber ebenfalls nie unter Windows gelaufen.
  - `WindowsArpProvider.cs` (Kill bei Abbruch, robustere `arp -a`-Zeilenpruefung)
    liess sich auf diesem Linux-Rechner nicht einmal bauen (Windows-only TFM) -
    rein durch Lesen geprueft, nicht kompiliert.

## Offen: braucht Test unter Linux

- **IPv6 Router-Advertisement/MLD Live-Capture (2026-08-09).**
  Mit `CAP_NET_RAW` öffnet der Rohsocket korrekt, empfängt aber im Test nie ein
  Paket - auch nicht nach expliziter Router Solicitation. Kernel-Zähler
  (`/proc/net/snmp6`) deuten darauf hin, dass die FRITZ!Box nach vielen
  Testläufen in derselben Sitzung nicht mehr geantwortet hat (Rate-Limiting),
  nicht auf einen Fehler im Code. Sauberer Einzeltest (eine Solicitation,
  ausreichend Abstand zur letzten) steht noch aus.
  Details: siehe Claude-Memory `ipv6_ra_mld_raw_capture_untested.md`.

---

## Verlauf (erledigt)

- 2026-08-10: Reverse-DNS (IP -> Hostname) noch einmal geprueft, Version
  6.0.0.1. Kette IPToScan -> ScanningMethod_ReverseLookupToHostAndAlieases ->
  ReverseLookupScanMethod -> DeviceObservation.HostName ist die einzige Quelle
  fuer `Device.HostName` (kein Ueberschreiben durch NetBIOS oder mDNS, die
  haben eigene Felder) - kein Konflikt zwischen Verfahren. Der `null`-Callback
  bei fehlendem PTR-Eintrag wird von `ReverseLookupScanMethod` bereits sauber
  abgefangen. Gefunden und live bestaetigt: die Host/Domain-Trennung griff
  erst ab drei Labels (`Count > 2`), ein zweiteiliger PTR-Name wie
  "fritz.box" landete komplett unaufgeteilt im HostName-Feld mit leerer
  Domain - reproduzierbar an der eigenen FRITZ!Box (192.168.178.1 ->
  "fritz.box") und an 8.8.8.8 (-> "dns.google"). Schwelle auf `Count > 1`
  korrigiert und gegen alle vier lokalen Geraete, IPv6 (2001:4860:4860::8888)
  und den "kein PTR"-Fall erneut getestet - jetzt ueberall sauber getrennt.

- 2026-08-10: Zweiter, schwerwiegenderer Reverse-DNS-Fehler gefunden und
  behoben, Version 6.0.0.2 - der eigentliche Grund, warum Hostnamen bei einem
  Scan des ganzen Netzes ueberwiegend nicht ankamen (Nutzerbericht: "192.168.178.11
  hat onvif, aber in der Tabelle steht die IP"). Zwei Fehler zusammen:
  1) Die Nebenlaeufigkeit lag bei 50 gleichzeitigen PTR-Abfragen. Live an
     192.168.178.0/24 (ca. 33 echte Geraete) gemessen: bei 50 gleichzeitig kamen
     nur 4 Treffer zurueck, weil der lokale DNS-Server (laut `resolvectl` das NAS,
     dort laeuft offenbar Pi-hole - siehe "pi-hole.fritz.box" unter den
     Testergebnissen) unter dem Burst die meisten UDP-Antworten verliert.
  2) Der aeussere Abbruch (`CancelAfter`) nutzte dieselbe Zeitspanne wie der
     interne Timeout je Versuch - die konfigurierte Wiederholung des DNS-Clients
     kam dadurch nie zum Zug, sie wurde faktisch schon nach dem ersten
     Fehlschlag abgewuergt.
  Fix: Nebenlaeufigkeit auf 8 gesenkt, Timeout je Versuch auf 1s mit 3
  Wiederholungen, aeusseres Zeitbudget passend dazu vergroessert (Timeout *
  (Retries+1) + Puffer). Live-Ergebnis: 32 von 254 Adressen aufgeloest (=
  praktisch alle real vorhandenen Geraete) in 37 Sekunden statt vorher 4 in
  10 Sekunden - unter anderem korrekt 192.168.178.11 -> Pixel-9-Pro-TM.fritz.box.
  Reine .NET-Logik, kein Linux/Windows-Unterschied zu erwarten, aber wie immer
  nur unter Linux getestet.

- 2026-08-10: Nutzerwunsch nach dem obigen Fix - kein Umweg mehr ueber den
  OS-Resolver/-Cache, die Abfrage soll direkt beim DNS-Server ankommen,
  Version 6.0.0.3. Dabei aufgefallen: der Fix von eben griff bei fehlendem
  eigenen DNS-Server im Scope automatisch auf den vom System konfigurierten
  Resolver zurueck (DnsClient ohne eigene Serverangabe liest `/etc/resolv.conf`)
  - unter Linux mit systemd-resolved also `127.0.0.53`, ein weiterer lokaler
    Cache/Stub, exakt das, was der Nutzer nicht wollte. Live verglichen: direkt
  gegen die FritzBox (Gateway) gefragt kamen alle 32 Geraete in 23-60
  Millisekunden zurueck, direkt gegen das NAS/Pi-hole (den vom System
  eigentlich konfigurierten Server) dagegen nur 21-32 in 13-17 Sekunden - die
  FritzBox ist fuer den `fritz.box`-Namensraum selbst autoritativ, das NAS muss
  erst dorthin weiterleiten. Fix: `LegacyScanMethod.BuildTargets` traegt jetzt,
  wenn im Scope kein eigener DNS-Server gesetzt ist, automatisch die
  IPv4-Gateway-Adresse des scannenden Interfaces als Server ein (kein
  Rueckfall auf den System-Resolver mehr). Voll durch die Engine
  end-zu-Ende getestet (ScanScope ohne DnsServers, Kind=NetworkInterface):
  254 Adressen, 32 Treffer, 82 Millisekunden gesamt. Setzt voraus, dass das
  Gateway selbst DNS beantwortet - bei den meisten Heimroutern (FritzBox &
  Co.) der Fall; wo nicht, bleibt die Adresse einfach ohne PTR-Ergebnis, kein
  weiterer automatischer Rueckfall. Ein eigener DNS-Server im Scope (Feld
  "DNS-Server") sticht diesen Automatismus weiterhin.

- 2026-08-10: Denselben Umbau (direkt zum DNS-Server statt ueber den
  System-Resolver) auch fuer die Vorwaerts-Aufloesung (Hostname -> IP) in
  `ScanningMethod_LookUp.cs` gemacht, Version 6.0.0.4. Nutzte bisher
  `System.Net.Dns.GetHostEntryAsync`, also denselben System-Resolver-Umweg wie
  vorher die Rueckwaertsaufloesung. Jetzt derselbe DnsClient-Ansatz mit
  Gateway-Fallback wie bei ReverseLookup (der Automatismus in
  `LegacyScanMethod.BuildTargets` gilt fuer beide, da beide dieselbe
  `IPToScan.DNSServerList` bekommen). Live end-zu-Ende getestet: Reverse-Lookup
  fuellt den Store mit 32 Hostnamen in 78ms, direkt darauf Forward-Lookup
  ueber alle 254 Ziele in 18ms - alle Namen loesen korrekt zur passenden IP
  zurueck auf. Die separate `nsLookup(string)`-Methode (nur von den
  Legacy-Oberflaechen MainWindowView/WPF genutzt, nicht vom aktiven ShellView)
  bewusst unveraendert gelassen - ohne IPToScan/Scope hat sie keinen DNS-Server
  zur Hand, den man stattdessen nehmen koennte.

- 2026-08-09: Sechs IPv6-Suchverfahren (Version 5.1.0.30, Commit a55962a - Hinweis:
  Hash am 2026-08-09 abends durch History-Rewrite geändert, alte Referenz 4d5f73d
  ist ungültig) unter Linux getestet - vier von sechs (neighborcache, multicastping,
  routeradvertisement-Fallback, eui64) funktionieren einwandfrei; lowbytesweep läuft
  sauber durch (0 Treffer erwartungsgemäß); MLD meldet 0 ohne Absturz.
  Live-Capture-Pfad siehe oben, weiterhin offen.
- 2026-08-09: Firmennetz-Erkennung (Version 5.1.0.31) auf Linux entwickelt und
  getestet, siehe oben - Windows-Test steht noch aus.
- 2026-08-09: Gesamte Git-Historie umgeschrieben (Co-Authored-By-Zeilen entfernt,
  484 Commits, alle Tags neu gepusht). Alte Commit-Hashes aus früheren Notizen oder
  Bookmarks sind ab diesem Zeitpunkt ungültig - bei Verweisen auf Commits vor
  2026-08-09 lieber über die Commit-Message/Version suchen statt über den Hash.
- 2026-08-10: Vollständiges Review aller IPv4-Scan-Verfahren (5 parallele
  Teil-Reviews) plus Umsetzung auf Linux, Version 6.0.0.0. Kernfunde: die
  Diensterkennung prüfte Antworten nie wirklich nach (jede Antwort galt als
  Treffer), vier Sonden-Byte-Arrays waren aus Versehen rohe TCP-SYN-Pakete statt
  Anwendungsdaten, SMB meldete SMB1 als unterstützt obwohl der Server es
  nachweislich ablehnte, UDP-Portscan fragte nie das Ziel, mDNS fand unter Linux
  nachweislich nie ein Gerät (falsche Socket-Bindung). Alles einzeln live gegen
  echte Server getestet (Samba, SSH, FTP, ONVIF-Kamera, DNS) - siehe oben für den
  Windows-Teil, der noch aussteht. Auch die MAC-Herstellerliste kann jetzt in den
  Einstellungen aus Wiresharks manuf-Datei aktualisiert werden (alle drei
  IEEE-Blockgrößen MA-L/MA-M/MA-S statt nur MA-L).
