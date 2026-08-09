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
