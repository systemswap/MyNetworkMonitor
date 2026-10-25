# Plattform-Testnotizen

Merkzettel für Tests, die nur auf der jeweils anderen Plattform nachgeholt werden können: Ein Punkt
kommt hinzu, wenn etwas auf einer Plattform entwickelt und geprüft wurde und die andere noch aussteht.
Ist er erledigt, wird er hier gestrichen; was dabei an Fehlern gefunden wurde, steht im Fehlergedächtnis
(`docs/FEHLERGEDAECHTNIS.md`), das Vorgehen beim Prüfen in `docs/PRUEFUNGEN.md`.

Testnetze nur allgemein beschreiben – keine Adressen, Gerätenamen, Router- oder Gerätemodelle.

## Offen: braucht Test unter Windows

- **Firmennetz-Erkennung** (`WindowsEnterpriseEnvironment`, Fehlergedächtnis Nr. 1). Unter Linux in einem
  Heimnetz geprüft: korrekt `false`, rund 75 ms. Unter Windows prüfen:
  - Liefert sie `false` in einem Heimnetz, auch mit aktiven Hyper-V-, WSL2- und VPN-Adaptern?
  - Liefert sie `true` in einem echten AD-Netz?
  - Die Liste übergangener Adapter (`docker`, `veth`, `virbr`, `br-`, `vmnet`, `vboxnet`, `tun`, `tap`,
    `wg`, `utun`, `zt`) ist an Linux-Namen ausgerichtet – Windows-typische virtuelle Adapter (Hyper-V
    „vEthernet (…)“, VPN-Clients, „TAP-Windows Adapter“) stichprobenartig gegenprüfen.
  - Code: `MyNetworkMonitor.Core/Services/ActiveDirectoryDetector.cs`.
- **Diensterkennung und Suchverfahren** (Fehlergedächtnis Nr. 2–5), unter Linux im Testnetz gegen echte
  Server geprüft, unter Windows noch nie gelaufen. Am wichtigsten:
  - **mDNS** bindet an `IPAddress.Any`: Findet mDNS unter Windows weiterhin Geräte?
  - **UDP-Portscan**: Erkennung „zu“ über `SocketException` (`ConnectionReset`/`ConnectionRefused`) nach
    ICMP „Port nicht erreichbar“ – Windows hat hier Eigenheiten (`SIO_UDP_CONNRESET`).
  - `SocketOptionName.MulticastInterface` (SSDP, ONVIF) mit `byte[]`-Adresse.
  - Übrige reine .NET-Logik (Nebenläufigkeit von ARP und TCP-Portscan, SMB-Prüfung, NetBIOS `Connect()`
    vor `Send()`, Zeitbudget der Rückwärtsauflösung): geringeres Risiko.
  - `WindowsArpProvider.cs` (Abbruch beendet `arp`, strengere Zeilenprüfung von `arp -a`): baut, unter Windows
    noch nicht gelaufen.

- **Dienst einrichten und entfernen (7.3.0.26, Fehlergedächtnis Nr. 23):** `sc.exe`/`icacls.exe` werden mit gleichzeitig
  gelesener Fehlerausgabe aufgerufen; bei einem Fehlschlag nennt die Meldung den Pfad des Protokolls im Temp-Ordner.
  Unter Windows einrichten, entfernen und einen Fehlschlag (z. B. Dienst schon vorhanden) nachstellen.

- **WLAN-Messung (7.3.0.27, Fehlergedächtnis Nr. 24):** neu nach `wlanapi.h`; wird im Programm noch nicht angezeigt. Mit
  einem kleinen Testprogramm `ScanningMethod_WiFi.StartScanningAsync` laufen lassen: Name und Signal des verbundenen
  Netzes wie in `netsh wlan show interfaces`?

## Offen: auf beiden Plattformen

- **Firmennetz-Erkennung (7.3.0.29, Fehlergedächtnis Nr. 26):** in einem Firmennetz mit Active Directory prüfen, dass der
  Hinweis weiterhin erscheint – mit einer Domäne unter `.local`, und im Homeoffice über ein Firmen-VPN. Im Heimnetz
  mit Router-Domäne erscheint er nicht und es wird nichts gefragt (Linux geprüft).

- **Neutrale Sonden-Pakete (Version 7.3.0.17, Fehlergedächtnis Nr. 14):** MS-SQL (Standardinstanz), MongoDB
  (`isMaster` ohne Client-Angaben) und OPC UA (Endpoint `localhost`) gegen echte Server prüfen – erkannt wie vorher?
  MongoDB seit 7.3.0.25 mit neuer Antwortprüfung (Fehlergedächtnis Nr. 22): mehrere Serverfassungen, auch mit Replica
  Set, sollten jetzt erkannt werden.

## Offen: braucht Test unter Linux

- **Rechte-Hinweis in der Startprüfung (7.3.0.30, Fehlergedächtnis Nr. 27):** den Befehl für die AppImage (entpacken, dann
  `setcap`) einmal ganz durchspielen und `squashfs-root/AppRun` starten – meldet die Startprüfung danach „allowed“, und
  hören die IPv6-Verfahren mit?

- **IPv6: Router Advertisement und MLD mitlesen.** Mit `CAP_NET_RAW` öffnet der Rohsocket, empfängt im
  Test aber kein Paket – auch nicht nach einer Router Solicitation. Die Zähler in `/proc/net/snmp6`
  deuten darauf hin, dass der Router nach vielen Versuchen in kurzer Zeit nicht mehr antwortete
  (Begrenzung der Antwortrate), nicht auf einen Fehler im Code. Ein sauberer Einzeltest (eine
  Solicitation, genug Abstand zur letzten) steht aus.
