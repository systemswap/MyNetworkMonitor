# Plattform-Testnotizen

Merkzettel für offene Tests, die nur auf der jeweils anderen Plattform
nachgeholt werden können. Wird von Claude gepflegt: neue Punkte kommen rein,
wenn auf einer Plattform entwickelt/getestet wurde und die andere noch
absteht; erledigte Punkte wandern nach unten in den Verlauf statt gelöscht zu
werden, damit nachvollziehbar bleibt, was wann geprüft wurde.

## Offen: braucht Test unter Windows

- **Firmennetz-Erkennung (`WindowsEnterpriseEnvironment`, 2026-08-09).**
  `IsCompanyNetwork()` wurde auf `ActiveDirectoryDetector.DomainControllerReachable()`
  umgestellt (DNS-SRV-Abfrage `_ldap._tcp.dc._msdcs.<domain>` statt IP-Bereichs-Heuristik).
  Auf Linux gegen ein FRITZ!Box-Heimnetz getestet: korrekt `false`, ~75ms.
  Unter Windows noch nicht getestet:
  - Liefert `false` in einem normalen Windows-Heimnetz (auch mit Hyper-V/WSL2/VPN-Adaptern aktiv)?
  - Liefert `true` in einem echten AD-Netz?
  - Die Adapter-Filterliste (`docker`, `veth`, `virbr`, `br-`, `vmnet`, `vboxnet`,
    `tun`, `tap`, `wg`, `utun`, `zt`) ist Linux-lastig entstanden - Windows-typische
    virtuelle Adapternamen (Hyper-V "vEthernet (...)", Cisco AnyConnect, Tailscale,
    OpenVPN "TAP-Windows Adapter") sollten stichprobenartig gegengeprüft werden.
  - Siehe `MyNetworkMonitor.Core/Services/ActiveDirectoryDetector.cs`.

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

- 2026-08-09: Sechs IPv6-Suchverfahren (Commit 4d5f73d) unter Linux getestet -
  vier von sechs (neighborcache, multicastping, routeradvertisement-Fallback,
  eui64) funktionieren einwandfrei; lowbytesweep läuft sauber durch (0 Treffer
  erwartungsgemäß); MLD meldet 0 ohne Absturz. Live-Capture-Pfad siehe oben,
  weiterhin offen.
