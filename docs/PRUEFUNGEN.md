# Prüfungen und Prüfwerkzeuge – MyNetworkMonitor

Alles, womit MyNetworkMonitor geprüft wird. Neue Prüfungen hier ergänzen. Erzeugte Daten
(Scanergebnisse, Mitschnitte, Bildschirmfotos) kommen nie ins Git, sondern in den lokalen
Testordner außerhalb des Projekts (im Folgenden `<testordner>`) – sie enthalten echte Adressen
und Gerätenamen.

## Bauen

    dotnet build MyNetworkMonitor.sln -c Release -p:UseArtifactsOutput=true -p:ArtifactsPath=<testordner>/artifacts

Unter Linux baut das Oberflächenprojekt für `net10.0` ohne `MyNetworkMonitor.Platform.Windows`; mit dem Ziel
`win-x64` und `-p:EnableWindowsTargeting=true` (wie in `publish.sh`) baut es auch unter Linux für Windows. Die Pakete (AppImage, Windows-Zip) baut der
GitHub-Bau (`.github/workflows/build-and-release.yml`), sobald sich `<Version>` ändert.

## Tests

Es gibt noch keine automatischen Tests (`docs/OFFENE-PUNKTE.md`). Geprüft wird im Testnetz mit dem
fertigen Programm; was nur auf einer Plattform geprüft ist, steht in `PLATFORM_TESTING_NOTES.md`.

## Prüfprogramme

Bis es ein Testprojekt gibt, laufen Prüfungen einzelner Teile als C#-Datei mit `dotnet run <datei>.cs` und der
Zeile `#:project <pfad>/MyNetworkMonitor.Core/MyNetworkMonitor.Core.csproj` im lokalen Testordner:

| Prüfung | Was |
|---|---|
| NetBIOS (`NetBiosNodeStatus`) | Anfrage byte-gleich zur bekannten Form; synthetische Antworten nach RFC 1002 (Rechner/Gruppe, Gruppe zuerst, nur Browsergruppe, nur Workstation, leer) gegen die frühere Auswertung; komprimierter Name; falsche Transaktionsnummer, Fehlercode, Anfrage statt Antwort; 200 000 verdorbene Antworten |
| Sonden-Prüfsummen (`SupersededDefaults`) | alte Pakete mit dem Algorithmus von `Fingerprint` nachgerechnet |

## Testnetz

Allgemein beschrieben, ohne Adressen und Gerätenamen:

| Fall | Beschreibung | Wofür |
|---|---|---|
| Heimnetz | ein /24-Netz hinter einem Heimrouter, der DNS für seinen lokalen Namensraum selbst beantwortet, rund 30 Geräte, dazu ein weiterleitender DNS-Server im Netz | Ping, ARP, Rückwärts- und Vorwärtsauflösung, Tempo bei vollem Netz |
| Dienste | SSH-, FTP-, Samba- und DNS-Server, eine ONVIF-Kamera | Diensterkennung, SMB, ONVIF |
| IPv6 | Router mit Router Advertisement | Nachbartabelle, Multicast-Ping, EUI-64, Router Advertisement, MLD |
| öffentliche Server | bekannte öffentliche DNS-Server (IPv4, IPv6) | PTR-Einträge, Fall „kein PTR“ |

## Letzter Stand

| Datum | Version | Ergebnis |
|---|---|---|
| 09.08.2026 | 5.1.0.30 | IPv6-Verfahren unter Linux: Nachbartabelle, Multicast-Ping, Router Advertisement (Rückfall), EUI-64 funktionieren; Durchlauf der niedrigen Adressen ohne Treffer (erwartet); MLD 0 ohne Absturz; Mitlesen offen |
| 10.08.2026 | 6.0.0.0 | alle IPv4-Verfahren durchgesehen und einzeln im Testnetz geprüft (nur Linux) |
| 10.08.2026 | 6.0.0.4 | Rückwärtsauflösung: alle rund 30 Geräte in unter 100 ms, Vorwärtsauflösung über 254 Ziele in 18 ms |
| 25.10.2026 | 7.3.0.11 | Prüfung gegen die gemeinsamen Regeln (Doku, Lizenzen, Privatsphäre, Telemetrie) |
