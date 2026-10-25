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

    dotnet test MyNetworkMonitor.Core.Tests -c Release -p:UseArtifactsOutput=true -p:ArtifactsPath=<testordner>/artifacts

`MyNetworkMonitor.Core.Tests` (xUnit) läuft auch im GitHub-Bau vor dem Linux-Paket; schlägt ein Test fehl, gibt es
kein Release. Die Tests prüfen die Fachlogik ohne Netz: Pakete und Antworten bauen die Tests selbst,
Namen und Adressen sind erfunden. Was ein echtes Netz braucht, wird im Testnetz mit dem fertigen Programm geprüft;
was nur auf einer Plattform geprüft ist, steht in `PLATFORM_TESTING_NOTES.md`.

| Testklasse | Was |
|---|---|
| `NetBiosNodeStatusTests` | Anfrage byte-gleich zur bekannten Form; Rechner/Gruppe, Gruppe zuerst, nur Browsergruppe, nur Workstation, leer; komprimierter Name; falsche Transaktionsnummer, Fehlercode, Anfrage statt Antwort; 200 000 verdorbene Antworten |

## Prüfprogramme

Einmalige Prüfungen, die nicht als Test bleiben, laufen als C#-Datei mit `dotnet run <datei>.cs` und der
Zeile `#:project <pfad>/MyNetworkMonitor.Core/MyNetworkMonitor.Core.csproj` im lokalen Testordner:

| Prüfung | Was |
|---|---|
| NetBIOS (`NetBiosNodeStatus`) | synthetische Antworten gegen die frühere Auswertung mit festen Stellen (die übrigen Fälle sind jetzt Tests) |
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
| 25.10.2026 | 7.3.0.31 | Normabschnitte in den Kommentaren gegen die Originaltexte (rfc-editor.org, OPC-UA-Referenz 1.05.07): keine falsche Nummer; ungenaue Stellen berichtigt; SEMI und ASHRAE nicht frei prüfbar |
| 25.10.2026 | 7.3.0.31 | 83 Tests grün; AppImage im Testordner gestartet: Titel mit Version, Startprüfung mit Hinweis auf Rohsocket-Rechte |
