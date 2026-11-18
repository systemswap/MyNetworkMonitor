# Prüfungen und Prüfwerkzeuge – MyNetworkMonitor

Alles, womit MyNetworkMonitor geprüft wird. Neue Prüfungen hier ergänzen. Erzeugte Daten
(Scanergebnisse, Mitschnitte, Bildschirmfotos) kommen nie ins Git, sondern in den lokalen
Testordner außerhalb des Projekts (im Folgenden `<testordner>`) – sie enthalten echte Adressen
und Gerätenamen.

## Bauen

    dotnet build MyNetworkMonitor.sln -c Release -p:UseArtifactsOutput=true -p:ArtifactsPath=<testordner>/artifacts

Der Bau läuft ohne Warnungen (Linux und Windows, seit 7.3.0.49); eine neue Warnung wird behoben, nicht hingenommen.
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
| Nachbau (Testordner) | erfundenes Netz aus Dokumentationsadressen in Linux-Netz-Namensräumen ohne Zugang zum echten Netz: Zentrale in einem Segment, ein Router, acht Bereiche mit rund 90 virtuellen Geräten (je eigene MAC, antworten auf Ping und ARP), zwei Satelliten in eigenen Namensräumen in ihren Segmenten; Bedienung über einen unsichtbaren Bildschirm | Satellitenbetrieb über einen Router, MACs aus fremden Segmenten, Befunde zu doppelten Namen, MACs und DNS, Bildschirmfotos der Startseite |

## Satellitenbetrieb – Durchlauf im Nachbau

Am 18.11.2026 mit 7.3.0.45/7.3.0.46 auf Linux, Zentrale und zwei Satelliten (alle drei als Fenster, kein Dienst),
die Satelliten in eigenen Segmenten hinter einem Router; die Bereiche der Satelliten vorher leer im Bestand der
Zentrale. Ergebnis je Schritt:

| Schritt | Was angezeigt wurde | Ergebnis |
|---|---|---|
| Verbinden, Freigabe | Satellit „Waiting for approval“, nach Approve „Connected“; Zentrale zeigt Schlüssel, Last seen, Version, Herkunftsadresse | in Ordnung (Herkunft seit 7.3.0.46 ohne `::ffff:`) |
| Neustart aller drei | Satelliten verbinden sich ohne Zutun über den Router | in Ordnung nach „Connect all“; mit Einzel-„Connect“ erst seit 7.3.0.45 |
| Scan | Zentrale: Fortschritt je Satellit („Ping 0 % · 0 / 0 / 30 · step 1 / 2“), Statuszeile „2 satellites are scanning“, danach „… reported N device(s)“ je Satellit, bleibt nach dem eigenen Scan stehen | in Ordnung seit 7.3.0.45 (Fehlergedächtnis Nr. 42) |
| Ergebnis | Geräte der Satelliten-Bereiche grün, im richtigen Bereich, mit MAC und Hersteller aus dem fremden Segment; Router mit einer MAC in zwei Segmenten als zwei Geräte mit „DUP MAC“ | in Ordnung seit 7.3.0.45 (Nr. 43) und 7.3.0.42 (Nr. 36) |
| Satellit fällt im Auftrag weg | Zentrale: „Offline since <Zeit des Abbruchs>“, Statuszeile „connection was lost during the job …“ | in Ordnung seit 7.3.0.46 (Nr. 44, 45) |
| Satellit offline beim Start | Rückfrage „… is not connected. Scan these ranges from this machine instead?“; bei „No“ „1 range was left out …“ | in Ordnung |
| Stopp in der Zentrale | beendet nur den eigenen Scan; Statuszeile sagt weiter, dass der Satellit scannt | so gewollt (Stoppen eines Satelliten über „Stop this satellite's job“ bzw. am Satelliten) |
| neuer Scan, Satellit noch beschäftigt | Statuszeile „"sat-…": A job is already running (…)“, danach das Ergebnis des alten Auftrags | in Ordnung seit 7.3.0.45 |
| Seite des Satelliten | „Scanning for <Zentrale>:27411 (Zentrale) · job …“, Verfahren mit Fortschritt, erledigt/noch offen, „Stop the job“; eigene Angaben Hostname, Adresse, Netz | in Ordnung |

Offen bzw. nicht geprüft: Betrieb als Windows-Dienst, zwei Zentralen für einen Satelliten, Satellit auf Windows,
echte Router und Switches (Gegenproben in `docs/OFFENE-PUNKTE.md`). Der Satellit selbst steht seit 7.3.0.47 mit seiner MAC
und seinem Hersteller in der Tabelle der Zentrale (Fehlergedächtnis Nr. 46; vorher ohne, weil kein Rechner sich selbst
in seiner Nachbartabelle führt).

## Letzter Stand

| Datum | Version | Ergebnis |
|---|---|---|
| 09.08.2026 | 5.1.0.30 | IPv6-Verfahren unter Linux: Nachbartabelle, Multicast-Ping, Router Advertisement (Rückfall), EUI-64 funktionieren; Durchlauf der niedrigen Adressen ohne Treffer (erwartet); MLD 0 ohne Absturz; Mitlesen offen |
| 10.08.2026 | 6.0.0.0 | alle IPv4-Verfahren durchgesehen und einzeln im Testnetz geprüft (nur Linux) |
| 10.08.2026 | 6.0.0.4 | Rückwärtsauflösung: alle rund 30 Geräte in unter 100 ms, Vorwärtsauflösung über 254 Ziele in 18 ms |
| 25.10.2026 | 7.3.0.11 | Prüfung gegen die gemeinsamen Regeln (Doku, Lizenzen, Privatsphäre, Telemetrie) |
| 25.10.2026 | 7.3.0.31 | Normabschnitte in den Kommentaren gegen die Originaltexte (rfc-editor.org, OPC-UA-Referenz 1.05.07): keine falsche Nummer; ungenaue Stellen berichtigt; SEMI und ASHRAE nicht frei prüfbar |
| 25.10.2026 | 7.3.0.31 | 83 Tests grün; AppImage im Testordner gestartet: Titel mit Version, Startprüfung mit Hinweis auf Rohsocket-Rechte |
| 18.11.2026 | 7.3.0.46 | Satellitenbetrieb im Nachbau durchgespielt (siehe oben); 205 Tests grün |
| 19.11.2026 | 7.3.0.47 | Nachbau mit zwei Satelliten: beide Satelliten mit eigener MAC und Hersteller in der Zentrale; 209 Tests grün |
| 19.11.2026 | 7.3.0.49 | Compiler-Warnungen von 115 auf 0 (Linux und Windows); Nachbau mit zwei Satelliten gescannt, Ergebnis wie vorher; 210 Tests grün |
