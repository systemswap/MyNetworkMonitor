# Fremde Bestandteile und ihre Lizenzen

Mit MyNetworkMonitor werden die folgenden Bestandteile anderer Projekte weitergegeben; ihre Rechte
liegen bei den jeweiligen Autoren. Die vollständigen Lizenztexte liegen im Ordner `licenses/` (im
Repository und in den Paketen neben dem Programm). Neue Bestandteile werden im selben Commit
eingetragen, in dem sie hinzukommen.

## Bibliotheken und Werkzeuge

| Bestandteil | Version | Lizenz | Quelle |
|---|---|---|---|
| .NET-Laufzeit und -Bibliotheken, darin Microsoft.Extensions.Hosting (auch .WindowsServices), System.DirectoryServices, System.ServiceProcess.ServiceController (nur Windows) | 10.0 | MIT und die Lizenzen der enthaltenen Bestandteile – `licenses/MIT-Bestandteile.txt`, `licenses/dotnet-runtime-*-THIRD-PARTY-NOTICES.txt` | https://github.com/dotnet/runtime |
| Avalonia (UI, Fluent-Design, DataGrid, Skia-, X11-, Win32- und FreeDesktop-Anbindung) | 12.1.1 | MIT – `licenses/MIT-Bestandteile.txt` | https://github.com/AvaloniaUI/Avalonia |
| Avalonia.Controls.WebView (eingebettete Webansicht über WebView2 bzw. WebKitGTK des Systems) | 12.0.1 | MIT – `licenses/MIT-Bestandteile.txt` | https://github.com/AvaloniaUI |
| Avalonia.Fonts.Inter, darin die Schrift Inter | 12.1.1 | MIT; Schrift: SIL Open Font License 1.1 – `licenses/inter-OFL.txt` | https://github.com/AvaloniaUI/Avalonia, https://github.com/rsms/inter |
| SkiaSharp / Skia, darin u. a. libjpeg-turbo, libpng, zlib, FreeType, expat, libwebp | 3.119.4 | MIT / BSD-3-Clause und die Lizenzen der enthaltenen Bibliotheken – `licenses/SkiaSharp-HarfBuzzSharp-THIRD-PARTY-NOTICES.txt` | https://github.com/mono/SkiaSharp |
| HarfBuzzSharp / HarfBuzz | 8.3.1.3 | MIT / „Old MIT“ – `licenses/HarfBuzz-OldMIT.txt` | https://github.com/mono/SkiaSharp, https://github.com/harfbuzz/harfbuzz |
| ANGLE (nur Windows, über Avalonia.Angle.Windows.Natives), darin Abseil | 2.1.27548 | BSD-3-Clause – `licenses/ANGLE-BSD-3.txt`; Apache License 2.0 – `licenses/Abseil-Apache-2.0.txt` | https://chromium.googlesource.com/angle/angle, https://github.com/abseil/abseil-cpp |
| Tmds.DBus.Protocol, MicroCom.Runtime (über Avalonia) | 0.94.1, 0.11.6 | MIT – `licenses/MIT-Bestandteile.txt` | https://github.com/tmds/Tmds.DBus, https://github.com/kekekeks/MicroCom |
| CommunityToolkit.Mvvm | 8.4.2 | MIT – `licenses/CommunityToolkit-ThirdPartyNotices.txt` | https://github.com/CommunityToolkit/dotnet |
| DnsClient.NET | 1.8.0 | Apache License 2.0 – `licenses/DnsClient-Apache-2.0.txt` | https://github.com/MichaCo/DnsClient.NET |
| Lextm.SharpSnmpLib | 12.5.7 | MIT – `licenses/MIT-Bestandteile.txt` | https://github.com/lextudio/sharpsnmplib |
| Newtonsoft.Json | 13.0.3 | MIT – `licenses/MIT-Bestandteile.txt` | https://github.com/JamesNK/Newtonsoft.Json |
| 3d-force-graph (3D-Netzansicht), darin three.js, three-forcegraph, three-render-objects, d3-force-3d und weitere d3-Bausteine, ngraph, tween.js, polished, preact, tinycolor2 u. a. | 1.76.2 | MIT, ISC, BSD-3-Clause – alle Texte in `licenses/3d-force-graph-Bestandteile.txt` | https://github.com/vasturiano/3d-force-graph |
| AppImage-Laufzeit (nur im Linux-Paket), darin musl, libfuse, squashfuse, zstd, zlib | type2 | MIT, LGPL-2.1, BSD-2/3-Clause, zlib – `licenses/AppImage-Laufzeit.txt` | https://github.com/AppImage/type2-runtime |

Nur beim Entwickeln (nicht in den Paketen): AvaloniaUI.DiagnosticsSupport (nur im Debug-Bau).

## Übertragener Code

Stellen, die aus anderem Quellcode übernommen oder eng nachgebaut sind (Prüfung vom 25.10.2026). Was noch
offen ist (neu schreiben oder entfernen), steht in `docs/OFFENE-PUNKTE.md`.

| Eigene Stelle | Herkunft | Lizenz | Stand |
|---|---|---|---|
| `MyNetworkMonitor.Core/Support/SupportMethods.cs` (`IsAdministrator`, CSV-Regex, IPv4-Regex, `GetEnumDescription`) | übliche kurze Muster, wie auf Stack Overflow verbreitet | ohne Schöpfungshöhe | in Gebrauch |
| `MyNetworkMonitor.Platform.Windows/WindowsArpProvider.cs`, `SendARP`-Deklaration | Signatur nach der Windows-API-Dokumentation (Schreibweise wie auf pinvoke.net) | ohne Schöpfungshöhe | in Gebrauch |
| `MyNetworkMonitor.Core/Services/TopologyGraph.cs`, `ServiceTopologyGraph.cs` (HTML-Seite) | Aufruf von 3d-force-graph nach dessen Dokumentation und Beispielen | MIT (siehe oben) | in Gebrauch |

Sonden-Pakete der Diensterkennung sind nach den Protokollnormen gebaut oder aus eigenen Netzmitschnitten
gewonnen (Bytefolgen eines Protokolls); Programmcode anderer Werkzeuge ist darin nicht enthalten.

## Daten

| Daten | Herkunft | Lizenz |
|---|---|---|
| MAC-Herstellerliste `Assets/MacVendors/mac_vendors.csv` (mitgeliefert, Stand 25.10.2026, 58 575 Einträge) | erzeugt mit der Funktion „Update from Wireshark“ des Programms aus der Datei `manuf` von Wireshark (https://www.wireshark.org/download/automated/data/manuf), die die öffentlichen Register der IEEE Registration Authority (MA-L, MA-M, MA-S) zusammenfasst; übernommen ist der volle Herstellername aus dem Register | Fakten aus einem öffentlichen Register; die Datei `manuf` nennt keine eigenen Bedingungen |
| Erneuerte Herstellerliste (auf Knopfdruck, wird nicht mitgeliefert) | wird zur Laufzeit aus der Datei `manuf` von Wireshark erzeugt: https://www.wireshark.org/download/automated/data/manuf | Daten aus den Registern der IEEE |
| Bekannte Ports und Dienstnamen (`MyNetworkMonitor.Core/Support/zzz_DataStructure.cs`) | IANA Service Name and Transport Protocol Port Number Registry, `/etc/services`, eigene Beschreibungen | Registerangaben; einzelne Beschreibungen aus öffentlichen Portlisten (Prüfung offen) |
| Protokollkonstanten, Adressbereiche, OIDs | RFCs und Normen der jeweiligen Protokolle | – |

## Marken

PayPal und das PayPal-Logo (`MyNetworkMonitor.Avalonia/Images/PayPal.png`) sind Marken der PayPal, Inc.;
das Logo wird nur als Hinweis auf die Spendenmöglichkeit gezeigt.
