# MyNetworkMonitor

Findet die Geräte in deinem Netz und zeigt, was auf ihnen läuft: Ping, ARP, Namen, offene Ports,
erkannte Dienste (z. B. SSH, Datenbanken, Fernwartung, Drucker, Kameras, Steuerungen), IPv6 und eine
3D-Ansicht des Netzes. Für Linux und Windows.

## Herunterladen und starten

Fertige Pakete stehen unter „Releases“ auf GitHub:

- **Linux:** `MyNetworkMonitor-linux-x64.tar.gz` entpacken, dann `./einrichten.sh` – danach steht das
  Programm im Anwendungsmenü. AppImages brauchen FUSE 2 (Debian/Ubuntu: `sudo apt install libfuse2t64`,
  Fedora: `sudo dnf install fuse-libs`).
- **Windows:** `MyNetworkMonitor-windows-x64.zip` entpacken und `MyNetworkMonitor.exe` starten.

Manche Verfahren (z. B. IPv6-Mitlesen) brauchen erweiterte Rechte; das Programm sagt dann, was fehlt.

## Selbst bauen

    ./publish.sh            # fragt nach Paketform und Ziel
    ./publish.sh linux      # ohne Rückfrage

Benötigt das .NET SDK 10. Die fertigen Programme liegen danach in `published/`.

## Privatsphäre

MyNetworkMonitor sendet keine Nutzungsdaten. Beim Start fragt es die Namensserver deines Netzes, ob es einen
Domänencontroller gibt (Erkennung eines Firmennetzes für den Lizenzhinweis) – nicht bei den Domänen, die Heimrouter
vergeben, und nie bei großen öffentlichen Diensten wie Google oder Cloudflare. Ins Internet geht es nur, wenn du es
auslöst: beim
Erneuern der Herstellerliste (Datei von wireshark.org) und, wenn der Haken „library from CDN“ gesetzt
ist, beim Laden der 3D-Bibliothek. Scanne nur Netze, für die du die Erlaubnis hast.

## Lizenz

Eigene Lizenz, Quellcode einsehbar („Source Available“, `LICENSE`), kein Open Source:

- **Kostenlos** für Privatleute, Vereine ohne hauptberufliche Kräfte, Schulen, Hochschulen und
  gemeinnützige Einrichtungen.
- **Mit Lizenz:** Unternehmen, Selbständige und Behörden – für jede Nutzung, auch nur im eigenen Netz.
  Eine Lizenz gibt es auf Anfrage (Kontakt im Programm).
- Das unveränderte Programm darf kostenlos weitergegeben werden; verkaufen und veränderte Fassungen
  veröffentlichen ist nicht erlaubt.

Fremde Bestandteile und ihre Lizenzen: `THIRD-PARTY-NOTICES.md`.

**Haftung:** Bei kostenloser Nutzung wird die Software unentgeltlich und ohne Gewähr („wie sie ist“)
überlassen. Der Urheber haftet nur für Vorsatz und grobe Fahrlässigkeit, bei Verletzung von Leben, Körper
oder Gesundheit und nach dem Produkthaftungsgesetz; im Übrigen ist jede Haftung ausgeschlossen,
insbesondere für Datenverlust, entgangenen Gewinn, Ausfälle von Geräten oder Netzen und Folgeschäden.
Portscans und Abfragen können empfindliche Geräte wie Steuerungen stören – scanne nur, wofür du die
Erlaubnis hast.
