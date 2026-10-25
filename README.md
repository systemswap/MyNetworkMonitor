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

MyNetworkMonitor sendet keine Nutzungsdaten. Ins Internet geht es nur, wenn du es auslöst: beim
Erneuern der Herstellerliste (Datei von wireshark.org) und, wenn der Haken „library from CDN“ gesetzt
ist, beim Laden der 3D-Bibliothek. Scanne nur Netze, für die du die Erlaubnis hast.

## Lizenz

MIT mit „Commons Clause“ (`LICENSE`): Nutzen, weitergeben und verändern ist frei, auch für Firmen –
verkaufen darf man das Programm nicht. Fremde Bestandteile und ihre Lizenzen: `THIRD-PARTY-NOTICES.md`.

**Haftung:** Die Software wird unentgeltlich und ohne Gewähr („wie sie ist“) überlassen. Der Urheber
haftet nur für Vorsatz und grobe Fahrlässigkeit, bei Verletzung von Leben, Körper oder Gesundheit und
nach dem Produkthaftungsgesetz; im Übrigen ist jede Haftung ausgeschlossen, insbesondere für
Datenverlust, entgangenen Gewinn und Folgeschäden.
