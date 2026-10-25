#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
# Trägt MyNetworkMonitor für den angemeldeten Benutzer ins Anwendungsmenü ein – mit Symbol und
# (falls angegeben) den Dateiarten, damit es im Dateimanager unter „Öffnen mit …“ erscheint
# (nicht als Standardprogramm). Ohne Root-Rechte; kopiert werden nur Menüeintrag, Symbol und
# eine eigene Dateiart. Der Eintrag zeigt auf die AppImage in diesem Ordner (bei der Paketform
# „einzeln“ auf das Programm im Ordner). Wird der Ordner verschoben, hier erneut ausführen.
#
# Rückgängig: ./entfernen.sh
#
set -euo pipefail

# ---------------------------------------------------------------- Projektwerte
NAME="MyNetworkMonitor"                      # Anzeigename im Menü
KLASSE="MyNetworkMonitor.Avalonia"                 # Fensterklasse = Assembly-Name = Dateiname des Eintrags
PROGRAMM="MyNetworkMonitor"            # AppImage: $PROGRAMM-x86_64.AppImage; bei „einzeln“ siehe unten
SYMBOL="mynetworkmonitor.png"                 # Symbol neben diesem Skript (.png oder .svg)
KOMMENTAR="Geräte im Netz finden, Ports und Dienste erkennen, Netz als 3D-Ansicht zeigen"
ALLGEMEIN="Netzwerk-Scanner"
KATEGORIEN="Network;Monitor;"
STICHWORTE="Netzwerk;Scanner;Ping;ARP;Port;Dienst;SNMP;IPv6;"
DATEIARTEN=""                           # z. B. "video/x-matroska;video/mp4;" – leer: kein „Öffnen mit“
AUFRUF="%f"                             # %f: eine Datei je Fenster, %F: mehrere zusammen
EIGENE_DATEIART=""                      # z. B. "share/mime/<Programm>.xml" für neue Endungen, sonst leer
FRUEHERE_EINTRAEGE=()                   # frühere Dateinamen, z. B. ("mynetworkmonitor.desktop")

# ---------------------------------------------------------------- Ablauf
HIER="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
DATEN="${XDG_DATA_HOME:-$HOME/.local/share}"
ZIEL="$DATEN/applications"
EINTRAG="$ZIEL/$KLASSE.desktop"

PROG="$HIER/$PROGRAMM-x86_64.AppImage"
[ -f "$PROG" ] || PROG="$HIER/$KLASSE"                  # Paketform „einzeln“: Programmdatei heißt wie die Assembly
[ -f "$PROG" ] || { echo "Fehler: Programm nicht gefunden: $PROG" >&2; exit 1; }
chmod +x "$PROG"

# Was den Start verhindert, kann das Programm nicht selbst prüfen (Regeln/Startpruefung.md).
if [[ "$PROG" == *.AppImage ]] && ! { [ -e /usr/lib/x86_64-linux-gnu/libfuse.so.2 ] || [ -e /usr/lib64/libfuse.so.2 ] || [ -e /usr/lib/libfuse.so.2 ]; }; then
  echo "Hinweis: Für AppImages fehlt FUSE 2. Installieren mit:" >&2
  echo "  Debian/Ubuntu: sudo apt install libfuse2t64   (ältere Versionen: libfuse2)" >&2
  echo "  Fedora:        sudo dnf install fuse-libs" >&2
fi

# Symbol in das Symbolthema des Benutzers (Endung bestimmt den Unterordner).
SYMBOLNAME="${KLASSE,,}"
case "$SYMBOL" in
  *.svg) SYMBOLZIEL="$DATEN/icons/hicolor/scalable/apps/$SYMBOLNAME.svg" ;;
  *)     SYMBOLZIEL="$DATEN/icons/hicolor/256x256/apps/$SYMBOLNAME.png" ;;
esac
if [ -f "$HIER/$SYMBOL" ] && ! cmp -s "$HIER/$SYMBOL" "$SYMBOLZIEL"; then
  install -Dm644 "$HIER/$SYMBOL" "$SYMBOLZIEL"
  command -v gtk-update-icon-cache > /dev/null 2>&1 && gtk-update-icon-cache -f -t "$DATEN/icons/hicolor" > /dev/null 2>&1 || true
fi

# Eigene Dateiart (nur bei Änderung neu einlesen).
if [ -n "$EIGENE_DATEIART" ] && ! cmp -s "$HIER/$EIGENE_DATEIART" "$DATEN/mime/packages/$(basename "$EIGENE_DATEIART")"; then
  install -Dm644 "$HIER/$EIGENE_DATEIART" "$DATEN/mime/packages/$(basename "$EIGENE_DATEIART")"
  command -v update-mime-database > /dev/null 2>&1 && update-mime-database "$DATEN/mime" || true
fi

# Exec in Anführungszeichen, Sonderzeichen so maskiert, wie die Desktop-Entry-Spezifikation es verlangt.
MASKIERT="$(printf '%s' "$PROG" | sed -e 's/\\/\\\\\\\\/g' -e 's/["`$]/\\\\&/g' -e 's/%/%%/g')"

mkdir -p "$ZIEL"
# GNOME hält an einem geänderten Exec unter altem Dateinamen fest – frühere Namen entfernen.
for alt in "${FRUEHERE_EINTRAEGE[@]}"; do
  [ "$ZIEL/$alt" = "$EINTRAG" ] || rm -f -- "$ZIEL/$alt"
done

NEU="$(mktemp --suffix=.desktop)"
trap 'rm -f -- "$NEU"' EXIT
{
  echo "[Desktop Entry]"
  echo "Type=Application"
  echo "Name=$NAME"
  echo "GenericName=$ALLGEMEIN"
  echo "Comment=$KOMMENTAR"
  if [ -n "$DATEIARTEN" ]; then echo "Exec=\"$MASKIERT\" $AUFRUF"; else echo "Exec=\"$MASKIERT\""; fi
  echo "Icon=$SYMBOLNAME"
  echo "Terminal=false"
  echo "StartupWMClass=$KLASSE"
  echo "Categories=$KATEGORIEN"
  echo "Keywords=$STICHWORTE"
  if [ -n "$DATEIARTEN" ]; then echo "MimeType=$DATEIARTEN"; fi
} > "$NEU"

# Nur schreiben, wenn sich der Inhalt ändert: GNOME merkt sich Sortierung und Ordner am Dateinamen.
if cmp -s "$NEU" "$EINTRAG"; then
  echo "Menüeintrag unverändert: $EINTRAG"
  exit 0
fi
command -v desktop-file-validate > /dev/null 2>&1 && { desktop-file-validate "$NEU" || echo "Hinweis: desktop-file-validate meldet etwas (siehe oben)." >&2; }
install -m 644 "$NEU" "$EINTRAG"
command -v update-desktop-database > /dev/null 2>&1 && update-desktop-database -q "$ZIEL" || true

echo "Eingetragen: $NAME steht jetzt im Anwendungsmenü${DATEIARTEN:+ und unter „Öffnen mit …“}."
echo "Rückgängig: $HIER/entfernen.sh"
