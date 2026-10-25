#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
# Entfernt Menüeintrag, Symbol und eigene Dateiart von MyNetworkMonitor. Der Programmordner und die
# Einstellungen bleiben unberührt.
set -euo pipefail

# ---------------------------------------------------------------- Projektwerte
KLASSE="MyNetworkMonitor.Avalonia"
EIGENE_DATEIART=""                      # wie in einrichten.sh
FRUEHERE_EINTRAEGE=()                   # wie in einrichten.sh

# ---------------------------------------------------------------- Ablauf
DATEN="${XDG_DATA_HOME:-$HOME/.local/share}"
ZIEL="$DATEN/applications"
SYMBOLNAME="${KLASSE,,}"

rm -f -- "$ZIEL/$KLASSE.desktop"
for alt in "${FRUEHERE_EINTRAEGE[@]}"; do rm -f -- "$ZIEL/$alt"; done
rm -f -- "$DATEN/icons/hicolor/scalable/apps/$SYMBOLNAME.svg" "$DATEN/icons/hicolor/256x256/apps/$SYMBOLNAME.png"
if [ -n "$EIGENE_DATEIART" ]; then
  rm -f -- "$DATEN/mime/packages/$(basename "$EIGENE_DATEIART")"
  command -v update-mime-database > /dev/null 2>&1 && update-mime-database "$DATEN/mime" || true
fi
command -v update-desktop-database > /dev/null 2>&1 && update-desktop-database -q "$ZIEL" || true
command -v gtk-update-icon-cache > /dev/null 2>&1 && gtk-update-icon-cache -f -t "$DATEN/icons/hicolor" > /dev/null 2>&1 || true

echo "Menüeintrag entfernt. Programmordner und Einstellungen bleiben."
