#!/usr/bin/env bash
set -Eeuo pipefail

# Erstellt die fertigen Programme in published/:
#
#   published/linux-x64/MyNetworkMonitor-x86_64.AppImage   eine Datei: Programm, .NET, Avalonia und die Daten
#   published/windows-x64/MyNetworkMonitor.exe             eine Datei: Programm, .NET und Avalonia
#   published/MyNetworkMonitor-linux-x64.tar.gz, MyNetworkMonitor-windows-x64.zip
#
# Neben jedes Programm kommen LICENSE, THIRD-PARTY-NOTICES.md und licenses/, unter Linux außerdem
# einrichten.sh / entfernen.sh für den Menüeintrag (MyNetworkMonitor öffnet keine Dateien, darum ohne
# „Öffnen mit …“; unter Windows ist nichts einzurichten). Nach einem Linux-Bau trägt das Skript das
# Programm im Menü ein. Die Einstellungen liegen im Benutzerordner (~/.config/MyNetworkMonitor bzw.
# %APPDATA%\MyNetworkMonitor) und werden von einem Bau nicht berührt.
#
# Die Herstellerliste (MacVendors/) und die Bibliothek der 3D-Ansicht (3dForceGraphLib/) liest das
# Programm neben seiner Programmdatei: unter Linux liegen sie in der AppImage, unter Windows neben der EXE.
#
# Paketform:
#   dotnet   eine Datei mit .NET (Standard). Native AOT geht hier nicht: Newtonsoft.Json, DataTable/XML und
#            die Windows-Firewall über `dynamic` vertragen das Kürzen beim Übersetzen nicht.
#   einzeln  alle Bibliotheken lose im Ordner, ohne AppImage (Fehlersuche).
#
# Windows wird auch unter Linux gebaut (Ziel win-x64 mit EnableWindowsTargeting, siehe
# MyNetworkMonitor.Avalonia.csproj: dann mit den Windows-Teilen).
#
# Aufruf ohne Argumente fragt erst nach der Paketform, dann nach dem Ziel. Mit Argumenten ohne
# Rückfrage, Reihenfolge egal; was fehlt, gilt als Standard (Paketform dotnet, Ziel beides):
#   ./publish.sh [linux|windows|beides] [dotnet|einzeln]
#   z. B. ./publish.sh linux   ./publish.sh linux einzeln   ./publish.sh beides
#
# Zusätzliche Kopie der Windows-Fassung (optional): Steht in
#   ~/.config/mynetworkmonitor-build/publish.conf
# eine Zeile  windows_kopie=/pfad/zum/ordner , kommt nach jedem Windows-Bau der Inhalt von
# published/windows-x64/ direkt in diesen Ordner (ohne Unterordner), z. B. in einen Sync-Ordner für
# den Windows-Rechner. Dort ersetzt werden nur die mitgelieferten Dateien.
#
# Benötigt: .NET SDK 10, wget (lädt appimagetool beim ersten Mal), zip

# Keine Nutzungsdaten an Microsoft (.NET) oder Avalonia senden.
export DOTNET_CLI_TELEMETRY_OPTOUT=1 AVALONIA_TELEMETRY_OPTOUT=1 DO_NOT_TRACK=1
export DOTNET_NOLOGO=1

PROJECT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
PROJECT="$PROJECT_DIR/MyNetworkMonitor.Avalonia/MyNetworkMonitor.Avalonia.csproj"
OUT_DIR="$PROJECT_DIR/published"
LINUX_DIR="$OUT_DIR/linux-x64"
WINDOWS_DIR="$OUT_DIR/windows-x64"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/mynetworkmonitor-build"
WORK_DIR="$CACHE_DIR/publish"
ARTIFACTS="$CACHE_DIR/artifacts"
APPIMAGETOOL="$CACHE_DIR/appimagetool-x86_64.AppImage"
ICON="$PROJECT_DIR/packaging/linux/mynetworkmonitor.png"
ASSEMBLY="MyNetworkMonitor.Avalonia"
LOCAL_CONF="${XDG_CONFIG_HOME:-$HOME/.config}/mynetworkmonitor-build/publish.conf"
WINDOWS_COPY=""
[ -f "$LOCAL_CONF" ] && WINDOWS_COPY="$(sed -n 's/^windows_kopie=//p' "$LOCAL_CONF" | tail -1)"

TARGET=""
BAUART=""
for argument in "$@"; do
  case "$argument" in
    linux|windows) TARGET="$argument" ;;
    beides|all) TARGET=all ;;
    dotnet|net|eine-datei|datei) BAUART=dotnet ;;
    einzeln|ordner) BAUART=einzeln ;;
    *) echo "Aufruf: $0 [linux|windows|beides] [dotnet|einzeln]" >&2; exit 1 ;;
  esac
done

if [ $# -gt 0 ]; then
  # Mit Argumenten nie nachfragen (z. B. nach jeder Versionsänderung: ./publish.sh linux).
  TARGET="${TARGET:-all}"
  BAUART="${BAUART:-dotnet}"
fi

if [ -z "$BAUART" ]; then
  echo
  echo "Welche Paketform?"
  echo "  1) Eine Datei (Standard) – Linux: AppImage, Windows: EXE; .NET und Avalonia darin"
  echo "  2) Einzeln               – alle Bibliotheken lose im Ordner, ohne AppImage (Fehlersuche)"
  echo
  read -r -p "Auswahl [1]: " selection
  case "${selection:-1}" in
    1) BAUART=dotnet ;;
    2) BAUART=einzeln ;;
    *) echo "Fehler: Ungültige Auswahl." >&2; exit 1 ;;
  esac
fi

if [ -z "$TARGET" ]; then
  echo
  echo "Wofür soll gebaut werden?"
  echo "  1) beides (Standard)"
  echo "  2) Linux"
  echo "  3) Windows"
  echo
  read -r -p "Auswahl [1]: " selection
  case "${selection:-1}" in
    1) TARGET=all ;;
    2) TARGET=linux ;;
    3) TARGET=windows ;;
    *) echo "Fehler: Ungültige Auswahl." >&2; exit 1 ;;
  esac
fi

if [ "$BAUART" = einzeln ]; then SINGLE_FILE=false; else SINGLE_FILE=true; fi
echo "Ziel: $TARGET, Bauart: $BAUART"

command -v dotnet > /dev/null || { echo "Fehler: .NET SDK fehlt." >&2; exit 1; }
command -v zip > /dev/null || { echo "Fehler: zip fehlt (Debian: sudo apt install zip, Fedora: sudo dnf install zip)." >&2; exit 1; }
# Nicht, solange das Programm aus published/ läuft.
if pgrep -f "$LINUX_DIR/(MyNetworkMonitor-x86_64\.AppImage|$ASSEMBLY)( |$)" > /dev/null; then
  echo "Fehler: MyNetworkMonitor läuft gerade (aus published/) – bitte erst beenden, dann neu bauen." >&2
  exit 1
fi

VERSION="$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' "$PROJECT" | head -1)"
echo "MyNetworkMonitor $VERSION"

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR" "$OUT_DIR"

# Lizenz, Hinweise auf fremde Bestandteile und deren Lizenztexte neben das Programm.
notices() {
  local dest="$1"
  install -m 0644 "$PROJECT_DIR/LICENSE" "$dest/LICENSE"
  install -m 0644 "$PROJECT_DIR/THIRD-PARTY-NOTICES.md" "$dest/THIRD-PARTY-NOTICES.md"
  rm -rf "$dest/licenses"
  mkdir -p "$dest/licenses"
  install -m 0644 "$PROJECT_DIR/licenses/"* "$dest/licenses/"
}

clear_program_folder() {
  mkdir -p "$1"
  find "$1" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
}

publish() {
  local rid="$1" dest="$2" windows=()
  [[ "$rid" == win-* ]] && windows=(-p:EnableWindowsTargeting=true)
  dotnet publish "$PROJECT" -c Release -r "$rid" --self-contained true "${windows[@]}" \
    -p:PublishSingleFile=$SINGLE_FILE \
    -p:IncludeNativeLibrariesForSelfExtract=$SINGLE_FILE \
    -p:EnableCompressionInSingleFile=$SINGLE_FILE \
    -p:DebugType=None -p:DebugSymbols=false \
    -p:UseArtifactsOutput=true -p:ArtifactsPath="$ARTIFACTS" \
    -o "$dest" > "$WORK_DIR/publish-$rid.log" 2>&1 \
    || { tail -20 "$WORK_DIR/publish-$rid.log" >&2; echo "Fehler: dotnet publish für $rid fehlgeschlagen." >&2; exit 1; }
  find "$dest" -name '*.pdb' -delete
  [ -f "$dest/MacVendors/mac_vendors.csv" ] && [ -f "$dest/3dForceGraphLib/3d-force-graph.min.js" ] \
    || { echo "Fehler: MacVendors/ oder 3dForceGraphLib/ fehlt in der Ausgabe für $rid." >&2; exit 1; }
}

package() {
  local folder="$1" archive="$2"
  rm -f "$OUT_DIR/$archive"
  case "$archive" in
    *.tar.gz) tar -C "$OUT_DIR" -czf "$OUT_DIR/$archive" "$folder" ;;
    *.zip) (cd "$OUT_DIR" && zip -qr "$archive" "$folder") ;;
  esac
}

# ---------------------------------------------------------------- Linux
if [ "$TARGET" = all ] || [ "$TARGET" = linux ]; then
  echo "== Linux"
  publish linux-x64 "$WORK_DIR/linux"
  clear_program_folder "$LINUX_DIR"

  if [ "$SINGLE_FILE" = true ]; then
    APPDIR="$WORK_DIR/AppDir"
    mkdir -p "$APPDIR/usr/bin"
    # Programm mit den Daten, die es neben sich liest (MacVendors/, 3dForceGraphLib/), und den Lizenzen
    cp -a "$WORK_DIR/linux/." "$APPDIR/usr/bin/"
    chmod 0755 "$APPDIR/usr/bin/$ASSEMBLY"
    notices "$APPDIR/usr/bin"
    install -m 0644 "$PROJECT_DIR/packaging/linux/$ASSEMBLY.desktop" "$APPDIR/$ASSEMBLY.desktop"
    install -m 0644 "$ICON" "$APPDIR/mynetworkmonitor.avalonia.png"

    cat > "$APPDIR/AppRun" << APPRUN
#!/bin/sh
HERE="\$(dirname "\$(readlink -f "\$0")")"
exec "\$HERE/usr/bin/$ASSEMBLY" "\$@"
APPRUN
    chmod 0755 "$APPDIR/AppRun"

    if [ ! -x "$APPIMAGETOOL" ]; then
      mkdir -p "$CACHE_DIR"
      wget -nv -O "$APPIMAGETOOL" "https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-x86_64.AppImage"
      chmod +x "$APPIMAGETOOL"
    fi

    ARCH=x86_64 "$APPIMAGETOOL" --no-appstream "$APPDIR" "$LINUX_DIR/MyNetworkMonitor-x86_64.AppImage" > "$WORK_DIR/appimagetool.log" 2>&1 \
      || { tail -20 "$WORK_DIR/appimagetool.log" >&2; echo "Fehler: appimagetool fehlgeschlagen." >&2; exit 1; }
  else
    cp -a "$WORK_DIR/linux/." "$LINUX_DIR/"
    chmod 0755 "$LINUX_DIR/$ASSEMBLY"
  fi

  notices "$LINUX_DIR"
  install -m 0644 "$ICON" "$LINUX_DIR/mynetworkmonitor.png"
  install -m 0755 "$PROJECT_DIR/packaging/linux/einrichten.sh" "$PROJECT_DIR/packaging/linux/entfernen.sh" "$LINUX_DIR/"

  package linux-x64 MyNetworkMonitor-linux-x64.tar.gz
fi

# ---------------------------------------------------------------- Windows
if [ "$TARGET" = all ] || [ "$TARGET" = windows ]; then
  echo "== Windows"
  publish win-x64 "$WORK_DIR/windows"
  clear_program_folder "$WINDOWS_DIR"
  if [ "$SINGLE_FILE" = true ]; then
    install -m 0644 "$WORK_DIR/windows/$ASSEMBLY.exe" "$WINDOWS_DIR/MyNetworkMonitor.exe"
    cp -a "$WORK_DIR/windows/MacVendors" "$WORK_DIR/windows/3dForceGraphLib" "$WINDOWS_DIR/"
  else
    cp -a "$WORK_DIR/windows/." "$WINDOWS_DIR/"
  fi
  notices "$WINDOWS_DIR"
  package windows-x64 MyNetworkMonitor-windows-x64.zip

  # Kopie direkt in den eingestellten Ordner; dort nur ersetzen, was der Bau mitbringt.
  if [ -n "$WINDOWS_COPY" ]; then
    mkdir -p "$WINDOWS_COPY"
    for entry in "$WINDOWS_DIR"/*; do
      name="$(basename "$entry")"
      rm -rf -- "${WINDOWS_COPY:?}/$name"
      cp -a -- "$entry" "$WINDOWS_COPY/$name"
    done
    echo "   Kopie: $WINDOWS_COPY"
  fi
fi

echo
echo "Fertig (MyNetworkMonitor $VERSION):"
find "$OUT_DIR" -maxdepth 3 -type f \( -name "*.AppImage" -o -name "*.exe" -o -name "$ASSEMBLY" -o -name "*.tar.gz" -o -name "*.zip" \) -printf "  %P  (%s Bytes)\n" | sort

if [ "$TARGET" = all ] || [ "$TARGET" = linux ]; then
  echo
  "$LINUX_DIR/einrichten.sh"
fi
