# Satellitenbetrieb — Entwurf

Vorhaben: dieselbe Anwendung als Dienst in einem anderen Netzsegment laufen
lassen. Sie meldet sich beim Hauptscanner, wartet auf einen Scan-Auftrag,
führt ihn aus und liefert das Ergebnis zurück, wo es örtlich angezeigt wird.

**Warum überhaupt:** ARP überquert keinen Router. Ein fremdes VLAN lässt sich
nur von innen ausleuchten — aus der Ferne bleibt sonst nur, was durch den
Router kommt. Alles andere (Ping, Ports, Dienste) wird ebenfalls besser, weil
der Weg kurz ist und keine Firewall dazwischen steht.

**Grundsatz:** Der Satellit ist keine abgespeckte Variante, sondern dieselbe
Anwendung ferngesteuert. Jede Option, die örtlich einstellbar ist, muss sich
auch aus der Ferne auslösen lassen.

Stand: gebaut sind Transport, Anmeldung, Auftragsausfuehrung, die Liste der
Hauptscanner je Satellit, der Betrieb als Windows-Dienst und die Steuerpipe,
ueber die die Oberflaeche dem Dienst zusieht. Ueber die Leitung geht jetzt
auch, welche Verfahren sich auf schon gefundene Geraete beschraenken sollen.
Offen sind das Zwischenlagern eines Ergebnisses auf der Platte (Abschnitt 5),
Lebenszeichen und `ListenPortChanged` (Abschnitt 6), die Bestandshoheit beim
Hauptscanner (Abschnitt 7) und der Zeitplan (Abschnitt 10).
Version 7.0.0.1.

---

## 1. Richtung der Verbindung

**Der Satellit verbindet sich hinaus zum Hauptscanner.** Der Hauptscanner
lauscht auf einem fest vergebenen Port, der Satellit hält die Verbindung
offen, und die Aufträge laufen durch diese bestehende Verbindung nach unten.

Der Satellit lauscht selbst auf **nichts**. Das ist der eigentliche Gewinn:

- Keine Freigabe in das fremde Segment hinein, nur eine ausgehende Verbindung
  — die ist in aller Regel ohnehin erlaubt.
- Kein offener Port am Satelliten, der gefunden oder angegriffen werden kann.
- Der Hauptscanner darf seine Adresse wechseln, solange sein **Name** gleich
  bleibt. Damit kann der Hauptscanner ein Laptop sein.

Der Satellit kennt den Hauptscanner als **Hostname oder IP**. Ein Name ist
vorzuziehen: er überlebt einen Adresswechsel. Eine feste Server-Adresse geht
genauso.

**Den Scan stößt immer der Hauptscanner an.** Der Satellit fängt von sich aus
nie an zu scannen.

### Mehrere Empfänger

Ein Satellit kennt **mehrere** Hauptscanner — etwa den Arbeitsplatz-Laptop und
einen festen Server. Er hält zu allen gleichzeitig eine Verbindung, jede für
sich freigegeben und einzeln wiederverbindend. Fällt einer aus, arbeitet der
andere weiter.

Daraus folgen drei Regeln:

1. **Nur ein Auftrag zur Zeit.** Kommt von zwei Hauptscannern gleichzeitig
   einer, gewinnt der erste; der zweite bekommt `Busy` samt laufender
   Auftragskennung. Sonst scannte der Satellit dasselbe Segment doppelt und
   käme sich mit den eigenen Paketen ins Gehege.
2. **Das Ergebnis geht an den, der gefragt hat** — nicht an alle. Ein
   Ergebnis ist die Antwort auf einen Auftrag; ungefragt zugestellt landeten
   in der Gerätetabelle des anderen Funde, die dort niemand angefordert hat.
3. **Zurückgehaltene Ergebnisse gelten je Empfänger.** Wer den Auftrag gab,
   bekommt ihn zugestellt, sobald er wieder da ist — auch wenn der andere
   längst wieder verbunden ist.
4. **Abbrechen darf jeder freigegebene Empfänger**, nicht nur der
   Auftraggeber. Grund: ein hängender Auftrag sperrt den Satelliten für alle
   (`Busy`), und wer gerade davorsitzt, soll ihn freibekommen, ohne den
   Auftraggeber suchen zu müssen. Abschaltbar über die Einstellung
   `AllowCancelFromAnyReceiver` am Satelliten — aus heißt: nur der
   Auftraggeber darf abbrechen. Vorgabe: **an**.

   Wird von fremder Seite abgebrochen, erfährt der Auftraggeber es: er bekommt
   `Cancelled` mit der Auftragskennung und dem Namen dessen, der abgebrochen
   hat. Ein Auftrag verschwindet nie unerklärt.

Jeder Hauptscanner führt seine eigene Satellitenliste und gibt selbst frei;
der Satellit merkt sich den Fingerabdruck **je Empfänger**. Eine Freigabe auf
dem Laptop sagt nichts über den Server aus.

### Nichts wird getippt

Namen werden **nirgends** von Hand eingegeben:

- Am Satelliten steht ein **Verbinden**-Knopf. Er baut die Verbindung sofort
  auf, statt auf den nächsten Versuch des Wiederverbindens zu warten — für
  den Fall, dass man beide Seiten gerade nebeneinander einrichtet.
- Der Satellit nennt beim Verbinden seinen **eigenen** Namen. Der Hauptscanner
  legt ihn an und zeigt ihn an; ändern kann man ihn dort nicht, sonst zeigte
  er beim nächsten Verbinden wieder seinen eigenen und die Bereiche zeigten
  ins Leere. Nur eine Notiz ist frei.
- Am Bereich wird der Satellit über eine **Auswahlliste** gewählt, gefüllt aus
  den Namen der bekannten Satelliten. Ein leerer Eintrag bedeutet „von diesem
  Rechner aus".

Folge: Bereiche lassen sich einem Satelliten erst zuweisen, **nachdem** er
sich einmal gemeldet hat. Das ist gewollt — ein zugewiesener Name, den es nie
gab, wäre nur eine stille Fehlerquelle.

Wiedererkannt wird am **Fingerabdruck**, nicht am Namen: benennt sich ein
Satellit um, bleibt es derselbe Eintrag samt Freigabe. Nur ein neuer
Fingerabdruck ergibt einen neuen Eintrag, und der wartet auf Freigabe.

---

## 2. Datenmodell

### Satellitenliste

Ein Eintrag je Standort, nicht je Bereich — sonst steht dieselbe Zuordnung
mehrfach da.

| Feld | Zweck |
|---|---|
| `Name` | Anzeigename, z. B. "IDF2". Meldet der Satellit selbst |
| `Fingerprint` | Fingerabdruck seines Schlüssels — das ist seine Kennung, nicht die IP |
| `Approved` | vom Nutzer freigegeben, siehe Abschnitt 4 |
| `LastSeen` | zuletzt verbunden — nur Anzeige |
| `Version`, `Os` | seine Anwendungsversion und Plattform — nur Anzeige |
| `RemoteAddress` | von wo er sich zuletzt gemeldet hat — nur Anzeige |

Adresse und Port stehen **nicht** in der Liste: der Satellit kommt von selbst,
seine Adresse ist damit ein Beobachtungswert, keine Einstellung.

### Bereich (`ScanScope`)

| Feld | Bedeutung |
|---|---|
| `GatewayIP` | **Neue Bedeutung:** der Router dieses Netzes. Netzinfo wie der DNS-Server |
| `ScannedBy` | Verweis auf einen Satelliten. Leer = von diesem Rechner aus |

Ein Wert, zu dem es **keinen Satelliten mehr gibt**, zählt wie leer: die
Auswahl in der Maske zeigt ihn ohnehin nicht an, und was dort leer steht, läuft
örtlich. Beim Laden wird er auf leer zurückgesetzt.

`GatewayPort` entfällt — ein Router hat keinen Port.

**Das Gateway ist kein Satellitenfeld.** Es beschreibt das Netz und gibt TTL,
Topologie und Rogue-DHCP ihren Bezugspunkt.

Es ist eine **Übersteuerung, kein Ersatz**: bleibt das Feld leer, wird
weiterhin das Gateway des lokalen Adapters genommen
(`LegacyScanMethod.GatewayDnsFallback`) — auch wenn dasselbe für alle Bereiche
gilt. In diesem Netz ist das richtig so. Das Feld dient dem Fall, dass ein
Bereich einen anderen Router hat als der Adapter, über den gescannt wird.

---

## 3. Kein Doppelscannen

1. Vor dem Lauf werden die ausgewählten Bereiche nach `ScannedBy` gruppiert.
2. Jeder Satellit bekommt **genau einen** Auftrag mit **allen** seinen
   Bereichen — nicht einen je Bereich.
3. Bereiche ohne `ScannedBy` laufen örtlich — ebenso Bereiche, deren
   `ScannedBy` auf keinen vorhandenen Satelliten zeigt.
4. Ein Bereich läuft entweder örtlich **oder** über einen Satelliten, nie
   beides.
5. Der Satellit nimmt keinen zweiten Auftrag an, solange einer läuft: er
   antwortet mit `Busy` und der laufenden Auftragskennung.
6. Ist ein Satellit gerade nicht verbunden, werden seine Bereiche
   übersprungen und im Ergebnis als „nicht gescannt" ausgewiesen — nicht
   stillschweigend örtlich gescannt, denn das brächte falsche Ergebnisse
   (kein ARP, andere Laufzeiten).

---

## 4. Anmeldung — der Kern

Anforderung: **niemand soll beim Installieren etwas hinterlegen oder
kopieren müssen.** Der Satellit bekommt nur Name/Adresse und Port des
Hauptscanners; das ist kein Geheimnis.

### Warum „dieselbe Sprache sprechen" nicht reicht

Die Anwendung liegt offen auf GitHub. Wer das Protokoll spricht, hat sie
einfach heruntergeladen. Entscheidend ist, wer hier das lohnende Ziel ist:
**der Satellit**, denn er ist eine Scan-Maschine mit erhöhten Rechten mitten
in einem Segment. Wer sich ihm gegenüber als Hauptscanner ausgibt, kann ihm
beliebige Aufträge erteilen und bekommt die Ergebnisse frei Haus — eine
fertige Netzaufklärung. Dafür genügt es, den Namen zu übernehmen, auf den er
sich verbindet.

Umgekehrt kann sich jeder, der den Port des Hauptscanners erreicht, als
Satellit ausgeben und die Gerätetabelle mit erfundenen Funden füllen.

### Empfehlung: Vertrauen beim ersten Mal, ein Klick

Das ist das Verfahren, das ohne vorher verteiltes Material auskommt und
trotzdem nicht blind ist — dasselbe Prinzip wie bei SSH:

1. Beide Seiten erzeugen beim **ersten Start** selbst ein Schlüsselpaar. Kein
   Installationsschritt, nichts zu kopieren.
2. Der Satellit verbindet sich, TLS, beide zeigen ihren Schlüssel.
3. Der Hauptscanner kennt den Fingerabdruck noch nicht: der Satellit
   erscheint in der Liste als **„wartet auf Freigabe"**, mit Name,
   Fingerabdruck, Version und Herkunftsadresse. Er bekommt **keine** Aufträge.
4. Der Nutzer gibt ihn mit **einem Klick** frei. Ab da ist der Fingerabdruck
   die Kennung des Satelliten.
5. Der Satellit merkt sich beim ersten freigegebenen Austausch den
   Fingerabdruck des Hauptscanners. Ändert er sich später, verweigert er die
   Arbeit und schreibt es in sein Protokoll.

Der einzige menschliche Schritt ist ein Klick **am Hauptscanner** — dort, wo
der Nutzer ohnehin sitzt. Am Satelliten ist nichts zu tun.

**Nebenwirkung, die zum Laptop passt:** Die Kennung hängt am Schlüssel, nicht
an der Adresse. Der Hauptscanner darf die IP wechseln, ohne dass die
Freigabe bricht.

Ein Fingerabdruck lässt sich in der Liste wieder entziehen; dann meldet sich
der Satellit erneut als „wartet auf Freigabe".

---

## 5. Ergebnisse und Verbindungsabbruch

**Der Satellit scannt fertig, auch wenn die Verbindung abreißt, und schickt
danach das vollständige Ergebnis.** Bei 200 Geräten ist das eine kleine
Menge — zusammengepackt einige zehn Kilobyte.

Daraus folgt:

- **Kein Häppchenweise-Übertragen der Funde.** Ein Auftrag liefert **ein**
  Ergebnis, vollständig. Das ist einfacher und überlebt jeden Abbruch.
- **Fortschrittsmeldungen** laufen trotzdem, solange die Verbindung steht.
  Sie sind flüchtig: geht die Verbindung weg, fehlt nur die Anzeige, nicht
  das Ergebnis.
- Der Satellit **legt das fertige Ergebnis auf die Platte**, bis der Empfang
  bestätigt ist. Ein Neustart des Dienstes darf einen einstündigen Scan nicht
  vernichten.
- Nach der Bestätigung (`ResultAck` mit der Auftragskennung) wird es
  gelöscht.
- Meldet sich der Satellit wieder und hat noch ein unbestätigtes Ergebnis,
  liefert er es sofort nach — auch wenn inzwischen niemand darauf wartet.

---

## 6. Transport und Nachrichten

Eine TCP-Verbindung, TLS darüber, Nachrichten als:

```
[4 Byte Länge, big-endian][UTF-8 JSON, ab 4 KiB mit gzip gepackt]
```

Obergrenze je Nachricht 32 MiB — schützt vor einer kaputten Längenangabe und
reicht für ein vollständiges Ergebnis mit Reserve.

### Ports sind einstellbar, nicht fest im Quelltext

In manchen Netzen sind nur bestimmte Ports erlaubt. Darum ist **jeder** Port
eine Einstellung, nirgends eine Konstante im Programm:

| Port | Wo eingestellt | Vorgabe |
|---|---|---|
| Port, auf dem der Hauptscanner lauscht | Einstellungen des Hauptscanners | 27411 |
| Port, zu dem der Satellit verbindet | je Eintrag in seiner Empfängerliste | 27411 |
| Port zwischen Oberfläche und Dienst (localhost, Abschnitt 7) | Einstellungen | 27412 |

Die Vorgabe 27411 ist nur ein Startwert — sie liegt außerhalb der üblichen
Bereiche und ist nirgends vergeben. Weil der Satellit den Port **je
Empfänger** führt, darf derselbe Satellit einen Hauptscanner auf 443 und
einen anderen auf 27411 erreichen; das hilft dort, wo nur wenige Ports nach
draußen dürfen.

Ändert sich der Port des Hauptscanners, müssen die Satelliten davon erfahren.
Damit sie nicht ins Leere laufen, wird die Änderung **erst nach dem letzten
Verbindungsabbau wirksam** und der neue Port vorher über die bestehenden
Verbindungen bekanntgegeben (`ListenPortChanged`) — sonst muss jeder Satellit
von Hand nachgezogen werden.

Satellit → Hauptscanner:

| Nachricht | Inhalt |
|---|---|
| `Hello` | Protokollversion, Name, Anwendungsversion, Betriebssystem |
| `Progress` | Verfahren, gesendet/geantwortet/gesamt — speist die dreiteilige Anzeige |
| `Accepted` / `Busy` | Auftrag angenommen, oder es läuft schon einer |
| `Result` | Auftragskennung, **alle** Funde und Befunde, je Fund die Bereichskennung |
| `Cancelled` | Auftragskennung und wer abgebrochen hat — geht an den Auftraggeber |
| `Error` | Klartext, für den Nutzer verwendbar |
| `Pong` | Antwort auf `Ping` |

Hauptscanner → Satellit:

| Nachricht | Inhalt |
|---|---|
| `Welcome` / `Pending` | freigegeben, oder: wartet auf Freigabe |
| `Job` | Auftragskennung, Bereiche, vollständige `ScanSettings`, Verfahrensliste |
| `Cancel` | Auftragskennung |
| `ResultAck` | Ergebnis angekommen, darf gelöscht werden |
| `ListenPortChanged` | neuer Port des Hauptscanners, für den nächsten Verbindungsaufbau |
| `Ping` | Lebenszeichen |

`Job` trägt die vollständigen `ScanSettings` — das ist die Umsetzung des
Grundsatzes, dass jede örtliche Option auch fernauslösbar ist.

**Wiederverbinden:** Der Satellit versucht es nach einem Abbruch erneut, mit
wachsendem Abstand bis höchstens eine Minute. `Ping`/`Pong` hält die
Verbindung offen und erkennt stille Abbrüche.

**Protokollversion:** starr. Passt sie nicht, sagt der Hauptscanner es im
Klartext und lehnt ab — halb verstandene Aufträge sind schlimmer als eine
klare Meldung.

---

## 7. Auch der Hauptscanner ist ein Dienst

Der Hauptscanner muss erreichbar bleiben, wenn die Oberfläche geschlossen ist
— sonst finden die Satelliten niemanden, sobald der Nutzer das Fenster
zumacht, und ein Ergebnis, das nach Feierabend fertig wird, bleibt liegen.

Daraus folgt, dass die Anwendung in **zwei Teile** zerfällt:

| Teil | Aufgabe |
|---|---|
| **Dienst** | nimmt Satellitenverbindungen an, hält den Zeitplan, erteilt Aufträge, sammelt Ergebnisse, schreibt sie in den Bestand |
| **Oberfläche** | hängt sich an den Dienst, zeigt an, stößt an, verwaltet |

Die Oberfläche redet über **localhost** mit dem Dienst — dieselben Nachrichten
wie in Abschnitt 6, nur ohne Netz dazwischen. Damit gibt es nur **einen**
Weg, auf dem gescannt wird, und nicht zwei Wirklichkeiten.

Offene Punkte dazu, die beim Bauen zu entscheiden sind:

- **Ohne Dienst weiterarbeiten?** Die Oberfläche sollte auch dann laufen,
  wenn kein Dienst installiert ist — dann scannt sie wie heute selbst und
  kennt eben keine Satelliten. Sonst zwingt der Satellitenbetrieb jedem eine
  Installation auf, der ihn gar nicht will.
- **Wem gehört der Bestand?** Läuft der Dienst, schreibt er die
  Scanergebnisse; die Oberfläche liest mit. Zwei Schreiber auf dieselbe Datei
  wären ein Fehler mit Ansage.
- **Der Zeitplan wandert in den Dienst.** Läuft er durch, gibt es kaum noch
  etwas nachzuholen — die Nachholregel aus Abschnitt 9 greift dann nur noch,
  wenn der Rechner selbst aus war.

## 9. Betrieb als Dienst

- Start mit `--satellite` (Windows-Dienst bzw. systemd unter Linux).
- Ohne Oberfläche, Protokoll in eine Datei.
- Konfiguration: die **Liste der Hauptscanner** (je Eintrag Name/Adresse und
  Port), ein eigener Anzeigename und `AllowCancelFromAnyReceiver` (Vorgabe
  an). Der Schlüssel entsteht beim ersten Start von selbst, der Fingerabdruck
  je Empfänger kommt aus der ersten freigegebenen Verbindung.
- Rohsocket-Verfahren brauchen erhöhte Rechte — der Dienst läuft ohnehin
  erhöht, was ICMPv6 und ARP zugutekommt.

---

## 10. Automatischer Scan

Bereiche haben `AutomaticScan` samt Intervall. Der Zeitplan läuft beim
**Hauptscanner** — der Satellit braucht keine eigene Bereichsverwaltung und
keine Uhr.

War der Hauptscanner zum fälligen Zeitpunkt aus, wird **beim nächsten Start
nachgeholt**: er vergleicht `LastScanned` je Bereich mit dem Intervall und
stößt an, was überfällig ist. Mehrere verpasste Termine ergeben **einen**
Lauf, nicht mehrere — nachgeholt wird der Zustand, nicht die Anzahl.

Dafür muss `LastScanned` künftig gespeichert werden; bisher ist es
ausdrücklich flüchtig (`ScanScope.LastScanned`, „Nicht gespeichert").

---

## 11. Offen

- Nichts mehr. Bei Baubeginn zu prüfen: ob die Bündelung „ein Auftrag je
  Satellit" mit der bestehenden Fortschrittsanzeige zusammengeht, die heute
  je Verfahren zählt.
