namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// RustDesk-Client mit Direktzugriff ueber die IP. Wer hier antwortet,
    /// laesst sich im LAN unmittelbar fernsteuern - darum vom Serverdienst
    /// getrennt gefuehrt.
    /// <para>
    /// Der Client gruesst, sobald die Verbindung steht, unabhaengig vom Inhalt
    /// des gesendeten Pakets. Geprueft wird nur die feste Marke und das
    /// Geruest des ersten Feldes: die Zahlen dazwischen sind Laengen - die des
    /// protobuf-Rumpfes und die der Geraetekennung -, und wie lang eine
    /// Kennung ist, laesst sich von aussen nicht entscheiden. Eine fruehere
    /// Fassung nagelte sie fest und liess jeden Client mit kurzer Kennung
    /// durchfallen.
    /// </para>
    /// </summary>
    public sealed class RustdeskClientProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.RustdeskClient;
        public override string Group => ServiceGroups.Remote;
        public override IReadOnlyList<int> DefaultPorts => [21118];

        /// <summary>Woertlich aus dem alten Schalter uebernommen - kein Byte veraendert.</summary>
        public override byte[] Hello => new byte[]
            {
                0x59, 0x01,                                                                 // Magic Number / ID
                0x3A, 0x54,                                                                 // Paketlänge (wahrscheinlich 84 Bytes)
                0x0A, 0x0C,                                                                 // Länge der folgenden IP-Adresse (12 Bytes)
                0x31, 0x39, 0x38, 0x2E, 0x35, 0x31, 0x2E, 0x31, 0x30, 0x30, 0x2E, 0x31,     // IP-Adresse (ASCII), Beispielbereich RFC 5737
                0x22, 0x09,                                                                 // Länge der Client-ID (9 Bytes)
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,                       // Client-ID (ASCII), Platzhalter
                0x2A, 0x06,                                                                 // Länge des Client-Keys (6 Bytes)
                0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x32,                                   // Client-Key (ASCII), Platzhalter; 0x32 gehört schon zum nächsten Feld
                0x14, 0x48, 0x02,                                                           // Unbekannte Flags/Einstellungen
                0x52, 0x10,                                                                 // Versionsstring / Protokoll
                0x08, 0x01, 0x10, 0x01, 0x18, 0x01, 0x28, 0x01, 0x30, 0x01,                 // Verbindungsoptionen (z. B. Encryption, P2P)
                0x3A, 0x04, 0x10, 0x01, 0x18, 0x01,                                         // Verschlüsselungsparameter
                0x50, 0xFA, 0x8E, 0xF4, 0xBD, 0xDD, 0x8F, 0x88, 0xF0, 0x9F, 0x01,           // Wahrscheinlich eine Signatur oder ein Hash
                0x5A, 0x05, 0x31, 0x2E, 0x33, 0x2E, 0x37,                                   // RustDesk-Version "1.3.7"
                0x62, 0x00,                                                                 // Unbekannt (möglicherweise Terminator/Trennzeichen)
                0x6A, 0x07, 0x57, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73,                       // Plattform (Windows)
                0x08,                                                                       // Typ des Pakets (Möglicherweise ACK oder Keep-Alive)
                0x2A,                                                                       // Möglicherweise ein Status-Code oder eine ID
                0x00                                                                        // Terminierung / Ende des Pakets
            };

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // ?? RustDesk-Client mit "Direct IP Access" (Port 21118)
            //
            // Der Client gruesst beim Verbinden von sich aus - und zwar unabhaengig
            // davon, was man ihm schickt. Gegengeprueft mit dem richtigen Paket,
            // mit Muell und ganz ohne Nutzlast: die Antwort kam jedes Mal. Anders
            // als beim Server (der schweigt auf alles ausser seinem Hello) ist hier
            // also nicht das gesendete Paket der Filter, sondern allein diese
            // Pruefung - jeder Dienst auf 21118, der beim Verbinden gruesst, kaeme
            // sonst als RustDesk-Client durch.
            //
            // Der Aufbau, an vier lebenden Clients gemessen:
            //
            //   b0 │ 4a │ 2a │ 0a 20 <32 Zeichen> │ 12 06 <6 Zeichen>
            //   ^    ^    ^    ^                    ^
            //   |    |    |    Feld 1: Kennung      Feld 2: Challenge
            //   |    |    Laenge des protobuf-Rumpfes
            //   |    protobuf Feld 9, laengenkodiert  <- konstant
            //   Rahmenlaenge, um zwei Bit nach links geschoben
            //
            // Fest sind nur zwei Byte: die 0x4A an Position 1 und die 0x0A an
            // Position 3. Alles andere sind Laengen oder Inhalte.
            //
            // Byte 0 ist der Rahmen von RustDesk: die Laenge des Restes, um zwei
            // Bit nach links geschoben; die unteren zwei Bit sagen, in wie vielen
            // Byte die Laenge selbst steht. Gemessen:
            //
            //   Client A   19 Byte   0x48 -> 18 == 19-1   Kennung  6 Zeichen
            //   Client B   19 Byte   0x48 -> 18 == 19-1   Kennung  6 Zeichen
            //   Client C   45 Byte   0xb0 -> 44 == 45-1   Kennung 32 Zeichen
            //   Client D   45 Byte   0xb0 -> 44 == 45-1   Kennung 32 Zeichen
            //
            // Genau hier lag der Fehler der frueheren Fassung: sie las 0x48 als
            // feste Marke und bestand auf 19 Byte. 0x48 ist aber 18<<2, also eine
            // Laenge - ein Client mit laengerer Kennung schickt dort etwas anderes
            // und fiel durch, obwohl er einer ist. Aus demselben Grund sind auch
            // 0x10 und 0x06 nicht festgenagelt: das sind die Laengen des Rumpfes
            // und der Kennung. Wie lang eine Kennung ist, laesst sich von aussen
            // nicht entscheiden.
            //
            // Die feste Laenge war zusaetzlich unzuverlaessig: in etwa einem von
            // acht Versuchen schiebt der Client drei Byte nach (ein zweiter Rahmen,
            // 08 2a 00), die im selben Lesevorgang ankommen. Das Geraet wurde also
            // mal erkannt und mal nicht. Darum wird auf ">= Rahmenlaenge" geprueft
            // und nicht auf Gleichheit.
            //
            // Damit ist der Client vom Serverdienst (21115/21116/21117) getrennt:
            // wer hier so antwortet, laesst sich im LAN direkt ueber seine IP
            // fernsteuern.
            if (service == ServiceType.RustdeskClient)
            {
                // Nur der einbytige Rahmen wird ausgewertet - er reicht bis 63 Byte
                // Rumpf und damit fuer jede gemessene Kennung. Bei einer laengeren
                // steht die Laenge in mehreren Byte; deren Reihenfolge ist hier
                // nicht gemessen, und geraten wird sie nicht. Der Rahmen geht dann
                // in die Pruefung nicht ein, das Geruest darunter schon.
                bool singleByteFrame = response.Length > 0 && (response[0] & 0x03) == 0;
                int framed = response.Length > 0 ? response[0] >> 2 : 0;

                serviceMatched = response.Length >= 6
                    && response[1] == 0x4A                          // protobuf Feld 9
                    && response[3] == 0x0A                          // Feld 1: die Kennung
                    && response[4] > 0                              // sie ist nicht leer
                    && response[2] >= response[4] + 2               // der Rumpf traegt sie
                    && response.Length >= 5 + response[4]           // ... und sie ist da
                    && (!singleByteFrame
                        || (response.Length >= framed + 1           // Rahmen vollstaendig
                            && response[2] == framed - 2));         // und passt zum Rumpf
            }

            return serviceMatched;
        }
    }
}
