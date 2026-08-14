using System.Net.Sockets;
using System.Text;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Siemens S7 ueber ISO-on-TCP. 102 ist der Standardport, 1020 kommt bei
    /// abweichend eingerichteten Anlagen vor.
    /// </summary>
    public sealed class S7Probe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.S7;
        public override string Group => ServiceGroups.Industrial;
        public override IReadOnlyList<int> DefaultPorts => [102, 1020];

        /// <summary>Woertlich aus dem alten Schalter uebernommen - kein Byte veraendert.</summary>
        public override byte[] Hello => new byte[]
            {
                0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00, 0x00, 0x01,
                0x00, 0xC0, 0x01, 0x0A, 0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02,
                0x01, 0x02
            };

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // ?? Siemens S7: Antwort auf die COTP-Verbindungsanfrage ist ein
            // TPKT-Paket (0x03 0x00 ...), dessen COTP-Teil den Code 0xD0
            // (Connection Confirm) traegt - an derselben Stelle, an der die
            // eigene Anfrage 0xE0 (Connection Request) trug.
            if (service == ServiceType.S7)
            {
                if (response.Length >= 6 && response[0] == 0x03 && response[1] == 0x00 && response[5] == 0xD0)
                {
                    serviceMatched = true;
                }
            }

            return serviceMatched;
        }

        /// <summary>
        /// Drei Schritte: die uebliche Erkennung, bei Bedarf die Suche nach
        /// dem richtigen Anschlusspunkt, und zum Schluss die Frage, wer da
        /// steht.
        /// <para>
        /// Das Erkennungspaket bleibt unberuehrt und wird als erstes
        /// geschickt. Wer darauf bestaetigt, wird gefunden wie bisher - Byte
        /// fuer Byte derselbe Ablauf.
        /// </para>
        /// <para>
        /// Meldet die Basispruefung dagegen nur "Port offen", wird der
        /// Anschlusspunkt gesucht. Das Erkennungspaket fragt Rack 0, Slot 2 -
        /// dort sitzt die CPU einer S7-300 oder 400. Eine S7-1200 oder 1500
        /// hat sie auf Slot 1, und Slot 2 gibt es bei ihr nicht: sie laesst
        /// die Anfrage unbeantwortet und schliesst die Verbindung. Solche
        /// Steuerungen standen bisher als blosser offener Port in der Liste.
        /// </para>
        /// <para>
        /// Erst wenn ein Anschlusspunkt bestaetigt hat, folgt die Auskunft:
        /// Setup Communication und die SZL-Abfragen. Beides ist lesend. Eine
        /// Steuerung, die nur den COTP-Handschlag beherrscht, laesst die
        /// Setup-Nachricht unbeantwortet - dann bleibt es bei dem, was ohnehin
        /// feststeht.
        /// </para>
        /// </summary>
        public override async Task<PortResult> ProbeAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            PortResult portResult = await base.ProbeAsync(context, address, port, token);

            // Das Paket, mit dem die Verbindung zustande kam - der
            // Auskunftsschritt braucht denselben Anschlusspunkt noch einmal.
            byte[]? accepted = portResult.Status == PortStatus.IsRunning ? Hello : null;
            string? endpoint = null;

            if (accepted is null && portResult.Status == PortStatus.Open)
            {
                TsapCandidate? found = await FindAcceptedTsapAsync(context, address, port, token);

                if (found is not null)
                {
                    accepted = found.Value.Request;
                    endpoint = found.Value.Description;
                    portResult.Status = PortStatus.IsRunning;
                }
            }

            if (accepted is null) return portResult;

            string? info = null;

            try
            {
                info = await ReadIdentificationAsync(context, address, port, accepted, token);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                // Der Fund steht bereits fest; die Auskunft ist die Zugabe.
                // Der haeufigste Fall ist eine Steuerung, die nur den
                // COTP-Handschlag beherrscht: dann laeuft das Lesen der
                // Setup-Antwort in sein Zeitlimit.
            }

            // Auch wenn nichts zu holen war, wird das Protokoll ersetzt - und
            // zwar ausserhalb des try, damit es auch nach einem Zeitlimit
            // geschieht. Sonst bliebe die Notiz der Basispruefung stehen, und
            // die wandert bei diesem Dienst in die Detailansicht: dort stuende
            // dann "Antwort passt zum erwarteten Protokoll" als Auskunft ueber
            // die Steuerung.
            List<string> lines = [];

            // Wo die Verbindung zustande kam, gehoert dazu - aber nur, wenn es
            // nicht der uebliche Anschlusspunkt war. Bei einer S7-300 auf
            // Rack 0, Slot 2 waere die Zeile eine Selbstverstaendlichkeit.
            if (endpoint is not null) lines.Add($"Connection endpoint: {endpoint}");

            if (string.IsNullOrWhiteSpace(info))
            {
                lines.Add("Connection confirmed, but no S7comm identification available.");
            }
            else
            {
                lines.Add(info);
            }

            portResult.PortLog = string.Join(Environment.NewLine, lines);

            return portResult;
        }

        /// <summary>
        /// Ein Anschlusspunkt: das fertige Anfragepaket und seine Beschreibung
        /// im Klartext.
        /// </summary>
        private readonly record struct TsapCandidate(byte[] Request, string Description);

        /// <summary>Wie eine Gegenstelle auf eine Verbindungsanfrage reagiert hat.</summary>
        private enum Attempt
        {
            /// <summary>Bestaetigt - dieser Anschlusspunkt ist der richtige.</summary>
            Confirmed,

            /// <summary>Abgewiesen. Nicht der richtige Punkt, aber jemand hat geantwortet.</summary>
            Rejected,

            /// <summary>Keine Antwort bis zum Zeitlimit.</summary>
            Silent
        }

        /// <summary>
        /// Sucht einen Anschlusspunkt, den die Gegenstelle bestaetigt - in zwei
        /// Runden, deren zweite nur laeuft, wenn sie etwas bringen kann.
        /// <para>
        /// Die erste Runde fragt die gebraeuchlichen Punkte. Bestaetigt einer,
        /// ist die Suche vorbei.
        /// </para>
        /// <para>
        /// Sonst entscheidet das Verhalten der Gegenstelle ueber die zweite
        /// Runde, und nicht eine Einstellung: <b>hat sie abgewiesen</b>, ist sie
        /// ansprechbar, und dann wird der vollstaendige Adressraum durchsucht -
        /// alle Verbindungsarten, alle acht Racks, alle 32 Slots. Gemessen an
        /// zwei Steuerungen weist eine SPS jeden falschen Punkt binnen weniger
        /// Millisekunden ab, darum ist das billig. <b>War sie stumm</b>, wird
        /// abgebrochen: wo nichts antwortet, findet auch der volle Raum nichts,
        /// er wuerde nur Minuten verbrennen.
        /// </para>
        /// <para>
        /// Der Sinn der zweiten Runde ist, dass niemand den Aufbau der Anlage
        /// kennen muss. Wer den Scanner bedient, weiss nicht, auf welchem Rack
        /// und Slot die CPU steckt - das weiss nur, wer sie projektiert hat.
        /// </para>
        /// <para>
        /// Gefragt wird nebenlaeufig, gewertet in fester Reihenfolge, damit bei
        /// mehreren bestaetigten Punkten immer derselbe gewinnt. Ueber allem
        /// liegt ein Gesamtzeitbudget als Sicherung: verhaelt sich eine
        /// Gegenstelle unerwartet, ist danach trotzdem Schluss.
        /// </para>
        /// </summary>
        private static async Task<TsapCandidate?> FindAcceptedTsapAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            // Kuerzer als beim ersten Anlauf: hier geht es nur um die Frage, ob
            // ueberhaupt bestaetigt wird, und es sind viele Versuche.
            int timeoutMs = Math.Min(context.TimeoutMs, 1500);

            List<TsapCandidate> common = [.. CommonCandidates()];

            (TsapCandidate? found, bool responded) = await TryAllAsync(
                address, port, common, timeoutMs, token);

            if (found is not null) return found;

            // Niemand hat geantwortet - die zweite Runde koennte es auch nicht.
            if (!responded) return null;

            List<TsapCandidate> remaining = [.. RemainingCandidates()];

            using var budget = CancellationTokenSource.CreateLinkedTokenSource(token);
            budget.CancelAfter(FullSearchBudgetMs);

            try
            {
                (found, _) = await TryAllAsync(address, port, remaining, timeoutMs, budget.Token);
                return found;
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            {
                // Zeitbudget abgelaufen. Der Befund der ersten Runde bleibt
                // gueltig, es gibt nur keinen Anschlusspunkt dazu.
                return null;
            }
        }

        /// <summary>Obergrenze fuer die vollstaendige Suche, unabhaengig davon, wie sie laeuft.</summary>
        private const int FullSearchBudgetMs = 5000;

        /// <summary>
        /// Fragt alle Kandidaten nebenlaeufig und liefert den ersten
        /// bestaetigten in Reihenfolge - dazu, ob ueberhaupt jemand geantwortet
        /// hat.
        /// </summary>
        private static async Task<(TsapCandidate? Found, bool Responded)> TryAllAsync(
            string address, int port, List<TsapCandidate> candidates, int timeoutMs, CancellationToken token)
        {
            // Sechs gleichzeitig: genug, um die Wartezeiten zu ueberlappen, und
            // wenig genug, dass eine kleine Steuerung nicht an ihre Grenze der
            // gleichzeitigen Verbindungen stoesst.
            using var limit = new SemaphoreSlim(6);

            Task<Attempt>[] attempts = [.. candidates.Select(async candidate =>
            {
                await limit.WaitAsync(token);

                try
                {
                    return await TryTsapAsync(address, port, candidate.Request, timeoutMs, token);
                }
                finally
                {
                    limit.Release();
                }
            })];

            Attempt[] results = await Task.WhenAll(attempts);

            bool responded = false;

            for (int i = 0; i < results.Length; i++)
            {
                if (results[i] == Attempt.Confirmed) return (candidates[i], true);
                if (results[i] == Attempt.Rejected) responded = true;
            }

            return (null, responded);
        }

        /// <summary>Die Verbindungsarten, die im S7-Umfeld vorkommen.</summary>
        private static readonly byte[] ConnectionTypes = [0x01, 0x02, 0x03];

        /// <summary>
        /// Die gebraeuchlichen Anschlusspunkte fuer die erste Runde, in der
        /// Reihenfolge, in der sie gewertet werden: erst Slot 1 - dort sitzt
        /// die CPU einer S7-1200 oder 1500 -, dann Slot 0, dann die uebrigen.
        /// Rack 0 vor Rack 1, und je Stelle die Verbindungsarten PG, OP und
        /// Basic.
        /// <para>
        /// Rack 0, Slot 2 mit Verbindungsart PG fehlt bewusst: das ist das
        /// Erkennungspaket, und wenn diese Suche laeuft, ist es bereits
        /// erfolglos geblieben.
        /// </para>
        /// </summary>
        private static IEnumerable<TsapCandidate> CommonCandidates()
        {
            foreach (int slot in (int[])[1, 0, 2, 3])
            {
                for (int rack = 0; rack <= 1; rack++)
                {
                    foreach (byte type in ConnectionTypes)
                    {
                        if (IsDetectionPacket(type, rack, slot)) continue;

                        yield return Candidate(type, rack, slot);
                    }
                }
            }
        }

        /// <summary>
        /// Alles Uebrige fuer die zweite Runde: der vollstaendige Adressraum
        /// ohne das, was die erste Runde schon hatte.
        /// <para>
        /// Im zweiten TSAP-Byte tragen die oberen drei Bit das Rack und die
        /// unteren fuenf den Slot - mehr als acht Racks und 32 Slots gibt es
        /// also nicht. Mal drei Verbindungsarten sind das 768 Punkte
        /// insgesamt, von denen hier die 24 der ersten Runde fehlen.
        /// </para>
        /// </summary>
        private static IEnumerable<TsapCandidate> RemainingCandidates()
        {
            for (int rack = 0; rack <= 7; rack++)
            {
                for (int slot = 0; slot <= 31; slot++)
                {
                    foreach (byte type in ConnectionTypes)
                    {
                        if (IsDetectionPacket(type, rack, slot)) continue;
                        if (rack <= 1 && slot <= 3) continue;   // hatte die erste Runde

                        yield return Candidate(type, rack, slot);
                    }
                }
            }
        }

        private static bool IsDetectionPacket(byte connectionType, int rack, int slot) =>
            connectionType == 0x01 && rack == 0 && slot == 2;

        private static TsapCandidate Candidate(byte connectionType, int rack, int slot) =>
            new(ConnectionRequest(connectionType, rack, slot),
                $"{TypeName(connectionType)}, rack {rack}, slot {slot}");

        private static string TypeName(byte connectionType) => connectionType switch
        {
            0x01 => "PG",
            0x02 => "OP",
            0x03 => "Basic",
            _ => $"0x{connectionType:X2}"
        };

        /// <summary>
        /// Eine Verbindungsanfrage fuer einen Anschlusspunkt. Bis auf die
        /// beiden letzten Bytes steht hier dasselbe wie im Erkennungspaket;
        /// mit Verbindungsart 0x01, Rack 0 und Slot 2 kommt es Byte fuer Byte
        /// heraus.
        /// <para>
        /// Im zweiten Byte des Ziel-TSAP stecken Rack und Slot zusammen: die
        /// oberen drei Bit tragen das Rack, die unteren fuenf den Slot.
        /// </para>
        /// </summary>
        private static byte[] ConnectionRequest(byte connectionType, int rack, int slot)
        {
            byte destination = (byte)((rack << 5) | (slot & 0x1F));

            return
            [
                0x03, 0x00, 0x00, 0x16,
                0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
                0xC0, 0x01, 0x0A,
                0xC1, 0x02, 0x01, 0x00,
                0xC2, 0x02, connectionType, destination
            ];
        }

        /// <summary>
        /// Schickt eine Verbindungsanfrage und meldet, wie die Gegenstelle
        /// reagiert hat.
        /// <para>
        /// Die Unterscheidung zwischen "abgewiesen" und "stumm" ist der Kern
        /// der zweiten Runde. Abgewiesen heisst: es hat jemand geantwortet, nur
        /// nicht an diesem Punkt - dann lohnt das Weitersuchen. Eine Steuerung
        /// weist einen falschen Punkt binnen weniger Millisekunden ab, meist
        /// indem sie die Verbindung zuruecksetzt oder ohne Antwort schliesst.
        /// </para>
        /// </summary>
        private static async Task<Attempt> TryTsapAsync(
            string address, int port, byte[] request, int timeoutMs, CancellationToken token)
        {
            try
            {
                using var client = new TcpClient();

                Task connect = client.ConnectAsync(address, port, token).AsTask();
                if (await Task.WhenAny(connect, Task.Delay(timeoutMs, token)) != connect) return Attempt.Silent;
                await connect;

                NetworkStream stream = client.GetStream();

                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
                timeout.CancelAfter(timeoutMs);

                await stream.WriteAsync(request, timeout.Token);

                byte[]? confirm = await ReadTpktAsync(stream, timeout.Token);

                if (confirm is null) return Attempt.Rejected;   // ohne Antwort geschlossen

                return confirm.Length >= 6 && confirm[5] == 0xD0
                    ? Attempt.Confirmed
                    : Attempt.Rejected;                         // etwa ein Disconnect Request
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException)
            {
                return Attempt.Silent;                          // eigenes Zeitlimit abgelaufen
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
            {
                // Der Port ist inzwischen zu. Weitersuchen waere sinnlos, aber
                // es ist auch kein Zeichen von Ansprechbarkeit.
                return Attempt.Silent;
            }
            catch (IOException)
            {
                return Attempt.Rejected;                        // Verbindung zurueckgesetzt
            }
            catch (Exception)
            {
                return Attempt.Silent;
            }
        }

        /// <summary>
        /// Verbindung aufbauen, Verstaendigung aushandeln, beide Kennlisten
        /// lesen. <paramref name="connectionRequest"/> ist das Paket, das die
        /// Gegenstelle zuvor bestaetigt hat - ein anderer Anschlusspunkt
        /// wuerde hier wieder abgewiesen.
        /// </summary>
        private static async Task<string?> ReadIdentificationAsync(
            ProbeContext context, string address, int port, byte[] connectionRequest, CancellationToken token)
        {
            using var client = new TcpClient();

            Task connect = client.ConnectAsync(address, port, token).AsTask();
            if (await Task.WhenAny(connect, Task.Delay(context.TimeoutMs, token)) != connect) return null;
            await connect;

            NetworkStream stream = client.GetStream();

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(context.TimeoutMs * 3);
            CancellationToken read = timeout.Token;

            // Verbindungsanfrage - das Paket, das schon einmal bestaetigt wurde.
            await stream.WriteAsync(connectionRequest, read);

            byte[]? confirm = await ReadTpktAsync(stream, read);
            if (confirm is null || confirm.Length < 6 || confirm[5] != 0xD0) return null;

            // Setup Communication: handelt aus, wie gross die Datenpakete
            // sein duerfen. Ohne diesen Schritt beantwortet keine Steuerung
            // eine SZL-Abfrage.
            byte[] setup =
            [
                0x03, 0x00, 0x00, 0x19, 0x02, 0xF0, 0x80,
                0x32, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x08, 0x00, 0x00,
                0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xE0
            ];

            await stream.WriteAsync(setup, read);

            byte[]? negotiated = await ReadTpktAsync(stream, read);
            if (negotiated is null) return null;

            List<string> lines = [];

            // 0x0011 traegt die Bestellnummer, 0x001C die Namen der Anlage
            // und des Moduls samt Seriennummer.
            byte[]? modules = await ReadSzlAsync(stream, 0x0011, read);
            byte[]? components = await ReadSzlAsync(stream, 0x001C, read);

            AppendModuleInfo(lines, modules);
            AppendComponentInfo(lines, components);

            return lines.Count == 0 ? null : string.Join(Environment.NewLine, lines);
        }

        /// <summary>Fragt eine Systemzustandsliste ab und liefert ihren Datenteil.</summary>
        private static async Task<byte[]?> ReadSzlAsync(
            NetworkStream stream, ushort szlId, CancellationToken token)
        {
            byte[] request =
            [
                0x03, 0x00, 0x00, 0x21, 0x02, 0xF0, 0x80,
                0x32, 0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x08,
                0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00,
                0xFF, 0x09, 0x00, 0x04,
                (byte)(szlId >> 8), (byte)(szlId & 0xFF), 0x00, 0x00
            ];

            await stream.WriteAsync(request, token);
            return await ReadTpktAsync(stream, token);
        }

        /// <summary>
        /// Der Datenteil einer SZL-Antwort, ab dem Ruecknahmecode.
        /// <para>
        /// Aufbau: vier Byte TPKT, drei Byte COTP, zehn Byte S7-Kopf, dann der
        /// Parameterteil in der Laenge, die der Kopf nennt - und erst danach
        /// die Daten. Die Parameterlaenge wechselt zwischen Steuerungen,
        /// darum wird sie gelesen und nicht angenommen.
        /// </para>
        /// </summary>
        private static byte[]? SzlData(byte[]? response)
        {
            const int HeaderLength = 7 + 10;

            if (response is null || response.Length < HeaderLength + 2) return null;
            if (response[7] != 0x32) return null;

            int parameterLength = (response[13] << 8) | response[14];
            int start = HeaderLength + parameterLength;

            if (start + 12 > response.Length) return null;
            if (response[start] != 0xFF) return null;   // Ruecknahmecode: 0xFF ist "in Ordnung"

            return response[start..];
        }

        /// <summary>
        /// Die Saetze einer Liste. Jeder ist gleich lang, beginnt mit seiner
        /// Nummer und traegt danach seinen Text.
        /// </summary>
        private static IEnumerable<(int Index, byte[] Payload)> SzlRecords(byte[]? response)
        {
            byte[]? data = SzlData(response);
            if (data is null) yield break;

            int recordLength = (data[8] << 8) | data[9];
            int recordCount = (data[10] << 8) | data[11];

            if (recordLength < 3 || recordCount <= 0) yield break;

            int p = 12;

            for (int i = 0; i < recordCount && p + recordLength <= data.Length; i++)
            {
                int index = (data[p] << 8) | data[p + 1];
                byte[] payload = data[(p + 2)..(p + recordLength)];

                p += recordLength;

                yield return (index, payload);
            }
        }

        /// <summary>
        /// Text aus einem Satz, hoechstens <paramref name="maxLength"/> Zeichen
        /// lang. Die Begrenzung ist noetig, weil hinter dem Text noch Zahlen
        /// stehen koennen - in SZL 0x0011 etwa Bauform und Ausgabestand.
        /// </summary>
        private static string RecordText(byte[] payload, int maxLength)
        {
            int length = Math.Min(maxLength, payload.Length);

            // Nur der druckbare Anfang zaehlt. Die Textfelder einer SZL sind
            // ab dem ersten Byte mit Leerzeichen aufgefuellt; wo stattdessen
            // gleich ein Steuerzeichen steht, ist das Feld keins mit Text,
            // sondern eine Zahl. Ohne diese Bedingung machte die
            // Standortangabe einer S7-1500 aus den Bytes 00 2A ... den Text
            // "*" - kein Standort, sondern das zweite Byte einer Zahl.
            int end = 0;
            while (end < length && payload[end] is >= 0x20 and <= 0x7E) end++;

            string text = Encoding.ASCII.GetString(payload, 0, end).Trim();

            // Ein einzelnes Zeichen ist keine Auskunft, sondern ein Zufall.
            return text.Length >= 2 ? text : string.Empty;
        }

        /// <summary>
        /// SZL 0x0011: Satz 1 traegt die Bestellnummer des Moduls. Sie steht in
        /// den ersten 20 Zeichen; danach folgen Bauform, Ausgabestand der
        /// Baugruppe und des Erzeugnisses.
        /// </summary>
        private static void AppendModuleInfo(List<string> lines, byte[]? response)
        {
            foreach ((int index, byte[] payload) in SzlRecords(response))
            {
                // Satz 1 ist die Baugruppe selbst, Satz 7 ihre Firmware. Satz 6
                // wiederholt meist die Bestellnummer, und die Saetze ab 0x80
                // beschreiben Zubehoer wie die Speicherkarte.
                if (index == 1)
                {
                    string text = RecordText(payload, 20);
                    if (text.Length > 0) lines.Add($"Order number: {text}");
                }
                else if (index == 7)
                {
                    string? version = FirmwareVersion(payload);
                    if (version is not null) lines.Add($"Firmware: {version}");
                }
            }
        }

        /// <summary>
        /// Die Ausgabestaende stehen hinter den 20 Zeichen der Bestellnummer:
        /// zwei Byte Bauform, dann vier Byte Version. Das erste davon ist das
        /// Zeichen 'V', die drei folgenden sind die Zahlen - aus 56 04 05 01
        /// wird V4.5.1.
        /// <para>
        /// <c>null</c>, wenn dort kein 'V' steht: dann traegt der Satz keine
        /// Version, sondern etwas anderes.
        /// </para>
        /// </summary>
        private static string? FirmwareVersion(byte[] payload)
        {
            const int VersionOffset = 22;

            if (payload.Length < VersionOffset + 4) return null;
            if (payload[VersionOffset] != 0x56) return null;   // 'V'

            return $"V{payload[VersionOffset + 1]}.{payload[VersionOffset + 2]}.{payload[VersionOffset + 3]}";
        }

        /// <summary>
        /// SZL 0x001C: die Namen, die jemand bei der Projektierung vergeben
        /// hat - Anlage, Modul, Standort - und die Seriennummer.
        /// </summary>
        private static void AppendComponentInfo(List<string> lines, byte[]? response)
        {
            foreach ((int index, byte[] payload) in SzlRecords(response))
            {
                string? label = index switch
                {
                    1 => "System name",
                    2 => "Module name",
                    3 => "Plant designation",
                    4 => "Copyright",
                    5 => "Serial number",
                    7 => "Module type",
                    9 => "Location",
                    _ => null
                };

                if (label is null) continue;

                string text = RecordText(payload, 32);
                if (text.Length > 0) lines.Add($"{label}: {text}");
            }
        }

        /// <summary>Eine Nachricht mit TPKT-Kopf: die Laenge steht in Byte 2 und 3.</summary>
        private static async Task<byte[]?> ReadTpktAsync(NetworkStream stream, CancellationToken token)
        {
            byte[]? head = await ReadExactAsync(stream, 4, token);
            if (head is null || head[0] != 0x03) return null;

            int length = (head[2] << 8) | head[3];
            if (length is < 4 or > 4096) return null;

            byte[] rest = await ReadExactAsync(stream, length - 4, token) ?? [];

            byte[] all = new byte[length];
            head.CopyTo(all, 0);
            rest.CopyTo(all, 4);
            return all;
        }

        private static async Task<byte[]?> ReadExactAsync(NetworkStream stream, int count, CancellationToken token)
        {
            if (count <= 0) return [];

            byte[] buffer = new byte[count];
            int got = 0;

            while (got < count)
            {
                int read = await stream.ReadAsync(buffer.AsMemory(got, count - got), token);
                if (read <= 0) return null;
                got += read;
            }

            return buffer;
        }
    }
}
