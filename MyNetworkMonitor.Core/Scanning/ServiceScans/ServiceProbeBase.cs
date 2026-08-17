using System.Net.Sockets;
using System.Text;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Der Normalfall: eine Verbindung aufbauen, das Hello-Paket schicken -
    /// sofern es eines gibt -, die Antwort lesen und pruefen. 18 der 24
    /// Dienste brauchen nichts anderes; im alten Schalter
    /// <c>ScanServicePortAsync</c> standen dafuer 21 Zweige, die Zeichen fuer
    /// Zeichen dasselbe taten.
    /// <para>
    /// Der Rumpf ist <c>ScanningMethod_Services.ScanPortAsync</c>, woertlich
    /// uebernommen - einschliesslich der Reihenfolge der Zustaende, die die
    /// Ergebnisliste auswertet: <c>Filtered</c> bei Zeitueberschreitung,
    /// <c>Closed</c> bei abgelehnter Verbindung, <c>Open</c> sobald die
    /// Verbindung steht, und <c>IsRunning</c> erst, wenn die Antwort zum
    /// Protokoll passt. Ein offener Port ohne passende Antwort bleibt
    /// <c>Open</c> und traegt spaeter nicht den Namen dieses Dienstes.
    /// </para>
    /// </summary>
    public abstract class ServiceProbeBase : IServiceProbe
    {
        public abstract ServiceType Service { get; }
        public abstract string Group { get; }
        public abstract IReadOnlyList<int> DefaultPorts { get; }

        /// <summary>
        /// Beide bewusst ohne Vorgabe: ein Dienst ohne Hello-Paket und ohne
        /// Antwortpruefung ist keiner, den man erkennen kann. Wer eine neue
        /// Sonde anlegt, soll beim Uebersetzen darauf stossen und nicht erst
        /// daran, dass im Netz nichts gefunden wird.
        /// </summary>
        public abstract byte[] Hello { get; }

        /// <inheritdoc cref="Hello"/>
        public abstract bool Identify(byte[] response);

        /// <summary>Der Normalfall hat nichts vorzubereiten.</summary>
        public virtual Task PrepareAsync(ProbeContext context, IReadOnlyList<string> targets, CancellationToken token) =>
            Task.CompletedTask;

        /// <summary>
        /// Der Satz, der im Protokoll steht, wenn eine Sonde nichts weiter ueber
        /// das Geraet zu sagen hat. Oeffentlich, weil die Detailansicht ihn
        /// erkennen muss: er ist der Beleg einer geglueckten Erkennung, aber
        /// keine Auskunft, und hat unter "MORE DETAILS" nichts verloren.
        /// </summary>
        public const string ProtocolMatched = "Antwort passt zum erwarteten Protokoll.";

        /// <summary>
        /// Was die erste Antwort ueber das Geraet verraet - Version, Software,
        /// Sicherheitslage. <c>null</c>, wenn sie nichts hergibt.
        /// <para>
        /// Der Puffer wird ohnehin gelesen, auch bei Diensten ohne Hello-Paket;
        /// bisher pruefte <see cref="Identify"/> nur ja/nein und der Rest fiel
        /// weg. Ein SSH-Server nennt in derselben Zeile, an der er erkannt wird,
        /// seine Software samt Version - das ist der Unterschied zwischen "SSH
        /// laeuft" und "OpenSSH 8.9p1 auf Ubuntu".
        /// </para>
        /// <para>
        /// Ausdruecklich <b>keine</b> zweite Verbindung und kein Anmeldeversuch:
        /// ausgewertet wird allein, was die Gegenseite von sich aus geschickt
        /// hat. Die Erkennungspakete bleiben davon unberuehrt.
        /// </para>
        /// </summary>
        protected virtual string? Describe(byte[] response) => null;

        /// <summary>
        /// Die Nachfrage auf der <em>bereits stehenden</em> Verbindung, nachdem
        /// der Dienst erkannt ist. Fuer Protokolle, deren Auskunft nicht in der
        /// Begruessung steht, sondern einen zweiten Zug braucht - FTP nennt sein
        /// Betriebssystem erst auf <c>SYST</c>, VNC seine Anmeldeverfahren erst
        /// nach dem Versionsaustausch.
        /// <para>
        /// Es bleibt bei der einen Verbindung, die ohnehin schon steht, und bei
        /// Fragen, die jeder Client vor der Anmeldung stellt. Was hier
        /// zurueckkommt, wird an das Ergebnis von <see cref="Describe"/>
        /// angehaengt.
        /// </para>
        /// <para>
        /// Fehler sind hier kein Fehler des Laufs: bricht die Nachfrage ab,
        /// bleibt der Befund stehen, den die erste Antwort schon getragen hat.
        /// </para>
        /// </summary>
        protected virtual Task<string?> InterrogateAsync(
            NetworkStream stream, byte[] firstResponse, ProbeContext context, CancellationToken token) =>
            Task.FromResult<string?>(null);

        public virtual async Task<PortResult> ProbeAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            var portResult = new PortResult { Ports = new List<int> { port } };
            var logBuilder = new StringBuilder();

            byte[] detectionPacket = Hello;

            for (int attempt = 1; attempt <= context.RetryCount; attempt++)
            {
                token.ThrowIfCancellationRequested();

                using var client = new TcpClient();

                try
                {
                    Task connectTask = client.ConnectAsync(address, port);

                    if (await Task.WhenAny(connectTask, Task.Delay(context.TimeoutMs)) != connectTask)
                    {
                        portResult.Status = PortStatus.Filtered;
                        logBuilder.AppendLine("Timeout: Port möglicherweise durch Firewall blockiert.");
                        portResult.PortLog = logBuilder.ToString();
                        return portResult;
                    }

                    await connectTask; // wirft die eigentliche Verbindungsausnahme, falls es eine gab

                    portResult.Status = PortStatus.Open;

                    // Ein einziger Stream fuer Schreiben und Lesen - TcpClient.GetStream()
                    // liefert zwar bei jedem Aufruf dieselbe zugrundeliegende Verbindung,
                    // aber ihn zwischendurch zu entsorgen (etwa nur um den Schreibteil zu
                    // umklammern) schliesst den Socket mit - der zweite Aufruf traf dann
                    // auf "operation not allowed on non-connected sockets" statt zu lesen.
                    NetworkStream stream = client.GetStream();

                    if (detectionPacket.Length > 0)
                    {
                        await stream.WriteAsync(detectionPacket, 0, detectionPacket.Length, token);
                    }

                    // Immer lesen, auch ohne eigene Nutzlast - Begruessungsprotokolle
                    // wie FTP, MySQL und MariaDB schicken ihre Kennung unaufgefordert.
                    var buffer = new byte[4096];

                    using var readCts = CancellationTokenSource.CreateLinkedTokenSource(token);
                    readCts.CancelAfter(context.TimeoutMs);

                    try
                    {
                        int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, readCts.Token);

                        if (bytesRead > 0)
                        {
                            byte[] response = buffer[..bytesRead];

                            if (Identify(response))
                            {
                                portResult.Status = PortStatus.IsRunning;

                                // Erst lesen, was die Antwort selbst hergibt,
                                // dann - nur wo eine Sonde es braucht - auf
                                // derselben Verbindung nachfragen.
                                string? description = Describe(response);

                                try
                                {
                                    // Eigenes Zeitbudget statt des Restes von
                                    // readCts: dessen Uhr laeuft seit vor der
                                    // ersten Antwort, und ein Server, der sich
                                    // mit der Begruessung Zeit gelassen hat,
                                    // haette fuer die Nachfrage keine mehr.
                                    using CancellationTokenSource askCts =
                                        CancellationTokenSource.CreateLinkedTokenSource(token);
                                    askCts.CancelAfter(context.TimeoutMs);

                                    string? more = await InterrogateAsync(stream, response, context, askCts.Token);

                                    if (!string.IsNullOrWhiteSpace(more))
                                    {
                                        description = string.IsNullOrWhiteSpace(description)
                                            ? more
                                            : description + Environment.NewLine + more;
                                    }
                                }
                                catch (Exception) when (!token.IsCancellationRequested)
                                {
                                    // Zeitlimit, abgewiesene Nachfrage, geschlossene
                                    // Verbindung: der Dienst ist erkannt, nur die
                                    // Zusatzauskunft entfaellt. Kein Grund, den
                                    // Befund des Ports zu verwerfen.
                                }

                                logBuilder.AppendLine(
                                    string.IsNullOrWhiteSpace(description) ? ProtocolMatched : description);
                            }
                            else
                            {
                                logBuilder.AppendLine("Port offen, Antwort kam, passt aber nicht zum erwarteten Protokoll - vermutlich ein anderer Dienst auf demselben Port.");
                            }
                        }
                        else
                        {
                            logBuilder.AppendLine("Port ist offen, aber keine Antwort von einer Anwendung.");
                        }
                    }
                    catch (OperationCanceledException) when (!token.IsCancellationRequested)
                    {
                        // Nur das Zeitlimit der Antwort ist abgelaufen. Ein
                        // Abbruch des ganzen Laufs gehoert dagegen nach oben
                        // durchgereicht und nicht als "dauerte zu lange"
                        // protokolliert.
                        logBuilder.AppendLine("Antwort vom Server dauerte zu lange.");
                    }

                    portResult.PortLog = logBuilder.ToString();
                    return portResult;
                }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.ConnectionRefused)
                    {
                        portResult.Status = PortStatus.Closed;
                        logBuilder.AppendLine("Verbindung verweigert: Kein Dienst lauscht auf diesem Port.");
                        portResult.PortLog = logBuilder.ToString();
                        return portResult;
                    }

                    if (attempt == context.RetryCount)
                    {
                        portResult.Status = PortStatus.NoResponse;
                        logBuilder.AppendLine($"Fehler nach {context.RetryCount} Versuchen: {ex.Message}");
                    }
                }
                catch (IOException ex)
                {
                    // Die Gegenseite hat die Verbindung waehrend des Lesens
                    // zugeschlagen ("connection reset by peer"). Das ist ein
                    // Ergebnis dieses einen Ports und kein Fehler des Laufs:
                    // die Verbindung stand, also bleibt es bei "offen", nur
                    // ohne verwertbare Antwort.
                    //
                    // Ungefangen kam die Ausnahme frueher bis in den Ablauf
                    // hinauf und beendete den ganzen Dienstelauf - alles, was
                    // nach dem betroffenen Dienst an der Reihe gewesen waere,
                    // wurde nie geprueft.
                    logBuilder.AppendLine($"Verbindung wurde von der Gegenseite geschlossen: {ex.Message}");

                    portResult.PortLog = logBuilder.ToString();
                    return portResult;
                }
            }

            portResult.PortLog = logBuilder.ToString();
            return portResult;
        }

        /// <summary>
        /// Liest eine Protobuf-Varint-Zahl ab <paramref name="offset"/> bis zum
        /// Ende von <paramref name="data"/>.
        /// <para>
        /// Streng: die Zahl muss genau am Ende aufhoeren. Ein abgeschnittenes oder
        /// ueberlanges Feld gilt als kein Treffer - sonst wuerde beliebiges
        /// Rauschen als gueltige Zahl durchgehen.
        /// </para>
        /// </summary>
        protected static bool TryReadVarint(byte[] data, int offset, out int value)
        {
            value = 0;
            int shift = 0;

            for (int i = offset; i < data.Length; i++)
            {
                if (shift > 28) return false;

                value |= (data[i] & 0x7F) << shift;
                shift += 7;

                // Letztes Byte der Zahl: das Fortsetzungsbit fehlt.
                if ((data[i] & 0x80) == 0) return i == data.Length - 1;
            }

            return false;
        }

        /// <summary>
        /// Liest den Versionstext aus der Begruessung eines Servers der
        /// MySQL-Familie. <c>null</c>, wenn die Antwort keine solche Begruessung ist.
        /// <para>
        /// Aufbau des Pakets (HandshakeV10, gleich bei MySQL und MariaDB):
        /// 3 Byte Nutzlastlaenge (little-endian), 1 Byte Sequenznummer - bei der
        /// Begruessung immer 0 -, dann die Nutzlast: 1 Byte Protokollversion (10),
        /// der Versionstext mit abschliessender Null, 4 Byte Verbindungsnummer,
        /// 8 Byte des Zufallswerts fuer die Anmeldung, 1 Fuellbyte 0.
        /// </para>
        /// <para>
        /// Geprueft wird das Geruest, nicht der Inhalt: Laengen sind keine
        /// Konstanten. Fest sind allein Sequenznummer, Protokollversion, das
        /// Fuellbyte an der Stelle, die sich aus der Textlaenge ergibt, und dass
        /// der Text druckbar und mit Null abgeschlossen ist. Das alles zugleich
        /// faellt bei einem fremden Dienst auf demselben Port nicht zufaellig an.
        /// </para>
        /// </summary>
        protected static string? ReadMySqlServerVersion(byte[] response)
        {
            // Laenger meldet sich kein Server; die Grenze faengt einen Puffer ab,
            // in dem zufaellig lange keine Null steht.
            const int MaxVersionLength = 64;

            if (response.Length < 5) return null;
            if (response[3] != 0x00) return null;   // Sequenznummer der Begruessung
            if (response[4] != 0x0A) return null;   // Protokollversion 10

            int payloadLength = response[0] | response[1] << 8 | response[2] << 16;

            // Kuerzer als das Pflichtgeruest kann eine Begruessung nicht sein:
            // Protokollversion, ein Zeichen Version samt Null, Verbindungsnummer,
            // Zufallswert, Fuellbyte.
            if (payloadLength < 1 + 2 + 4 + 8 + 1) return null;

            int end = Array.IndexOf(response, (byte)0x00, 5);
            if (end < 0 || end == 5 || end - 5 > MaxVersionLength) return null;

            for (int i = 5; i < end; i++)
            {
                if (response[i] < 0x20 || response[i] > 0x7E) return null;
            }

            // Das Fuellbyte hinter Verbindungsnummer und Zufallswert. Steht es
            // noch nicht im gelesenen Stueck, ist der Rest der Nutzlast unterwegs -
            // dann gilt das Geruest, das bis hierher gestimmt hat.
            int filler = end + 1 + 4 + 8;
            if (filler < response.Length && response[filler] != 0x00) return null;

            return Encoding.ASCII.GetString(response, 5, end - 5);
        }

        /// <summary>
        /// Die Auskunft eines Servers der MySQL-Familie, wie sie in der
        /// Detailansicht steht. Geteilt von beiden Sonden, weil beide dieselbe
        /// Begruessung vor sich haben und sich nur darin unterscheiden, welche
        /// von ihnen sie anerkennt.
        /// <para>
        /// MariaDB ab 10.0 stellt der echten Version das Scheinpraefix "5.5.5-"
        /// voran. Angezeigt wird die echte Version; das Praefix ist ein Kniff
        /// fuer alte Clients und keine Auskunft ueber den Server.
        /// </para>
        /// </summary>
        protected static string? MySqlDetails(byte[] response)
        {
            string? version = ReadMySqlServerVersion(response);

            if (version is null)
            {
                // Kein Handshake, aber vielleicht das Fehlerpaket, mit dem ein
                // Server die Verbindung abweist - es nennt den Grund im
                // Klartext, und der ist selbst eine Auskunft ("Host ... is not
                // allowed to connect").
                if (response.Length < 7 || response[3] != 0x00 || response[4] != 0xFF) return null;

                // Aufbau des Fehlerpakets hinter der 0xFF: zwei Byte Fehlernummer,
                // ab Protokoll 4.1 dann ein '#' mit fuenf Zeichen Zustandscode,
                // und erst danach der Text. Wird die Nummer nicht uebersprungen,
                // steht ihr unteres Byte als Buchstabe vor der Meldung.
                int at = 5;

                int code = response[at] | response[at + 1] << 8;
                at += 2;

                if (at < response.Length && response[at] == (byte)'#') at += 6;
                if (at >= response.Length) return null;

                string message = Printable(Encoding.ASCII.GetString(response, at, response.Length - at));

                // Die Nummer gehoert dazu: 1130 heisst "Host nicht zugelassen",
                // 1045 "Anmeldung abgelehnt" - zwei sehr verschiedene Lagen.
                return message.Length > 0 ? $"Rejected ({code}): {message}" : null;
            }

            string real = version.StartsWith("5.5.5-", StringComparison.Ordinal) ? version[6..] : version;

            return real.Length > 0 ? $"Version: {real}" : null;
        }

        /// <summary>
        /// Schickt eine Textzeile und liest die Antwort - der Ablauf jedes
        /// zeilenweisen Protokolls (FTP, SMTP, POP3). Leerer Text, wenn nichts
        /// zurueckkommt.
        /// </summary>
        protected static async Task<string> AskLineAsync(
            NetworkStream stream, string command, CancellationToken token)
        {
            byte[] request = Encoding.ASCII.GetBytes(command + "\r\n");
            await stream.WriteAsync(request, token);

            return await ReadTextAsync(stream, token);
        }

        /// <summary>
        /// Liest, was gerade anliegt, und gibt es als Text zurueck. Bricht das
        /// Zeitlimit dazwischen, gilt das bereits Gelesene - eine halbe Antwort
        /// ist mehr als keine.
        /// </summary>
        protected static async Task<string> ReadTextAsync(NetworkStream stream, CancellationToken token)
        {
            byte[] buffer = new byte[4096];

            try
            {
                int read = await stream.ReadAsync(buffer, token);
                return read > 0 ? Encoding.ASCII.GetString(buffer, 0, read) : string.Empty;
            }
            catch (Exception)
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// Die erste Zeile eines Textes, ohne Zeilenende und ohne Steuerzeichen.
        /// Was ein Server als Begruessung schickt, ist Text fuer Menschen - aber
        /// nichts hindert ihn daran, Bytes mitzuschicken, die in einer
        /// Oberflaeche nichts zu suchen haben.
        /// </summary>
        protected static string FirstLine(string text)
        {
            if (string.IsNullOrEmpty(text)) return string.Empty;

            int end = text.IndexOfAny(['\r', '\n']);
            string line = end >= 0 ? text[..end] : text;

            return Printable(line);
        }

        /// <summary>
        /// Nur druckbare Zeichen, auf eine Zeilenlaenge begrenzt. Schutz gegen
        /// Rohbytes und gegen einen Server, der auf eine harmlose Frage mit
        /// Kilobytes antwortet.
        /// </summary>
        protected static string Printable(string text, int maxLength = 200)
        {
            if (string.IsNullOrEmpty(text)) return string.Empty;

            StringBuilder clean = new(Math.Min(text.Length, maxLength));

            foreach (char c in text)
            {
                if (clean.Length >= maxLength) break;
                if (c is >= ' ' and <= '~') clean.Append(c);
            }

            return clean.ToString().Trim();
        }

        public override string ToString() => $"{Service} [{string.Join(", ", DefaultPorts)}]";
    }
}
