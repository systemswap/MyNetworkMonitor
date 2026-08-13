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
                                logBuilder.AppendLine("Antwort passt zum erwarteten Protokoll.");
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

        public override string ToString() => $"{Service} [{string.Join(", ", DefaultPorts)}]";
    }
}
