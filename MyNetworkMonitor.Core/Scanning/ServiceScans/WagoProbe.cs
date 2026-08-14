using System.Net.Sockets;
using System.Text;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// WAGO-Steuerungen ueber ihren Serviceport 6626 (WBC, das Protokoll ihres
    /// Upload-Werkzeugs). Ein einziges Kommando fragt die Geraetekennung ab,
    /// und die Antwort traegt alles im Klartext: Bestellnummer, Beschreibung,
    /// Seriennummer, Hardware-Stand und die echte Firmware.
    /// <para>
    /// Anders als OPC UA, das nur die CODESYS-Laufzeit kennt, und anders als
    /// BACnet oder SNMP, die am Geraet erst freigeschaltet werden muessen,
    /// steht dieser Port bei laufender Steuerung ohne Zutun offen. Rein lesend.
    /// </para>
    /// <para>
    /// Das Protokoll wurde aus einem Mitschnitt des WAGO-Upload-Werkzeugs
    /// gewonnen - der eigentliche Code des Werkzeugs steckt in einer
    /// proprietaeren nativen Bibliothek und gibt die Bytes nicht her. Anfrage
    /// und Antwort sind gegen zwei Baureihen geprueft.
    /// </para>
    /// </summary>
    public sealed class WagoProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.Wago;
        public override string Group => ServiceGroups.Industrial;
        public override IReadOnlyList<int> DefaultPorts => [6626];

        /// <summary>
        /// Das Kommando 0x0108 ("Geraetekennung lesen") im WBC-Rahmen.
        /// <para>
        /// Aufbau: die Kennung <c>88 12</c>, eine Vorgangsnummer, die die
        /// Gegenstelle nur zurueckspiegelt, vier feste Bytes, acht Nullbytes,
        /// die Laenge des Kommandoteils (2) und das Kommando selbst.
        /// </para>
        /// </summary>
        public override byte[] Hello => new byte[]
            {
                0x88, 0x12,             // WBC-Kennung
                0x01, 0x00,             // Vorgangsnummer (wird gespiegelt)
                0x01, 0x00, 0x01, 0x00, // fester Kopf
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x02, 0x00,             // Laenge des Kommandoteils
                0x08, 0x01              // Kommando 0x0108
            };

        /// <summary>
        /// Eine Antwort ist WAGO, wenn sie die WBC-Kennung traegt und die
        /// Klartext-Kennung enthaelt. Beides zusammen faellt bei einem fremden
        /// Dienst auf demselben Port nicht zufaellig an.
        /// </summary>
        public override bool Identify(byte[] response)
        {
            if (response.Length < 4 || response[0] != 0x88 || response[1] != 0x12) return false;

            return IndexOfAscii(response, "ORDER=") >= 0;
        }

        /// <summary>
        /// Verbinden, das Kommando schicken, die Kennung lesen und in Zeilen
        /// fuer die Detailansicht zerlegen. Eigener Ablauf, weil die Antwort
        /// nicht bei Ja/Nein bleibt, sondern die Felder tragen soll.
        /// </summary>
        public override async Task<PortResult> ProbeAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            var portResult = new PortResult { Ports = new List<int> { port } };
            var log = new StringBuilder();

            for (int attempt = 1; attempt <= context.RetryCount; attempt++)
            {
                token.ThrowIfCancellationRequested();

                using var client = new TcpClient();

                try
                {
                    Task connect = client.ConnectAsync(address, port, token).AsTask();

                    if (await Task.WhenAny(connect, Task.Delay(context.TimeoutMs, token)) != connect)
                    {
                        portResult.Status = PortStatus.Filtered;
                        log.AppendLine("Timeout: Port möglicherweise durch Firewall blockiert.");
                        portResult.PortLog = log.ToString();
                        return portResult;
                    }

                    await connect;   // wirft die Verbindungsausnahme, falls es eine gab
                    portResult.Status = PortStatus.Open;

                    NetworkStream stream = client.GetStream();
                    await stream.WriteAsync(Hello, token);

                    byte[]? response = await ReadResponseAsync(stream, context.TimeoutMs, token);

                    if (response is null || response.Length == 0)
                    {
                        log.AppendLine("Port ist offen, aber keine Antwort von einer Anwendung.");
                        portResult.PortLog = log.ToString();
                        return portResult;
                    }

                    if (Identify(response))
                    {
                        portResult.Status = PortStatus.IsRunning;
                        portResult.PortLog = FormatIdentification(response);
                    }
                    else
                    {
                        log.AppendLine("Port offen, Antwort kam, passt aber nicht zum erwarteten Protokoll - vermutlich ein anderer Dienst auf demselben Port.");
                        portResult.PortLog = log.ToString();
                    }

                    return portResult;
                }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.ConnectionRefused)
                    {
                        portResult.Status = PortStatus.Closed;
                        log.AppendLine("Verbindung verweigert: Kein Dienst lauscht auf diesem Port.");
                        portResult.PortLog = log.ToString();
                        return portResult;
                    }

                    if (attempt == context.RetryCount)
                    {
                        portResult.Status = PortStatus.NoResponse;
                        log.AppendLine($"Fehler nach {context.RetryCount} Versuchen: {ex.Message}");
                    }
                }
                catch (IOException ex)
                {
                    // Die Gegenseite hat die Verbindung waehrend des Lesens
                    // geschlossen - ein Ergebnis dieses Ports, kein Fehler des
                    // Laufs. Die Verbindung stand, also bleibt es bei "offen".
                    log.AppendLine($"Verbindung wurde von der Gegenseite geschlossen: {ex.Message}");
                    portResult.PortLog = log.ToString();
                    return portResult;
                }
            }

            portResult.PortLog = log.ToString();
            return portResult;
        }

        /// <summary>
        /// Liest, bis die Klartext-Kennung vollstaendig da ist. Sie endet mit
        /// dem letzten Semikolon; steht das im Puffer, ist nichts mehr zu holen.
        /// </summary>
        private static async Task<byte[]?> ReadResponseAsync(
            NetworkStream stream, int timeoutMs, CancellationToken token)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(timeoutMs);

            var collected = new List<byte>();
            var buffer = new byte[4096];

            try
            {
                while (collected.Count < 8192)
                {
                    int read = await stream.ReadAsync(buffer, timeout.Token);
                    if (read <= 0) break;

                    collected.AddRange(buffer[..read]);

                    // Sobald die Kennung samt abschliessendem Semikolon steht,
                    // ist die Antwort komplett.
                    byte[] soFar = [.. collected];
                    int order = IndexOfAscii(soFar, "ORDER=");
                    if (order >= 0 && Array.LastIndexOf(soFar, (byte)';') > order) break;

                    if (!stream.DataAvailable) break;
                }
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            {
                // Nur das Lesezeitlimit - was bis hierher kam, wird ausgewertet.
            }

            return collected.Count > 0 ? [.. collected] : null;
        }

        /// <summary>
        /// Macht aus der Semikolon-Liste die Zeilen fuer die Detailansicht. Der
        /// Aufbau ist <c>SCHLUESSEL=Wert;SCHLUESSEL=Wert;</c> - dieselben Namen,
        /// die auch das WAGO-Werkzeug liest.
        /// </summary>
        private static string FormatIdentification(byte[] response)
        {
            int start = IndexOfAscii(response, "ORDER=");
            if (start < 0) return string.Empty;

            // Ab "ORDER=" bis zum ersten nicht druckbaren Zeichen.
            int end = start;
            while (end < response.Length && response[end] is >= 0x20 and <= 0x7E) end++;

            string text = Encoding.ASCII.GetString(response, start, end - start);

            Dictionary<string, string> fields = new(StringComparer.OrdinalIgnoreCase);
            foreach (string part in text.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                int eq = part.IndexOf('=');
                if (eq <= 0) continue;

                string key = part[..eq].Trim();
                string value = part[(eq + 1)..].Trim();
                if (value.Length > 0 && !fields.ContainsKey(key)) fields[key] = value;
            }

            // In fester Reihenfolge und unter sprechenden Namen. "Firmware"
            // steht bewusst so da: daran erkennt der OPC-UA-Nachlauf, dass die
            // Firmware dieses Geraets bereits feststeht.
            (string Key, string Label)[] wanted =
            [
                ("ORDER", "Order number"),
                ("DESCR", "Description"),
                ("SW-VER", "Firmware"),
                ("HW-VER", "Hardware"),
                ("FWL-VER", "Firmware loader"),
                ("SN", "Serial")
            ];

            List<string> lines = [];
            foreach ((string key, string label) in wanted)
            {
                if (fields.TryGetValue(key, out string? value)) lines.Add($"{label}: {value}");
            }

            return lines.Count > 0 ? string.Join(Environment.NewLine, lines) : string.Empty;
        }

        /// <summary>Die Stelle, an der die ASCII-Zeichenkette im Puffer beginnt, oder -1.</summary>
        private static int IndexOfAscii(byte[] haystack, string needle)
        {
            byte[] pattern = Encoding.ASCII.GetBytes(needle);
            if (pattern.Length == 0 || haystack.Length < pattern.Length) return -1;

            for (int i = 0; i <= haystack.Length - pattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (haystack[i + j] != pattern[j]) { match = false; break; }
                }

                if (match) return i;
            }

            return -1;
        }
    }
}
