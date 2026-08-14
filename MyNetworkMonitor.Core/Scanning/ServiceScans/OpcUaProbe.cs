using System.Net.Sockets;
using System.Text;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>OPC UA. Gefragt wird mit einer Hello-Nachricht des Binaerprotokolls.</summary>
    public sealed class OpcUaProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.OPCUA;
        public override string Group => ServiceGroups.Industrial;
        public override IReadOnlyList<int> DefaultPorts => [4840];

        /// <summary>Woertlich aus dem alten Schalter uebernommen - kein Byte veraendert.</summary>
        public override byte[] Hello => new byte[]
            {
                0x48, 0x45, 0x4C, 0x46, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
                0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00,
                0x6F, 0x70, 0x63, 0x2E, 0x74, 0x63, 0x70, 0x3A, 0x2F, 0x2F, 0x31, 0x37, 0x33, 0x2E, 0x31, 0x38,
                0x33, 0x2E, 0x31, 0x34, 0x37, 0x2E, 0x31, 0x30, 0x33, 0x3A, 0x34, 0x38, 0x34, 0x30, 0x2F

            };

        /// <summary>Woertlich aus der alten Antwortpruefung uebernommen - keine Bedingung veraendert.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // ?? OPC UA
            if (service == ServiceType.OPCUA)
            {
                if (response.Length >= 4)
                {
                    byte[] opcUaHelloHeader = { 0x48, 0x45, 0x4C, 0x46 }; // HELF
                    byte[] opcUaAckHeader = { 0x41, 0x43, 0x4B, 0x46 };   // ACKF

                    if (response.Take(4).SequenceEqual(opcUaHelloHeader))
                    {
                        //OPC UA Hello Frame erkannt
                        serviceMatched = true;
                    }
                    else if (response.Take(4).SequenceEqual(opcUaAckHeader))
                    {
                        //OPC UA Acknowledge Frame erkannt
                        serviceMatched = true;
                    }
                }
            }

            return serviceMatched;
        }

        /// <summary>
        /// Erst die uebliche Erkennung, und wenn sie gegriffen hat, noch eine
        /// Frage nach den Endpunkten.
        /// <para>
        /// Die Erkennung selbst bleibt unberuehrt: das Hello-Paket und
        /// <see cref="Identify"/> entscheiden weiterhin allein, ob hier OPC UA
        /// laeuft. Das Acknowledge, mit dem sie das tut, enthaelt aber nur
        /// Puffergroessen - wer der Server ist, steht erst in den Endpunkten.
        /// Die zweite Verbindung ist Absicht: die erste hat ihre Aufgabe
        /// erledigt, und ein Fehlschlag hier soll den Befund nicht umstossen.
        /// </para>
        /// </summary>
        public override async Task<PortResult> ProbeAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            PortResult portResult = await base.ProbeAsync(context, address, port, token);

            if (portResult.Status != PortStatus.IsRunning) return portResult;

            string? info = null;

            try
            {
                info = await ReadServerInfoAsync(context, address, port, token);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                // Der Dienst steht bereits fest. Dass die Auskunft darueber
                // hinaus nicht zu holen war, ist kein Grund, den Fund zu
                // verwerfen - viele Server geben ohne Zertifikat nichts heraus.
            }

            // Ausserhalb des try, damit es auch nach einem Zeitlimit greift:
            // sonst bliebe die Notiz der Basispruefung stehen, und die wandert
            // bei diesem Dienst in die Detailansicht.
            portResult.PortLog = string.IsNullOrWhiteSpace(info)
                ? "Acknowledged, but no endpoint information available."
                : info;

            return portResult;
        }

        /// <summary>
        /// Baut einen Sicherheitskanal ohne Verschluesselung auf und fragt die
        /// Endpunkte ab. Ohne diesen Umweg gibt ein OPC-UA-Server seine Kennung
        /// nicht heraus - das Acknowledge des Verbindungsaufbaus traegt sie nicht.
        /// </summary>
        private static async Task<string?> ReadServerInfoAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            using var client = new TcpClient();

            Task connect = client.ConnectAsync(address, port, token).AsTask();
            if (await Task.WhenAny(connect, Task.Delay(context.TimeoutMs, token)) != connect) return null;
            await connect;

            NetworkStream stream = client.GetStream();

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(context.TimeoutMs * 3);
            CancellationToken read = timeout.Token;

            string url = $"opc.tcp://{address}:{port}/";

            // --- Hello, diesmal mit der Adresse des Ziels ---
            //
            // Das Erkennungspaket oben traegt eine fest eingebaute fremde
            // Adresse. Fuer die Ja/Nein-Frage genuegt das - die Server
            // bestaetigen trotzdem -, fuer eine Auskunft nimmt man besser die
            // Adresse, unter der man den Server tatsaechlich anspricht.
            byte[] urlBytes = Encoding.UTF8.GetBytes(url);
            List<byte> hello = [.. "HELF"u8];
            hello.AddRange(BitConverter.GetBytes((uint)(32 + urlBytes.Length)));
            hello.AddRange(BitConverter.GetBytes(0u));          // ProtocolVersion
            hello.AddRange(BitConverter.GetBytes(65535u));      // ReceiveBufferSize
            hello.AddRange(BitConverter.GetBytes(65535u));      // SendBufferSize
            hello.AddRange(BitConverter.GetBytes(10485760u));   // MaxMessageSize
            hello.AddRange(BitConverter.GetBytes(0u));          // MaxChunkCount
            hello.AddRange(BitConverter.GetBytes((uint)urlBytes.Length));
            hello.AddRange(urlBytes);

            await stream.WriteAsync(hello.ToArray(), read);

            (string Type, byte[] Body)? acknowledge = await ReadMessageAsync(stream, read);
            if (acknowledge is null || acknowledge.Value.Type != "ACKF") return null;

            // --- Sicherheitskanal ohne Verschluesselung ---
            List<byte> request = [0x01, 0x00, 0xBE, 0x01];      // OpenSecureChannelRequest (446)
            request.AddRange(RequestHeader(1));
            request.AddRange(BitConverter.GetBytes(0u));        // ClientProtocolVersion
            request.AddRange(BitConverter.GetBytes(0u));        // RequestType: Issue
            request.AddRange(BitConverter.GetBytes(1u));        // SecurityMode: None
            request.AddRange(NullValue);                        // ClientNonce
            request.AddRange(BitConverter.GetBytes(3600000u));  // RequestedLifetime

            List<byte> secureHeader = [.. BitConverter.GetBytes(0u)];   // SecureChannelId
            secureHeader.AddRange(EncodeString("http://opcfoundation.org/UA/SecurityPolicy#None"));
            secureHeader.AddRange(NullValue);                   // SenderCertificate
            secureHeader.AddRange(NullValue);                   // ReceiverCertificateThumbprint
            secureHeader.AddRange(BitConverter.GetBytes(1u));   // SequenceNumber
            secureHeader.AddRange(BitConverter.GetBytes(1u));   // RequestId

            List<byte> open = [.. "OPNF"u8];
            open.AddRange(BitConverter.GetBytes((uint)(8 + secureHeader.Count + request.Count)));
            open.AddRange(secureHeader);
            open.AddRange(request);

            await stream.WriteAsync(open.ToArray(), read);

            (string Type, byte[] Body)? opened = await ReadMessageAsync(stream, read);
            if (opened is null || opened.Value.Type != "OPNF") return null;
            if (!TryReadChannelToken(opened.Value.Body, out uint channelId, out uint tokenId)) return null;

            // --- GetEndpoints ---
            List<byte> endpointRequest = [0x01, 0x00, 0xAC, 0x01];  // GetEndpointsRequest (428)
            endpointRequest.AddRange(RequestHeader(2));
            endpointRequest.AddRange(EncodeString(url));        // EndpointUrl
            endpointRequest.AddRange(NullValue);                // LocaleIds
            endpointRequest.AddRange(NullValue);                // ProfileUris

            List<byte> message = [.. "MSGF"u8];
            message.AddRange(BitConverter.GetBytes((uint)(24 + endpointRequest.Count)));
            message.AddRange(BitConverter.GetBytes(channelId));
            message.AddRange(BitConverter.GetBytes(tokenId));
            message.AddRange(BitConverter.GetBytes(2u));        // SequenceNumber
            message.AddRange(BitConverter.GetBytes(2u));        // RequestId
            message.AddRange(endpointRequest);

            await stream.WriteAsync(message.ToArray(), read);

            (string Type, byte[] Body)? endpoints = await ReadMessageAsync(stream, read);
            if (endpoints is null || endpoints.Value.Type != "MSGF") return null;

            return Summarize(ReadableStrings(endpoints.Value.Body));
        }

        /// <summary>
        /// Aus den Zeichenketten der Antwort das machen, was in der
        /// Detailansicht stehen soll. Sortiert wird nach der Form: eine
        /// Anwendungskennung beginnt mit "urn:", eine Sicherheitsrichtlinie
        /// endet hinter "SecurityPolicy#", ein Endpunkt beginnt mit "opc.tcp".
        /// Was uebrig bleibt und keine Adresse ist, ist der Name.
        /// </summary>
        private static string? Summarize(List<string> strings)
        {
            string? application = null;
            string? applicationUri = null;
            string? productUri = null;
            string? endpoint = null;
            List<string> policies = [];

            foreach (string text in strings)
            {
                if (text.StartsWith("urn:", StringComparison.OrdinalIgnoreCase))
                {
                    applicationUri ??= text;
                }
                else if (text.StartsWith("opc.tcp://", StringComparison.OrdinalIgnoreCase))
                {
                    endpoint ??= text;
                }
                else if (text.Contains("SecurityPolicy#", StringComparison.OrdinalIgnoreCase))
                {
                    string name = text[(text.IndexOf('#') + 1)..];
                    if (!policies.Contains(name)) policies.Add(name);
                }
                else if (text.StartsWith("http://opcfoundation.org", StringComparison.OrdinalIgnoreCase))
                {
                    // Profil- und Transportkennungen sagen nichts ueber das Geraet.
                }
                else if (text.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                {
                    productUri ??= text;
                }
                else if (!LooksLikeLocale(text))
                {
                    application ??= text;
                }
            }

            List<string> lines = [];
            if (!string.IsNullOrWhiteSpace(application)) lines.Add($"Application: {Readable(application)}");
            if (!string.IsNullOrWhiteSpace(applicationUri)) lines.Add($"Application URI: {Readable(applicationUri)}");
            if (!string.IsNullOrWhiteSpace(productUri)) lines.Add($"Product URI: {Readable(productUri)}");
            if (!string.IsNullOrWhiteSpace(endpoint)) lines.Add($"Endpoint: {endpoint}");
            if (policies.Count > 0) lines.Add($"Security policies: {string.Join(", ", policies)}");

            return lines.Count == 0 ? null : string.Join(Environment.NewLine, lines);
        }

        /// <summary>
        /// Loest Prozentzeichen-Ersatzdarstellungen auf, wie sie in einer
        /// Anwendungskennung vorkommen: aus "WAGO%20750" wird "WAGO 750".
        /// <para>
        /// Nur zweistellige Sedezimalfolgen werden ersetzt, und nur zu
        /// druckbaren Zeichen. Ein einzelnes Prozentzeichen im Text bleibt
        /// stehen, statt den Rest der Zeile zu verschlucken.
        /// </para>
        /// </summary>
        private static string Readable(string value)
        {
            if (!value.Contains('%')) return value;

            var result = new StringBuilder(value.Length);

            for (int i = 0; i < value.Length; i++)
            {
                if (value[i] == '%' && i + 2 < value.Length &&
                    Uri.IsHexDigit(value[i + 1]) && Uri.IsHexDigit(value[i + 2]))
                {
                    int code = Convert.ToInt32(value.Substring(i + 1, 2), 16);

                    if (code is >= 0x20 and <= 0x7E)
                    {
                        result.Append((char)code);
                        i += 2;
                        continue;
                    }
                }

                result.Append(value[i]);
            }

            return result.ToString();
        }

        /// <summary>Sprachkennzeichen wie "en-US" gehoeren zum Namen, sind aber nicht der Name.</summary>
        private static bool LooksLikeLocale(string text) =>
            text.Length <= 5 && text.Contains('-');

        /// <summary>
        /// Laengenpraefixierte, druckbare Zeichenketten aus der Antwort.
        /// <para>
        /// Die Antwort vollstaendig zu zerlegen hiesse, den halben
        /// OPC-UA-Datentypsatz nachzubauen - verschachtelte Strukturen,
        /// Felder, Erweiterungsobjekte. Fuer eine Auskunft in der
        /// Detailansicht genuegt es, die Texte einzusammeln: sie tragen ihre
        /// Laenge vor sich her, und was danach nicht druckbar ist, war keiner.
        /// </para>
        /// </summary>
        private static List<string> ReadableStrings(byte[] data)
        {
            List<string> found = [];

            for (int i = 0; i + 4 < data.Length; i++)
            {
                int length = BitConverter.ToInt32(data, i);
                if (length is < 4 or > 300 || i + 4 + length > data.Length) continue;

                bool printable = true;
                for (int j = i + 4; j < i + 4 + length; j++)
                {
                    if (data[j] is < 32 or > 126) { printable = false; break; }
                }

                if (!printable) continue;

                string text = Encoding.UTF8.GetString(data, i + 4, length);
                if (!found.Contains(text)) found.Add(text);
                i += 3 + length;
            }

            return found;
        }

        private static byte[] NullValue => [0xFF, 0xFF, 0xFF, 0xFF];

        private static byte[] EncodeString(string value)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(value);
            List<byte> result = [.. BitConverter.GetBytes((uint)bytes.Length)];
            result.AddRange(bytes);
            return [.. result];
        }

        /// <summary>Der Kopf, den jede Anfrage traegt - ohne Anmeldung, ohne Diagnose.</summary>
        private static byte[] RequestHeader(uint handle)
        {
            List<byte> header = [0x00, 0x00];                   // AuthenticationToken: leere NodeId
            header.AddRange(BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()));
            header.AddRange(BitConverter.GetBytes(handle));     // RequestHandle
            header.AddRange(BitConverter.GetBytes(0u));         // ReturnDiagnostics
            header.AddRange(NullValue);                         // AuditEntryId
            header.AddRange(BitConverter.GetBytes(10000u));     // TimeoutHint
            header.AddRange([0x00, 0x00, 0x00]);                // AdditionalHeader
            return [.. header];
        }

        /// <summary>
        /// Kanalnummer und Token aus der Antwort auf OpenSecureChannel. Beide
        /// muessen in jeder folgenden Nachricht stehen, sonst verwirft der
        /// Server sie ungelesen.
        /// </summary>
        private static bool TryReadChannelToken(byte[] body, out uint channelId, out uint tokenId)
        {
            channelId = 0;
            tokenId = 0;

            try
            {
                int p = 4;                      // SecureChannelId des Kopfes
                p = SkipByteString(body, p);    // SecurityPolicyUri
                p = SkipByteString(body, p);    // SenderCertificate
                p = SkipByteString(body, p);    // ReceiverCertificateThumbprint
                p += 8;                         // SequenceNumber + RequestId
                p += 4;                         // TypeId der Antwort
                p += 8 + 4 + 4 + 1 + 4 + 3;     // ResponseHeader
                p += 4;                         // ServerProtocolVersion

                if (p + 8 > body.Length) return false;

                channelId = BitConverter.ToUInt32(body, p);
                tokenId = BitConverter.ToUInt32(body, p + 4);
                return true;
            }
            catch (ArgumentOutOfRangeException)
            {
                return false;
            }
        }

        private static int SkipByteString(byte[] data, int offset)
        {
            int length = BitConverter.ToInt32(data, offset);
            return offset + 4 + (length > 0 ? length : 0);
        }

        /// <summary>Eine Nachricht des Binaerprotokolls: vier Zeichen Art, vier Byte Laenge, Rumpf.</summary>
        private static async Task<(string Type, byte[] Body)?> ReadMessageAsync(
            NetworkStream stream, CancellationToken token)
        {
            byte[]? head = await ReadExactAsync(stream, 8, token);
            if (head is null) return null;

            string type = Encoding.ASCII.GetString(head, 0, 4);
            uint size = BitConverter.ToUInt32(head, 4);

            // Eine Laengenangabe, der man nicht folgen sollte: ein Server, der
            // sich vertut, wuerde uns sonst einen Puffer in beliebiger Groesse
            // anlegen lassen.
            if (size is < 8 or > 1_000_000) return null;

            byte[] body = size > 8 ? await ReadExactAsync(stream, (int)size - 8, token) ?? [] : [];
            return (type, body);
        }

        private static async Task<byte[]?> ReadExactAsync(NetworkStream stream, int count, CancellationToken token)
        {
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
