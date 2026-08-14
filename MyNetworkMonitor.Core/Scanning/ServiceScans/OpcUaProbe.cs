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
        /// Liest die BuildInfo eines Servers ueber eine <b>anonyme</b> Sitzung:
        /// Hersteller, Softwarestand und Baudatum. <c>null</c>, wenn der Server
        /// keine anonyme Sitzung zulaesst oder nichts Verwertbares liefert.
        /// <para>
        /// Dies ist der einzige Schritt, der ueber die reine Auskunft
        /// hinausgeht und eine Sitzung <em>aufbaut</em>. Er laeuft ausdruecklich
        /// nur ohne Zugangsdaten - der Scanner fuehrt keine Passwoerter mit -,
        /// und nur dort, wo sonst keine Firmware zu bekommen ist. Ein Server,
        /// der anonyme Sitzungen ablehnt, liefert hier nichts, und dabei bleibt es.
        /// </para>
        /// </summary>
        internal static async Task<string?> ReadBuildInfoAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            using var client = new TcpClient();

            Task connect = client.ConnectAsync(address, port, token).AsTask();
            if (await Task.WhenAny(connect, Task.Delay(context.TimeoutMs, token)) != connect) return null;
            await connect;

            NetworkStream stream = client.GetStream();

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeout.CancelAfter(context.TimeoutMs * 4);
            CancellationToken read = timeout.Token;

            string url = $"opc.tcp://{address}:{port}/";
            byte[] urlBytes = Encoding.UTF8.GetBytes(url);

            // --- Hello ---
            List<byte> hello = [.. "HELF"u8];
            hello.AddRange(BitConverter.GetBytes((uint)(32 + urlBytes.Length)));
            hello.AddRange(BitConverter.GetBytes(0u));
            hello.AddRange(BitConverter.GetBytes(65535u));
            hello.AddRange(BitConverter.GetBytes(65535u));
            hello.AddRange(BitConverter.GetBytes(10485760u));
            hello.AddRange(BitConverter.GetBytes(0u));
            hello.AddRange(BitConverter.GetBytes((uint)urlBytes.Length));
            hello.AddRange(urlBytes);
            await stream.WriteAsync(hello.ToArray(), read);

            if (await ReadMessageAsync(stream, read) is not { Type: "ACKF" }) return null;

            // --- Sicherheitskanal ohne Verschluesselung ---
            List<byte> openBody = [0x01, 0x00, 0xBE, 0x01];
            openBody.AddRange(RequestHeader(1));
            openBody.AddRange(BitConverter.GetBytes(0u));
            openBody.AddRange(BitConverter.GetBytes(0u));
            openBody.AddRange(BitConverter.GetBytes(1u));
            openBody.AddRange(NullValue);
            openBody.AddRange(BitConverter.GetBytes(3600000u));

            List<byte> openHeader = [.. BitConverter.GetBytes(0u)];
            openHeader.AddRange(EncodeString("http://opcfoundation.org/UA/SecurityPolicy#None"));
            openHeader.AddRange(NullValue);
            openHeader.AddRange(NullValue);
            openHeader.AddRange(BitConverter.GetBytes(1u));
            openHeader.AddRange(BitConverter.GetBytes(1u));

            List<byte> open = [.. "OPNF"u8];
            open.AddRange(BitConverter.GetBytes((uint)(8 + openHeader.Count + openBody.Count)));
            open.AddRange(openHeader);
            open.AddRange(openBody);
            await stream.WriteAsync(open.ToArray(), read);

            (string Type, byte[] Body)? opened = await ReadMessageAsync(stream, read);
            if (opened is not { Type: "OPNF" }) return null;
            if (!TryReadChannelToken(opened.Value.Body, out uint channel, out uint tokenId)) return null;

            // --- CreateSession ---
            List<byte> create = [0x01, 0x00, 0xCD, 0x01];   // CreateSessionRequest (461)
            create.AddRange(RequestHeader(2));
            create.AddRange(EncodeString("urn:mynetworkmonitor:client"));   // ClientDescription.ApplicationUri
            create.AddRange(EncodeString("urn:mynetworkmonitor:client"));   // ProductUri
            create.AddRange([0x02]);                                        // ApplicationName: nur Text
            create.AddRange(EncodeString("MyNetworkMonitor"));
            create.AddRange(BitConverter.GetBytes(1u));                     // ApplicationType: Client
            create.AddRange(NullValue);                                     // GatewayServerUri
            create.AddRange(NullValue);                                     // DiscoveryProfileUri
            create.AddRange(NullValue);                                     // DiscoveryUrls
            create.AddRange(NullValue);                                     // ServerUri
            create.AddRange(EncodeString(url));                            // EndpointUrl
            create.AddRange(EncodeString("MyNetworkMonitor"));            // SessionName
            byte[] nonce = new byte[32];
            Random.Shared.NextBytes(nonce);
            create.AddRange(BitConverter.GetBytes(32u));                    // ClientNonce
            create.AddRange(nonce);
            create.AddRange(NullValue);                                     // ClientCertificate
            create.AddRange(BitConverter.GetBytes(60000.0));               // RequestedSessionTimeout
            create.AddRange(BitConverter.GetBytes(0u));                     // MaxResponseMessageSize
            await SendSecureMessage(stream, channel, tokenId, 2, 2, create, read);

            (string Type, byte[] Body)? session = await ReadMessageAsync(stream, read);
            if (session is not { Type: "MSGF" }) return null;

            byte[] sb = session.Value.Body;
            int q = 16 + 4 + 24;                 // Sicherheitskopf, TypeId, ResponseHeader
            q = SkipNodeId(sb, q);               // SessionId
            int tokenStart = q;
            q = SkipNodeId(sb, q);               // AuthenticationToken
            if (q > sb.Length) return null;
            byte[] authToken = sb[tokenStart..q];

            // --- ActivateSession, anonym ---
            List<byte> activate = [0x01, 0x00, 0xD3, 0x01];   // ActivateSessionRequest (467)
            activate.AddRange(RequestHeader(3, authToken));
            activate.AddRange(NullValue); activate.AddRange(NullValue);   // ClientSignature
            activate.AddRange(NullValue);                                 // SoftwareCertificates
            activate.AddRange(NullValue);                                 // LocaleIds
            byte[] policy = EncodeString("Anonymous");
            activate.AddRange([0x01, 0x00, 0x41, 0x01]);                  // AnonymousIdentityToken (321)
            activate.AddRange([0x01]);                                    // Body als ByteString
            activate.AddRange(BitConverter.GetBytes((uint)policy.Length));
            activate.AddRange(policy);
            activate.AddRange(NullValue); activate.AddRange(NullValue);   // UserTokenSignature
            await SendSecureMessage(stream, channel, tokenId, 3, 3, activate, read);

            (string Type, byte[] Body)? activated = await ReadMessageAsync(stream, read);
            if (activated is not { Type: "MSGF" } || activated.Value.Body.Length < 16 + 4 + 16) return null;

            uint status = BitConverter.ToUInt32(activated.Value.Body, 16 + 4 + 12);   // ServiceResult
            if (status != 0) return null;                // etwa Bad_IdentityTokenRejected

            // --- Read auf die BuildInfo-Knoten ---
            uint[] nodes = [2263, 2264, 2265, 2266, 2267];

            List<byte> readRequest = [0x01, 0x00, 0x77, 0x02];   // ReadRequest (631)
            readRequest.AddRange(RequestHeader(4, authToken));
            readRequest.AddRange(BitConverter.GetBytes(0.0));    // MaxAge
            readRequest.AddRange(BitConverter.GetBytes(3u));     // TimestampsToReturn: Neither
            readRequest.AddRange(BitConverter.GetBytes((uint)nodes.Length));

            foreach (uint node in nodes)
            {
                readRequest.AddRange([0x01, 0x00]);                       // NodeId FourByte, Namensraum 0
                readRequest.AddRange(BitConverter.GetBytes((ushort)node));
                readRequest.AddRange(BitConverter.GetBytes(13u));         // AttributeId: Value
                readRequest.AddRange(NullValue);                          // IndexRange
                readRequest.AddRange([0x00, 0x00]);                       // DataEncoding: leere QualifiedName
                readRequest.AddRange(NullValue);
            }

            await SendSecureMessage(stream, channel, tokenId, 4, 4, readRequest, read);

            (string Type, byte[] Body)? values = await ReadMessageAsync(stream, read);
            if (values is not { Type: "MSGF" }) return null;

            return FormatBuildInfo(values.Value.Body);
        }

        /// <summary>Verpackt einen Rumpf in eine MSG-Nachricht mit Sicherheitskopf und sendet sie.</summary>
        private static async Task SendSecureMessage(
            NetworkStream stream, uint channel, uint tokenId, uint sequence, uint requestId,
            List<byte> body, CancellationToken token)
        {
            List<byte> message = [.. "MSGF"u8];
            message.AddRange(BitConverter.GetBytes((uint)(24 + body.Count)));
            message.AddRange(BitConverter.GetBytes(channel));
            message.AddRange(BitConverter.GetBytes(tokenId));
            message.AddRange(BitConverter.GetBytes(sequence));
            message.AddRange(BitConverter.GetBytes(requestId));
            message.AddRange(body);
            await stream.WriteAsync(message.ToArray(), token);
        }

        /// <summary>Wie <see cref="RequestHeader(uint)"/>, aber mit einem Sitzungstoken statt der leeren NodeId.</summary>
        private static byte[] RequestHeader(uint handle, byte[] authToken)
        {
            List<byte> header = [.. authToken];
            header.AddRange(BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()));
            header.AddRange(BitConverter.GetBytes(handle));
            header.AddRange(BitConverter.GetBytes(0u));
            header.AddRange(NullValue);
            header.AddRange(BitConverter.GetBytes(10000u));
            header.AddRange([0x00, 0x00, 0x00]);
            return [.. header];
        }

        /// <summary>Ueberspringt eine NodeId in ihren verschiedenen Kodierungen.</summary>
        private static int SkipNodeId(byte[] d, int p)
        {
            byte encoding = (byte)(d[p] & 0x0F);
            return encoding switch
            {
                0x00 => p + 2,                                                     // TwoByte
                0x01 => p + 4,                                                     // FourByte
                0x02 => p + 7,                                                     // Numeric
                0x03 => p + 3 + Math.Max(0, BitConverter.ToInt32(d, p + 3)) + 4,   // String
                0x04 => p + 3 + 16,                                                // Guid
                0x05 => p + 3 + Math.Max(0, BitConverter.ToInt32(d, p + 3)) + 4,   // ByteString
                _ => p + 2
            };
        }

        /// <summary>
        /// Macht aus den fuenf gelesenen BuildInfo-Werten die Zeilen fuer die
        /// Detailansicht.
        /// <para>
        /// Die Hersteller belegen die einzelnen Felder uneinheitlich - der eine
        /// legt die Version in "ProductName", der andere in "SoftwareVersion".
        /// Darum wird nicht nach Feldnamen zugeordnet, sondern nach Form: der
        /// Hersteller steht im ersten Feld, die Version ist die erste
        /// versionsartige Zeichenkette, das Baudatum der erste Zeitwert.
        /// </para>
        /// </summary>
        private static string? FormatBuildInfo(byte[] body)
        {
            int p = 16 + 4 + 24;
            if (p + 4 > body.Length) return null;

            int count = BitConverter.ToInt32(body, p); p += 4;
            if (count is < 1 or > 20) return null;

            List<string> texts = [];
            string? date = null;

            for (int i = 0; i < count; i++)
            {
                (string? text, string? asDate) = ReadDataValue(body, ref p);
                if (!string.IsNullOrWhiteSpace(text)) texts.Add(text);
                date ??= asDate;
            }

            if (texts.Count == 0 && date is null) return null;

            List<string> lines = [];

            // Erstes Textfeld ist der Hersteller.
            string? manufacturer = texts.Count > 0 ? texts[0] : null;
            if (!string.IsNullOrWhiteSpace(manufacturer)) lines.Add($"Manufacturer: {manufacturer}");

            string? version = texts.Skip(1).FirstOrDefault(LooksLikeVersion);
            if (!string.IsNullOrWhiteSpace(version)) lines.Add($"Software version: {version}");

            if (!string.IsNullOrWhiteSpace(date)) lines.Add($"Build date: {date}");

            return lines.Count == 0 ? null : string.Join(Environment.NewLine, lines);
        }

        /// <summary>Eine Zeichenkette mit Ziffern und Punkt, oder mit fuehrendem V - etwa "1.2.3.4" oder "V01.02.03".</summary>
        private static bool LooksLikeVersion(string text)
        {
            if (text.Contains('.') && text.Any(char.IsDigit)) return true;
            return text.Length >= 2 && (text[0] is 'V' or 'v') && char.IsDigit(text[1]);
        }

        /// <summary>
        /// Ein DataValue: der Wert und, wo vorhanden, ein Zeitwert. Die Felder
        /// stehen in fester Reihenfolge, jedes nur, wenn sein Bit in der Maske
        /// steht - werden die Zeitstempel nicht abgezogen, verrutscht der
        /// naechste Wert.
        /// </summary>
        private static (string? Text, string? AsDate) ReadDataValue(byte[] d, ref int p)
        {
            if (p >= d.Length) return (null, null);

            byte mask = d[p++];
            string? text = null;
            string? asDate = null;

            if ((mask & 0x01) != 0 && p < d.Length)
            {
                byte variant = d[p++];
                int type = variant & 0x3F;

                switch (type)
                {
                    case 12:                       // String
                    case 15:                       // ByteString
                        int len = BitConverter.ToInt32(d, p); p += 4;
                        if (len > 0 && p + len <= d.Length) { text = Encoding.UTF8.GetString(d, p, len); p += len; }
                        break;

                    case 13:                       // DateTime
                        long ticks = BitConverter.ToInt64(d, p); p += 8;
                        if (ticks > 0)
                        {
                            try { asDate = DateTime.FromFileTimeUtc(ticks).ToString("yyyy-MM-dd"); }
                            catch (ArgumentOutOfRangeException) { }
                        }
                        break;

                    case 21:                       // LocalizedText: Maske, dann Sprache und Text
                        byte lt = d[p++];
                        if ((lt & 0x01) != 0) p = SkipByteString(d, p);
                        if ((lt & 0x02) != 0)
                        {
                            int tl = BitConverter.ToInt32(d, p); p += 4;
                            if (tl > 0 && p + tl <= d.Length) { text = Encoding.UTF8.GetString(d, p, tl); p += tl; }
                        }
                        break;
                }
            }

            if ((mask & 0x02) != 0) p += 4;        // StatusCode
            if ((mask & 0x04) != 0) p += 8;        // SourceTimestamp
            if ((mask & 0x10) != 0) p += 2;        // SourcePicoseconds
            if ((mask & 0x08) != 0) p += 8;        // ServerTimestamp
            if ((mask & 0x20) != 0) p += 2;        // ServerPicoseconds

            return (text?.Trim(), asDate);
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
