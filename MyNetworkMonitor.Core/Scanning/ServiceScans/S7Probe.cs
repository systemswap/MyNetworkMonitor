using System.Net.Sockets;
using System.Text;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// Siemens S7 over ISO-on-TCP (RFC 1006). 102 is the standard port; 1020
    /// occurs in installations configured differently.
    /// </summary>
    public sealed class S7Probe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.S7;
        public override string Group => ServiceGroups.Industrial;
        public override IReadOnlyList<int> DefaultPorts => [102, 1020];

        /// <summary>
        /// TPKT with a COTP Connection Request (ISO 8073) for TSAP connection
        /// type PG, rack 0, slot 2.
        /// </summary>
        public override byte[] Hello => new byte[]
            {
                0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00, 0x00, 0x01,
                0x00, 0xC0, 0x01, 0x0A, 0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02,
                0x01, 0x02
            };

        /// <summary>Matches a TPKT packet whose COTP code is Connection Confirm (0xD0).</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // Siemens S7: the answer to the COTP connection request is a TPKT
            // packet (0x03 0x00 ...) whose COTP part carries the code 0xD0
            // (Connection Confirm), at the same position where the request
            // carried 0xE0 (Connection Request).
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
        /// Three steps: the common detection, if needed the search for the
        /// correct connection endpoint (TSAP), and finally the question of
        /// who is there.
        /// <para>
        /// The detection packet is sent first. A device that confirms it is
        /// found by the common procedure alone.
        /// </para>
        /// <para>
        /// If the base check reports only "port open", the endpoint is
        /// searched. The detection packet asks for rack 0, slot 2, where the
        /// CPU of an S7-300 or S7-400 sits. An S7-1200 or S7-1500 has it in
        /// slot 1 and has no slot 2: it leaves the request unanswered and
        /// closes the connection. Without the search, such controllers would
        /// appear as a mere open port.
        /// </para>
        /// <para>
        /// Only after an endpoint has confirmed does the information request
        /// follow: Setup Communication and the SZL queries. Both are read-only.
        /// A controller that supports only the COTP handshake leaves the setup
        /// message unanswered; the finding then stays as it is.
        /// </para>
        /// </summary>
        public override async Task<PortResult> ProbeAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            PortResult portResult = await base.ProbeAsync(context, address, port, token);

            // The packet that established the connection; the information
            // step needs the same endpoint again.
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
                // The finding is already established; the identification is
                // extra. The most common case is a controller that supports
                // only the COTP handshake: reading the setup answer then runs
                // into its timeout.
            }

            // The log is replaced even if nothing was available, outside the
            // try so that this also happens after a timeout. Otherwise the note
            // of the base check would remain and, for this service, end up in
            // the details view as if it were information about the controller.
            List<string> lines = [];

            // Where the connection was established is included, but only if it
            // was not the usual endpoint. For an S7-300 on rack 0, slot 2 the
            // line would state the obvious.
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
        /// A connection endpoint: the complete request packet and its
        /// plain-text description.
        /// </summary>
        private readonly record struct TsapCandidate(byte[] Request, string Description);

        /// <summary>How the remote side reacted to a connection request.</summary>
        private enum Attempt
        {
            /// <summary>Confirmed: this endpoint is the correct one.</summary>
            Confirmed,

            /// <summary>Rejected. Not the correct endpoint, but something answered.</summary>
            Rejected,

            /// <summary>No answer before the timeout.</summary>
            Silent
        }

        /// <summary>
        /// Searches for an endpoint that the remote side confirms, in two
        /// rounds; the second runs only if it can yield something.
        /// <para>
        /// The first round asks the common endpoints. If one confirms, the
        /// search is over.
        /// </para>
        /// <para>
        /// Otherwise the behaviour of the remote side, not a setting, decides
        /// about the second round: <b>if it rejected</b>, it is responsive, and
        /// the complete address space is searched: all connection types, all
        /// eight racks, all 32 slots. Measured on two controllers, a PLC rejects
        /// every wrong endpoint within a few milliseconds, so this is cheap.
        /// <b>If it was silent</b>, the search stops: where nothing answers, the
        /// full space finds nothing either and would only waste minutes.
        /// </para>
        /// <para>
        /// The purpose of the second round is that no knowledge of the
        /// installation is required. The person running the scanner usually
        /// does not know which rack and slot hold the CPU; only whoever
        /// configured it does.
        /// </para>
        /// <para>
        /// Requests run concurrently and are evaluated in a fixed order, so that
        /// with several confirmed endpoints the same one always wins. An overall
        /// time budget acts as a safeguard: if a remote side behaves
        /// unexpectedly, the search still ends.
        /// </para>
        /// </summary>
        private static async Task<TsapCandidate?> FindAcceptedTsapAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            // Shorter than the first attempt: the only question here is whether
            // a confirmation comes at all, and there are many attempts.
            int timeoutMs = Math.Min(context.TimeoutMs, 1500);

            List<TsapCandidate> common = [.. CommonCandidates()];

            (TsapCandidate? found, bool responded) = await TryAllAsync(
                address, port, common, timeoutMs, token);

            if (found is not null) return found;

            // Nothing answered; the second round could not change that.
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
                // Time budget expired. The result of the first round stays
                // valid; there is just no endpoint for it.
                return null;
            }
        }

        /// <summary>Upper limit for the complete search, regardless of how it proceeds.</summary>
        private const int FullSearchBudgetMs = 5000;

        /// <summary>
        /// Asks all candidates concurrently and returns the first confirmed one
        /// in order, plus whether anything answered at all.
        /// </summary>
        private static async Task<(TsapCandidate? Found, bool Responded)> TryAllAsync(
            string address, int port, List<TsapCandidate> candidates, int timeoutMs, CancellationToken token)
        {
            // Six at a time: enough to overlap the waiting times, and few enough
            // that a small controller does not reach its limit of simultaneous
            // connections.
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

        /// <summary>The connection types used with S7 controllers.</summary>
        private static readonly byte[] ConnectionTypes = [0x01, 0x02, 0x03];

        /// <summary>
        /// The common endpoints for the first round, in the order of
        /// evaluation: first slot 1, where the CPU of an S7-1200 or S7-1500
        /// sits, then slot 0, then the others. Rack 0 before rack 1, and for
        /// each position the connection types PG, OP and Basic.
        /// <para>
        /// Rack 0, slot 2 with connection type PG is deliberately missing: that
        /// is the detection packet, and when this search runs, it has already
        /// failed.
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
        /// Everything else for the second round: the complete address space
        /// without what the first round already covered.
        /// <para>
        /// In the second TSAP byte the upper three bits hold the rack and the
        /// lower five the slot, so there are no more than eight racks and 32
        /// slots. Times three connection types that makes 768 endpoints in
        /// total, of which the 24 of the first round are omitted here.
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
                        if (rack <= 1 && slot <= 3) continue;   // covered by the first round

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
        /// A connection request for an endpoint. Except for the last two bytes
        /// it is identical to the detection packet; with connection type 0x01,
        /// rack 0 and slot 2 it matches byte for byte.
        /// <para>
        /// The second byte of the destination TSAP combines rack and slot: the
        /// upper three bits hold the rack, the lower five the slot.
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
        /// Sends a connection request and reports how the remote side reacted.
        /// <para>
        /// The distinction between "rejected" and "silent" is the core of the
        /// second round. Rejected means something answered, just not at this
        /// endpoint, so searching further is worthwhile. A controller rejects a
        /// wrong endpoint within a few milliseconds, usually by resetting the
        /// connection or closing it without an answer.
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

                if (confirm is null) return Attempt.Rejected;   // closed without an answer

                return confirm.Length >= 6 && confirm[5] == 0xD0
                    ? Attempt.Confirmed
                    : Attempt.Rejected;                         // e.g. a Disconnect Request
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                throw;
            }
            catch (OperationCanceledException)
            {
                return Attempt.Silent;                          // own timeout expired
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused)
            {
                // The port is now closed. Searching further would be pointless,
                // and it is no sign of responsiveness either.
                return Attempt.Silent;
            }
            catch (IOException)
            {
                return Attempt.Rejected;                        // connection reset
            }
            catch (Exception)
            {
                return Attempt.Silent;
            }
        }

        /// <summary>
        /// Connects, negotiates communication and reads both identification
        /// lists. <paramref name="connectionRequest"/> is the packet the remote
        /// side confirmed before; a different endpoint would be rejected again.
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

            // Connection request: the packet that was already confirmed once.
            await stream.WriteAsync(connectionRequest, read);

            byte[]? confirm = await ReadTpktAsync(stream, read);
            if (confirm is null || confirm.Length < 6 || confirm[5] != 0xD0) return null;

            // Setup Communication negotiates the maximum PDU size. Without this
            // step no controller answers an SZL query.
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

            // 0x0011 carries the order number, 0x001C the names of the plant
            // and the module, including the serial number.
            byte[]? modules = await ReadSzlAsync(stream, 0x0011, read);
            byte[]? components = await ReadSzlAsync(stream, 0x001C, read);

            AppendModuleInfo(lines, modules);
            AppendComponentInfo(lines, components);

            return lines.Count == 0 ? null : string.Join(Environment.NewLine, lines);
        }

        /// <summary>Queries a system status list (SZL) and returns its answer.</summary>
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
        /// The data part of an SZL answer, starting at the return code.
        /// <para>
        /// Layout: four bytes TPKT, three bytes COTP, ten bytes S7 header, then
        /// the parameter part in the length given by the header, and only
        /// then the data. The parameter length differs between controllers, so
        /// it is read rather than assumed.
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
            if (response[start] != 0xFF) return null;   // return code: 0xFF means "success"

            return response[start..];
        }

        /// <summary>
        /// The records of a list. All have the same length, start with their
        /// index and carry their text after it.
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
        /// Text from a record, at most <paramref name="maxLength"/> characters.
        /// The limit is needed because numbers can follow the text, in SZL
        /// 0x0011 for example module type and revision.
        /// </summary>
        private static string RecordText(byte[] payload, int maxLength)
        {
            int length = Math.Min(maxLength, payload.Length);

            // Only the printable start counts. The text fields of an SZL are
            // padded with spaces from the first byte; where a control character
            // comes first instead, the field holds a number, not text. Without
            // this condition the location of an S7-1500 with the bytes 00 2A ...
            // would become the text "*": not a location, but the second byte of
            // a number.
            int end = 0;
            while (end < length && payload[end] is >= 0x20 and <= 0x7E) end++;

            string text = Encoding.ASCII.GetString(payload, 0, end).Trim();

            // A single character is not information but chance.
            return text.Length >= 2 ? text : string.Empty;
        }

        /// <summary>
        /// SZL 0x0011: record 1 carries the order number of the module in its
        /// first 20 characters, followed by module type and the hardware and
        /// product revisions.
        /// </summary>
        private static void AppendModuleInfo(List<string> lines, byte[]? response)
        {
            foreach ((int index, byte[] payload) in SzlRecords(response))
            {
                // Record 1 is the module itself, record 7 its firmware. Record 6
                // usually repeats the order number, and records from 0x80 on
                // describe accessories such as the memory card.
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
        /// The revision follows the 20 characters of the order number: two
        /// bytes module type, then four bytes version. The first of these is
        /// the character 'V', the three after it are the numbers: 56 04 05 01
        /// becomes V4.5.1.
        /// <para>
        /// <c>null</c> if there is no 'V': the record then carries something
        /// other than a version.
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
        /// SZL 0x001C: the names assigned during configuration (plant, module,
        /// location) and the serial number.
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

        /// <summary>A message with TPKT header (RFC 1006): the length is in bytes 2 and 3.</summary>
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
