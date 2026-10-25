// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net.Sockets;
using System.Text;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// SECS/GEM over HSMS (SEMI E37). Semiconductor and electronics
    /// manufacturing: the equipment talks to the host system, usually on
    /// port 5000.
    /// <para>
    /// HSMS has two roles. The <em>passive</em> side waits for the
    /// connection; that is the side that can be found here. The
    /// <em>active</em> side establishes the connection itself and has no open
    /// port at all; such equipment is never visible this way, however long
    /// the search.
    /// </para>
    /// </summary>
    public sealed class SecsGemProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.SecsGem;
        public override string Group => ServiceGroups.Industrial;

        /// <summary>
        /// 5000 is convention, not a requirement; HSMS does not prescribe a
        /// port. 5001 and 5002 occur where several tools or interfaces run on
        /// one computer. Other ports can be added in the service manager.
        /// </summary>
        public override IReadOnlyList<int> DefaultPorts => [5000, 5001, 5002];

        /// <summary>
        /// Select.req, the request with which every HSMS connection starts.
        /// <para>
        /// Four bytes length (10), then the header: session ID 0xFFFF, two
        /// unused bytes, PType 0 (SECS-II), SType 1 (Select.req) and four bytes
        /// system bytes, which the answer must repeat.
        /// </para>
        /// </summary>
        public override byte[] Hello => Frame(0xFFFF, 0x00, 0x00, SType.SelectReq, HelloSystemBytes);

        /// <summary>
        /// Fixed system bytes in the detection packet, so that the
        /// "HelloBytePackage" column of the service manager shows the same
        /// bytes on every start. The follow-up requests use their own numbers.
        /// </summary>
        private const uint HelloSystemBytes = 0x00000001;

        /// <summary>
        /// An answer matches if it is an HSMS frame and its control message is
        /// one that may follow a Select.req.
        /// <para>
        /// Not only Select.rsp: equipment already connected to its host allows
        /// no second session and answers with Reject.req. That is not a failure
        /// of detection but its strongest evidence; only an HSMS endpoint
        /// answers that way.
        /// </para>
        /// </summary>
        public override bool Identify(byte[] response)
        {
            if (!TryReadHeader(response, out Header header)) return false;

            return header.PType == 0 && header.SType is
                SType.SelectRsp or SType.DeselectRsp or SType.LinktestRsp or SType.RejectReq;
        }

        /// <summary>
        /// What the select answer itself reveals. The information about the
        /// equipment follows in <see cref="InterrogateAsync"/> on the same
        /// connection.
        /// <para>
        /// This line is always written, even if nothing follows: it confirms
        /// that the session was established, and it keeps the standard text
        /// <see cref="ServiceProbeBase.ProtocolMatched"/> out of the log, where
        /// it does not belong in the details view.
        /// </para>
        /// </summary>
        protected override string? Describe(byte[] response)
        {
            if (!TryReadHeader(response, out Header header)) return null;

            if (header.SType == SType.RejectReq)
            {
                // The reason is in byte 3 of the header. The common case is
                // equipment whose single permitted session is already taken.
                return $"HSMS select rejected (reason {header.Byte3}) - link probably already in use.";
            }

            if (header.SType != SType.SelectRsp) return "HSMS answered, but did not open a session.";

            // Select status other than 0: 1 means "already active", 2 "not
            // ready", 3 "connection exhausted".
            return header.Byte3 == 0
                ? "HSMS select accepted."
                : $"HSMS select refused (status {header.Byte3}).";
        }

        /// <summary>
        /// Asks who is there, on the connection that is already established.
        /// <para>
        /// The same connection is essential: equipment waiting for its host
        /// introduces itself <em>on its own</em> as soon as a session is
        /// established, measured about 800 ms after the select answer. A second
        /// connection gets nothing: the equipment has just directed its attempt
        /// at the first one and then waits for the T5 timer before trying
        /// again. Ten seconds, which no scan waits for.
        /// </para>
        /// <para>
        /// The request is S1F1 "Are You There", and S1F13 only if the service
        /// manager explicitly allows it. Why that is the operator's decision
        /// and not the probe's is described at
        /// <see cref="ProbeContext.ActiveInquiry"/>.
        /// </para>
        /// </summary>
        protected override async Task<string?> InterrogateAsync(
            NetworkStream stream, byte[] firstResponse, ProbeContext context, CancellationToken token)
        {
            if (!TryReadHeader(firstResponse, out Header select)) return null;

            // Without an established session there is nothing to ask.
            if (select.SType != SType.SelectRsp || select.Byte3 != 0) return null;

            List<string> lines = [];

            try
            {
                // The select answer and the introduction may have arrived in the
                // same read, since TCP has no message boundaries. The information
                // is then already there and need not be requested.
                if (firstResponse.Length > 14)
                {
                    AppendFrom(lines, firstResponse.AsSpan(14).ToArray());
                }

                if (lines.Count == 0)
                {
                    await AskAsync(stream, context, token);

                    Message? answer = await ReadDataAsync(stream, token);

                    if (answer is not null)
                    {
                        AppendIdentity(lines, answer.Body, answer.Header.SessionId);
                        await AcknowledgeAsync(stream, answer, token);
                    }
                }
            }
            finally
            {
                await SeparateAsync(stream);
            }

            return lines.Count == 0 ? null : string.Join(Environment.NewLine, lines);
        }

        /// <summary>
        /// Reads an introduction from the part that followed the select answer
        /// in the same buffer.
        /// </summary>
        private static void AppendFrom(List<string> lines, byte[] trailing)
        {
            if (!TryReadHeader(trailing, out Header header)) return;
            if (header.SType != SType.Data || header.Byte3 == 0) return;
            if (trailing.Length < 14) return;

            AppendIdentity(lines, trailing[14..], header.SessionId);
        }

        /// <summary>
        /// The common detection, plus a second attempt for a port that is open
        /// but stayed silent on the detection packet.
        /// </summary>
        public override async Task<PortResult> ProbeAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            PortResult portResult = await base.ProbeAsync(context, address, port, token);

            if (portResult.Status == PortStatus.Open)
            {
                Knock knock = await KnockAgainAsync(context, address, port, token);

                if (knock.Note is not null)
                {
                    portResult.Status = PortStatus.IsRunning;

                    // An endpoint that answered only the second attempt is
                    // detected, but the information below requires a session,
                    // which does not exist here.
                    portResult.PortLog = knock.Note;
                    return portResult;
                }

                if (knock.Silent)
                {
                    // The port accepts every connection and stays silent on
                    // everything. That is not a finding, since anything can
                    // listen on 5000, but it is exactly how busy equipment
                    // behaves: HSMS-SS allows only one session, and equipment
                    // that has already given it to its host leaves a second
                    // select unanswered.
                    //
                    // The port therefore stays open, with an explanation next
                    // to it, so that the cause is not sought in the scanner.
                    const string Silent =
                        "Connection accepted, but HSMS select and linktest stayed unanswered - " +
                        "typical of an HSMS passive endpoint whose single session is already taken.";

                    string? before = portResult.PortLog?.TrimEnd();

                    portResult.PortLog = string.IsNullOrWhiteSpace(before)
                        ? Silent
                        : before + Environment.NewLine + Silent;
                }

                return portResult;
            }

            // HSMS is established, but the equipment did not introduce itself
            // during the base check. A short second attempt is still
            // worthwhile: the base check has only a narrow time window, and an
            // establish request that came a moment too late arrives here.
            //
            // Waiting longer yields nothing; see <see cref="IntroductionWaitMs"/>.
            if (portResult.Status == PortStatus.IsRunning &&
                portResult.PortLog?.Contains(ModelPrefix, StringComparison.Ordinal) != true)
            {
                string? late = await WaitForIntroductionAsync(context, address, port, token);

                if (late is not null)
                {
                    string? before = portResult.PortLog?.TrimEnd();

                    portResult.PortLog = string.IsNullOrWhiteSpace(before)
                        ? late
                        : before + Environment.NewLine + late;
                }
            }

            return portResult;
        }

        /// <summary>The line that marks a successful introduction.</summary>
        private const string ModelPrefix = "Model: ";

        /// <summary>
        /// How long a confirmed HSMS endpoint is listened to after the session
        /// was established.
        /// <para>
        /// Deliberately short, for two reasons. First, equipment that
        /// introduces itself does so at once, measured within 200 to 800
        /// milliseconds after the select is confirmed; if it does not, it does
        /// not do so in twenty seconds either, but waits for an answer a
        /// scanner must not give. Waiting 21 seconds yielded nothing but 21
        /// seconds in three of four runs.
        /// </para>
        /// <para>
        /// Second, and more important: HSMS-SS allows only <b>one</b> session.
        /// While the probe holds it, the real host cannot connect. The whole
        /// session takes about 330 milliseconds as measured, and the equipment
        /// accepts again immediately after the Separate.req; it must stay
        /// that way.
        /// </para>
        /// </summary>
        private const int IntroductionWaitMs = 2500;

        /// <summary>
        /// Opens a session and listens until the equipment introduces itself.
        /// <c>null</c> if it does not do so in time.
        /// <para>
        /// Equipment in the "not communicating" state leaves S1F1 unanswered,
        /// as GEM (SEMI E30) provides; only a wrong device ID yields an S9F1.
        /// The introduction then comes solely from its own S1F13, at the pace of
        /// its own retry cycle.
        /// </para>
        /// </summary>
        private static async Task<string?> WaitForIntroductionAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            try
            {
                using var client = new TcpClient();

                Task connect = client.ConnectAsync(address, port, token).AsTask();
                if (await Task.WhenAny(connect, Task.Delay(context.TimeoutMs, token)) != connect) return null;
                await connect;

                NetworkStream stream = client.GetStream();

                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
                timeout.CancelAfter(IntroductionWaitMs);
                CancellationToken listen = timeout.Token;

                await stream.WriteAsync(Frame(0xFFFF, 0x00, 0x00, SType.SelectReq, 1), listen);

                Message? select = await ReadMessageAsync(stream, listen);
                if (select is null || select.Header.SType != SType.SelectRsp || select.Header.Byte3 != 0) return null;

                List<string> lines = [];

                try
                {
                    // Ask here as well instead of only listening: the first attempt
                    // failed because of its narrow time limit, not because the
                    // equipment had nothing to say.
                    await AskAsync(stream, context, listen);

                    Message? introduction = await ReadDataAsync(stream, listen);

                    if (introduction is not null)
                    {
                        AppendIdentity(lines, introduction.Body, introduction.Header.SessionId);
                        await AcknowledgeAsync(stream, introduction, listen);
                    }
                }
                finally
                {
                    await SeparateAsync(stream);
                }

                return lines.Count == 0 ? null : string.Join(Environment.NewLine, lines);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                // Timeout or aborted connection: the finding stays, the
                // introduction is missing.
                return null;
            }
        }

        /// <summary>
        /// The result of the second attempt. <paramref name="Note"/> carries the
        /// line of a successful answer, <paramref name="Silent"/> tells whether
        /// the remote side accepted the connection and then stayed silent until
        /// the timeout.
        /// <para>
        /// The difference matters more than it seems: busy equipment stays
        /// <em>silent</em>, while any other service that cannot handle the
        /// bytes sent <em>closes</em> the connection. Without the distinction,
        /// an RDP port would get the explanation that only applies to an HSMS
        /// endpoint.
        /// </para>
        /// </summary>
        private readonly record struct Knock(string? Note, bool Silent);

        /// <summary>
        /// The second attempt for a port that is open but stayed silent on the
        /// detection packet. <see cref="Knock.Note"/> is <c>null</c> if nothing
        /// comes here either; the port then stays a mere open port.
        /// <para>
        /// Two reasons why an HSMS endpoint silently discards a Select.req.
        /// First the session ID: the detection packet carries 0xFFFF, as usual
        /// for control messages, but some HSMS-SS implementations expect the
        /// configured device ID there and ignore any other. Second the state of
        /// the remote side: an endpoint that is already connected sometimes
        /// does not answer a second select at all.
        /// </para>
        /// <para>
        /// Therefore select is tried with the usual device IDs first, and
        /// finally a linktest, the message with which HSMS checks whether the
        /// link is still up. Without an open session the remote side must
        /// reject it, and that rejection is the information: only an HSMS
        /// endpoint answers that way.
        /// </para>
        /// </summary>
        private static async Task<Knock> KnockAgainAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            // Shorter than the first attempt: the only question here is whether
            // there is an answer at all.
            int timeoutMs = Math.Min(context.TimeoutMs, 1500);

            (ushort Session, byte SType, string Note)[] knocks =
            [
                (0, SType.SelectReq, "HSMS answered on session 0."),
                (1, SType.SelectReq, "HSMS answered on session 1."),
                (0xFFFF, SType.LinktestReq, "HSMS linktest answered without a session.")
            ];

            bool silent = false;

            foreach ((ushort session, byte sType, string note) in knocks)
            {
                token.ThrowIfCancellationRequested();

                try
                {
                    using var client = new TcpClient();

                    Task connect = client.ConnectAsync(address, port, token).AsTask();
                    if (await Task.WhenAny(connect, Task.Delay(timeoutMs, token)) != connect) continue;
                    await connect;

                    NetworkStream stream = client.GetStream();

                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
                    timeout.CancelAfter(timeoutMs);

                    await stream.WriteAsync(Frame(session, 0x00, 0x00, sType, 1), timeout.Token);

                    Message? answer = await ReadMessageAsync(stream, timeout.Token);

                    if (answer is not null && answer.Header.PType == 0) return new Knock(note, false);

                    // Returning without an answer means the remote side closed
                    // the connection itself or sent something that is not HSMS.
                    // Neither is silence.
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    throw;
                }
                catch (OperationCanceledException)
                {
                    // The own timeout: the connection was established, and
                    // nothing came until the end. That is what busy equipment does.
                    silent = true;
                }
                catch (Exception)
                {
                    // Closed connection, socket error: this attempt yielded
                    // nothing, the next one may.
                }
            }

            return new Knock(null, silent);
        }

        /// <summary>
        /// The content of S1F2: a list of model name (MDLN) and software
        /// revision (SOFTREV), both text.
        /// <para>
        /// The same two texts are in S1F13, with which equipment requests to
        /// establish communication on its own. Measured on running equipment,
        /// that is even the more common way: it waits for its host, and as
        /// soon as the session exists, it introduces itself unprompted, before
        /// the probe's request has been answered. Therefore the texts present
        /// are read, regardless of which message carried them.
        /// </para>
        /// <para>
        /// Both may be empty; equipment that only confirms its presence sends
        /// two empty texts. Then at least the device ID it answers under is
        /// known, which is the information actually needed for connecting it.
        /// </para>
        /// </summary>
        private static void AppendIdentity(List<string> lines, byte[] body, ushort deviceId)
        {
            List<string> texts = [.. ReadTexts(body)];

            string model = texts.Count > 0 ? texts[0] : string.Empty;
            string revision = texts.Count > 1 ? texts[1] : string.Empty;

            // Without a model name it is no introduction. The device ID alone
            // would say nothing about the equipment, only that some message
            // arrived; the details view would show "Device ID: 0" and nothing
            // else.
            if (model.Length == 0) return;

            lines.Add($"Device ID: {deviceId}");
            lines.Add($"{ModelPrefix}{model}");

            if (revision.Length > 0) lines.Add($"Software revision: {revision}");
        }

        /// <summary>
        /// The texts of a SECS-II message (SEMI E5), in the order in which they
        /// appear.
        /// <para>
        /// Layout of an item: one byte whose upper six bits give the format and
        /// whose lower two tell how many bytes the length occupies, then the
        /// length, then the content. Format 0 is a list, whose length is the
        /// number of its items and which has no content of its own; format 16
        /// is ASCII text. Everything else is skipped, since only names are
        /// sought here.
        /// </para>
        /// </summary>
        private static IEnumerable<string> ReadTexts(byte[] body)
        {
            const int Ascii = 16;
            const int List = 0;

            int at = 0;

            // Guard against a message that describes itself in circles: there
            // cannot be more items than bytes.
            for (int guard = 0; guard <= body.Length && at < body.Length; guard++)
            {
                int format = body[at] >> 2;
                int lengthBytes = body[at] & 0x03;

                if (lengthBytes == 0) yield break;
                if (at + 1 + lengthBytes > body.Length) yield break;

                int length = 0;
                for (int i = 0; i < lengthBytes; i++) length = length << 8 | body[at + 1 + i];

                at += 1 + lengthBytes;

                // A list has no content of its own; its items follow
                // immediately and are read in the next iteration.
                if (format == List) continue;

                if (at + length > body.Length) yield break;

                if (format == Ascii)
                {
                    yield return Printable(Encoding.ASCII.GetString(body, at, length), 64);
                }

                at += length;
            }
        }

        /// <summary>
        /// Sends the identity request in all its variants, one after the other,
        /// before waiting for an answer.
        /// <para>
        /// All requests go out before reading: the device ID is carried in the
        /// session ID and known only to whoever configured the equipment, and a
        /// wrong one yields at most an S9F1, which is skipped anyway. Asking and
        /// reading one at a time, the first ID would use up the whole time
        /// budget.
        /// </para>
        /// <para>
        /// By default only S1F1 "Are You There" is sent, <b>no S1F13</b>. That
        /// is not a detail but measured on real equipment: it reliably answers
        /// an S1F13 with the requested S1F14, but enters the communicating state
        /// and treats the sender as its host. Within half a second an alarm
        /// "Communication ok" and a continuous stream of S6F1 with real
        /// production data (lot numbers, measurements) arrived. Where spooling
        /// is configured, the equipment could record them as delivered, and
        /// they would be missing at the real host. A scanner asks; it does not
        /// accept data that belongs to someone else. S1F13 is sent only when
        /// <see cref="ProbeContext.ActiveInquiry"/> is set.
        /// </para>
        /// <para>
        /// The price is that equipment which leaves S1F1 unanswered in the "not
        /// communicating" state (GEM allows this) introduces itself only on its
        /// own. It does so reliably on the first contact after an idle period.
        /// </para>
        /// </summary>
        private static async Task AskAsync(
            NetworkStream stream, ProbeContext context, CancellationToken token)
        {
            foreach (ushort deviceId in (ushort[])[0, 1])
            {
                await stream.WriteAsync(Frame(deviceId, 0x81, 0x01, SType.Data, 10u + deviceId), token);
            }

            if (!context.ActiveInquiry) return;

            // Only when explicitly enabled: the request that forces an answer
            // and changes the state of the equipment. See
            // <see cref="ProbeContext.ActiveInquiry"/>.
            foreach (ushort deviceId in (ushort[])[0, 1])
            {
                await stream.WriteAsync(
                    Frame(deviceId, 0x81, 0x0D, SType.Data, 20u + deviceId, EstablishRequest), token);
            }
        }

        /// <summary>
        /// The body of an S1F13: <c>L,2 { MDLN, SOFTREV }</c>, both empty.
        /// <para>
        /// Empty is permitted and correct here: the two fields describe who is
        /// <em>asking</em>, and a scanner is not a host with model and software
        /// revision. The answer does not depend on them.
        /// </para>
        /// </summary>
        private static readonly byte[] EstablishRequest = [0x01, 0x02, 0x41, 0x00, 0x41, 0x00];

        /// <summary>
        /// Acknowledges the establish request of the equipment (S1F14 to its
        /// S1F13), with a refusal.
        /// <para>
        /// Without this answer the equipment waits for its T3 timer before the
        /// next attempt; as measured, it then stayed silent for almost a minute,
        /// and a second scan in that time only got "select accepted" without a
        /// model. Once acknowledged, its cycle is ready again at once.
        /// </para>
        /// <para>
        /// COMMACK is deliberately <b>1</b>, "denied". A 0 would mean "accepted"
        /// and put the equipment into the communicating state: it would then
        /// have a host that is none. With 1, only its wait for an answer ends;
        /// its state stays as it was, and spooled events stay where they are,
        /// to be collected only by a real host.
        /// </para>
        /// <para>
        /// The system bytes of the request must be echoed, otherwise the
        /// equipment cannot match the answer to its request and keeps waiting.
        /// </para>
        /// </summary>
        private static async Task AcknowledgeAsync(
            NetworkStream stream, Message request, CancellationToken token)
        {
            // Without the W-bit the remote side expects no answer; an
            // unsolicited reply would itself be a protocol error.
            if ((request.Header.Byte2 & 0x80) == 0) return;
            if (request.Header.Byte3 != 13) return;

            // L,2 { COMMACK = 1, L,2 { MDLN = "", SOFTREV = "" } }
            byte[] body =
            [
                0x01, 0x02,
                0x21, 0x01, 0x01,
                0x01, 0x02,
                0x41, 0x00,
                0x41, 0x00
            ];

            await stream.WriteAsync(
                Frame(request.Header.SessionId, 0x01, 0x0E, SType.Data, request.Header.SystemBytes, body),
                token);
        }

        /// <summary>
        /// Ends the own session with Separate.req, the HSMS disconnect message.
        /// The remote side then knows at once that the link is free and waits
        /// for no timer.
        /// <para>
        /// Every caller has it in a <c>finally</c>, and that is the point: the
        /// most common outcome is equipment that says nothing and lets the read
        /// run into its timeout. Placed after the read, the separate would be
        /// skipped exactly when it is needed most.
        /// </para>
        /// <para>
        /// It uses its own short time limit instead of the passed token, which
        /// has usually expired at this point and would reject the write before
        /// a single byte leaves. Even a cancelled run should end the session
        /// properly; it costs microseconds.
        /// </para>
        /// <para>
        /// The session cannot <em>hang</em> anyway: it exists only within the
        /// TCP connection, which is closed in every case. Separate.req only
        /// makes the end explicit instead of leaving the remote side to infer
        /// it from the connection teardown.
        /// </para>
        /// </summary>
        private static async Task SeparateAsync(NetworkStream stream)
        {
            try
            {
                using CancellationTokenSource quick = new(SeparateTimeoutMs);

                await stream.WriteAsync(Frame(0xFFFF, 0x00, 0x00, SType.SeparateReq, 99), quick.Token);
            }
            catch (Exception)
            {
                // Courtesy, not a result. If the connection is gone, so is the
                // session, and there was nothing left to separate.
            }
        }

        /// <summary>Time limit for the separate message: it goes out promptly or not at all.</summary>
        private const int SeparateTimeoutMs = 500;

        /// <summary>The HSMS message types as numbered by SEMI E37.</summary>
        private static class SType
        {
            public const byte Data = 0;
            public const byte SelectReq = 1;
            public const byte SelectRsp = 2;
            public const byte DeselectRsp = 4;
            public const byte LinktestReq = 5;
            public const byte LinktestRsp = 6;
            public const byte RejectReq = 7;
            public const byte SeparateReq = 9;
        }

        /// <summary>The header of an HSMS message: ten bytes after the length.</summary>
        private readonly record struct Header(
            ushort SessionId, byte Byte2, byte Byte3, byte PType, byte SType, uint SystemBytes);

        private sealed record Message(Header Header, byte[] Body);

        /// <summary>
        /// Reads the header from a buffer as the base check has it: four bytes
        /// length, then the header.
        /// </summary>
        private static bool TryReadHeader(byte[] response, out Header header)
        {
            header = default;

            if (response is null || response.Length < 14) return false;

            uint length = (uint)(response[0] << 24 | response[1] << 16 | response[2] << 8 | response[3]);

            // Nothing is shorter than the header, and a message of more than one
            // megabyte is no longer HSMS but a chance match in another protocol.
            if (length < 10 || length > 0x100000) return false;

            header = new Header(
                (ushort)(response[4] << 8 | response[5]),
                response[6],
                response[7],
                response[8],
                response[9],
                (uint)(response[10] << 24 | response[11] << 16 | response[12] << 8 | response[13]));

            return true;
        }

        /// <summary>A complete message: four bytes length, ten bytes header, then the content.</summary>
        private static byte[] Frame(
            ushort sessionId, byte byte2, byte byte3, byte sType, uint systemBytes, byte[]? body = null)
        {
            body ??= [];

            uint length = (uint)(10 + body.Length);
            byte[] frame = new byte[4 + length];

            frame[0] = (byte)(length >> 24);
            frame[1] = (byte)(length >> 16);
            frame[2] = (byte)(length >> 8);
            frame[3] = (byte)length;

            frame[4] = (byte)(sessionId >> 8);
            frame[5] = (byte)sessionId;
            frame[6] = byte2;
            frame[7] = byte3;
            frame[8] = 0x00;        // PType 0: the content is SECS-II
            frame[9] = sType;

            frame[10] = (byte)(systemBytes >> 24);
            frame[11] = (byte)(systemBytes >> 16);
            frame[12] = (byte)(systemBytes >> 8);
            frame[13] = (byte)systemBytes;

            body.CopyTo(frame, 14);

            return frame;
        }

        /// <summary>
        /// Waits for a data message and answers any control messages the
        /// remote side sends in between.
        /// <para>
        /// A linktest is the heartbeat of HSMS: if it stays unanswered, the
        /// equipment drops the session, in the middle of the request whose
        /// answer is awaited here.
        /// </para>
        /// </summary>
        private static async Task<Message?> ReadDataAsync(NetworkStream stream, CancellationToken token)
        {
            // Read until the introduction arrives or time runs out, not for a
            // fixed number of messages. In between comes whatever else the
            // equipment sends: linktests, and an S9F1 for every device ID that
            // is not its own. Taking the first message would mistake such an
            // S9F1 for the answer and put a device ID without a model into the
            // details.
            while (!token.IsCancellationRequested)
            {
                Message? message = await ReadMessageAsync(stream, token);
                if (message is null) return null;

                if (message.Header.SType == SType.LinktestReq)
                {
                    await stream.WriteAsync(
                        Frame(0xFFFF, 0x00, 0x00, SType.LinktestRsp, message.Header.SystemBytes),
                        token);

                    continue;
                }

                if (message.Header.SType != SType.Data) continue;

                // Stream 1, function 2, 13 or 14: the answer to "Are You
                // There", the establish request of the equipment and the answer
                // to the probe's own. All three carry model name and software
                // revision, and only they are an introduction.
                int stream1 = message.Header.Byte2 & 0x7F;

                if (stream1 == 1 && message.Header.Byte3 is 2 or 13 or 14) return message;
            }

            return null;
        }

        /// <summary>A length-prefixed message: four bytes length, then that many bytes.</summary>
        private static async Task<Message?> ReadMessageAsync(NetworkStream stream, CancellationToken token)
        {
            byte[]? head = await ReadExactAsync(stream, 4, token);
            if (head is null) return null;

            uint length = (uint)(head[0] << 24 | head[1] << 16 | head[2] << 8 | head[3]);
            if (length < 10 || length > 0x100000) return null;

            byte[]? rest = await ReadExactAsync(stream, (int)length, token);
            if (rest is null) return null;

            byte[] all = new byte[4 + length];
            head.CopyTo(all, 0);
            rest.CopyTo(all, 4);

            if (!TryReadHeader(all, out Header header)) return null;

            return new Message(header, rest[10..]);
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
