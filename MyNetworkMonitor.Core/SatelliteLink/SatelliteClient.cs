using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.SatelliteLink
{
    /// <summary>What the satellite connection is doing, for the display.</summary>
    public enum SatelliteLinkState
    {
        /// <summary>Not connected and not trying to.</summary>
        Idle,

        /// <summary>A connection attempt is in progress.</summary>
        Connecting,

        /// <summary>Connected, but the main scanner has not approved this satellite yet.</summary>
        WaitingForApproval,

        /// <summary>Connected and approved.</summary>
        Connected,

        /// <summary>The last attempt failed; a retry follows.</summary>
        Failed
    }

    /// <summary>
    /// The satellite side: connects out to a main scanner and keeps the
    /// connection open.
    /// <para>
    /// Outgoing, because then no firewall opening into the remote segment is
    /// needed and the satellite itself listens on nothing, see SATELLIT.md,
    /// section 1. The main scanner may change its address as long as its name
    /// stays the same; it is recognized by its fingerprint anyway.
    /// </para>
    /// </summary>
    public sealed class SatelliteClient : IAsyncDisposable
    {
        private readonly X509Certificate2 _certificate;
        private readonly string _ownName;
        private readonly string _ownVersion;

        private CancellationTokenSource? _cts;
        private Task? _loop;

        /// <summary>Creates the client; it connects only after <see cref="Start"/>.</summary>
        /// <param name="certificate">Own certificate with private key, presented to the main scanner.</param>
        /// <param name="ownName">Name reported to the main scanner; empty means the machine name.</param>
        /// <param name="ownVersion">Own application version.</param>
        /// <exception cref="ArgumentNullException"><paramref name="certificate"/> is null.</exception>
        public SatelliteClient(X509Certificate2 certificate, string ownName, string ownVersion)
        {
            _certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
            _ownName = string.IsNullOrWhiteSpace(ownName) ? Environment.MachineName : ownName;
            _ownVersion = ownVersion ?? string.Empty;
        }

        /// <summary>State change with plain text for the display.</summary>
        public event EventHandler<(SatelliteLinkState State, string Text)>? StateChanged;

        /// <summary>
        /// The fingerprint of the main scanner, as remembered on the first
        /// successful connection. Empty means none yet; the next one is then
        /// adopted (trust on first use).
        /// </summary>
        public string PinnedFingerprint { get; set; } = string.Empty;

        /// <summary>Raised when a fingerprint has been newly adopted.</summary>
        public event EventHandler<string>? FingerprintPinned;

        /// <summary>
        /// Runs a job and returns the devices found as JSON.
        /// <para>
        /// A callback rather than a dependency: the transport must not know the
        /// scan engine. It stays testable on its own, and the code using it
        /// decides what a job does.
        /// </para>
        /// </summary>
        public Func<string, IProgress<ProgressPayload>, CancellationToken, Task<string>>? JobRunner { get; set; }

        /// <summary>
        /// The shared job management. Shared across all main scanners: only
        /// then can "one at a time" be enforced and the question of who may
        /// cancel be answered.
        /// </summary>
        public SatelliteJobHost Jobs { get; set; } = new();

        /// <summary>
        /// Key of the main scanner this connection talks to. Serves as the
        /// identity of the job's owner.
        /// </summary>
        private string _receiverKey = string.Empty;

        /// <summary>
        /// Whether the handshake succeeded on the last attempt. Decides whether
        /// a retry after a disconnect happens right away or after a grown delay.
        /// </summary>
        private bool _wasConnected;

        /// <summary>Identifier of the running job, or <c>null</c>.</summary>
        public string? CurrentJobId => Jobs.CurrentJobId;

        /// <summary>The current connection state.</summary>
        public SatelliteLinkState State { get; private set; } = SatelliteLinkState.Idle;

        /// <summary>
        /// Connects in the background and keeps the connection, with a growing
        /// delay after failures. Returns immediately; the loop runs until
        /// <see cref="Stop"/>.
        /// </summary>
        /// <param name="host">Host name or address of the main scanner.</param>
        /// <param name="port">TCP port of the main scanner.</param>
        public void Start(string host, int port)
        {
            Stop();

            _receiverKey = $"{host}:{port}";
            _cts = new CancellationTokenSource();
            _loop = Task.Run(() => ConnectLoopAsync(host, port, _cts.Token));
        }

        /// <summary>Stops the connection loop and reports <see cref="SatelliteLinkState.Idle"/>.</summary>
        public void Stop()
        {
            try { _cts?.Cancel(); } catch { }
            Report(SatelliteLinkState.Idle, "Not connected.");
        }

        private async Task ConnectLoopAsync(string host, int port, CancellationToken token)
        {
            // Growing delay: a main scanner that is switched off should not be
            // contacted every second. Capped at one minute so that reconnecting
            // does not take forever.
            TimeSpan wait = TimeSpan.FromSeconds(2);
            TimeSpan maxWait = TimeSpan.FromMinutes(1);

            while (!token.IsCancellationRequested)
            {
                _wasConnected = false;

                try
                {
                    await ConnectOnceAsync(host, port, token);

                    // Disconnected cleanly: retry right away, that was not an
                    // error.
                    wait = TimeSpan.FromSeconds(2);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (Exception ex)
                {
                    Report(SatelliteLinkState.Failed, ex.Message);

                    // If the connection had been up, the delay starts over.
                    // Otherwise a satellite that was connected for hours would
                    // wait up to a minute after a restart of the main scanner,
                    // although the path is known to be clear and only the peer
                    // was briefly gone.
                    if (_wasConnected) wait = TimeSpan.FromSeconds(2);
                }

                try
                {
                    await Task.Delay(wait, token);
                }
                catch (OperationCanceledException)
                {
                    return;
                }

                wait = wait < maxWait ? wait + wait : maxWait;
                if (wait > maxWait) wait = maxWait;
            }
        }

        private async Task ConnectOnceAsync(string host, int port, CancellationToken token)
        {
            Report(SatelliteLinkState.Connecting, $"Connecting to {host}:{port} …");

            using TcpClient client = new();
            await client.ConnectAsync(host, port, token);

            using SslStream tls = new(client.GetStream(), leaveInnerStreamOpen: false);

            string seenFingerprint = string.Empty;

            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                ClientCertificates = [_certificate],
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,

                RemoteCertificateValidationCallback = (_, certificate, _, _) =>
                {
                    if (certificate is null) return false;

                    using X509Certificate2 presented = new(certificate);
                    seenFingerprint = SatelliteIdentity.Fingerprint(presented);

                    // Trust on first use: if none is remembered yet, this one is
                    // adopted. After that it must match; a different key is a
                    // different peer, whatever its name.
                    if (string.IsNullOrEmpty(PinnedFingerprint)) return true;

                    return string.Equals(PinnedFingerprint, seenFingerprint, StringComparison.OrdinalIgnoreCase);
                }
            }, token);

            if (string.IsNullOrEmpty(PinnedFingerprint) && !string.IsNullOrEmpty(seenFingerprint))
            {
                PinnedFingerprint = seenFingerprint;
                FingerprintPinned?.Invoke(this, seenFingerprint);
            }

            MessageChannel channel = new(tls);

            // The site is collected here and not once at start: this path runs
            // on every connection, including reconnects after a disconnect. The
            // addresses on the main scanner are thus correct again after a
            // restart or a new DHCP lease.
            SiteInfo site = SiteInfo.Read();

            await channel.SendAsync(new SatelliteMessage
            {
                Type = MessageType.Hello,
                ProtocolVersion = SatelliteListener.ProtocolVersion,
                Name = _ownName,
                AppVersion = _ownVersion,
                Os = RuntimeInformation.OSDescription,
                Site = new SitePayload
                {
                    HostName = site.HostName,
                    Domain = site.Domain,
                    Ipv4 = string.Join(", ", site.Ipv4.Select(a => a.Address)),
                    Ipv6 = string.Join(", ", site.Ipv6.Select(a => a.Address)),
                    PrimaryNetwork = site.PrimaryNetwork,
                    Networks = string.Join(", ", site.Networks)
                }
            }, token);

            SatelliteMessage? answer = await channel.ReceiveAsync(token)
                ?? throw new AuthenticationException("The main scanner closed the connection without answering.");

            // From here on the connection is really up: the handshake is done.
            _wasConnected = true;

            switch (answer.Type)
            {
                case MessageType.Welcome:
                    Report(SatelliteLinkState.Connected, "Connected and approved.");
                    break;

                case MessageType.Pending:
                    Report(SatelliteLinkState.WaitingForApproval,
                           answer.Text ?? "Waiting for approval on the main scanner.");
                    break;

                case MessageType.Error:
                    throw new AuthenticationException(answer.Text ?? "The main scanner refused the connection.");

                default:
                    throw new InvalidDataException($"Unexpected answer \"{answer.Type}\" to the hello.");
            }

            await PumpAsync(channel, token);
        }

        /// <summary>
        /// Keeps the connection and answers what comes in. Ends when the peer
        /// closes the connection.
        /// </summary>
        private async Task PumpAsync(MessageChannel channel, CancellationToken token)
        {
            // Liveness check. Without it the satellite does not notice when the
            // main scanner disappears: if the remote machine dies abruptly
            // (restart, power failure, cut cable), neither a FIN nor an RST
            // arrives. The connection is half-open, the read below waits
            // forever, and the satellite considers itself connected until
            // "Connect" is pressed by hand.
            //
            // Answering pings is not enough: a side that only answers and
            // never asks detects nothing. The satellite therefore sends pings
            // itself and watches for silence.
            using CancellationTokenSource dead = CancellationTokenSource.CreateLinkedTokenSource(token);

            long lastHeard = DateTimeOffset.UtcNow.Ticks;
            Task heartbeat = HeartbeatAsync(channel, () => Interlocked.Read(ref lastHeard), dead);

            try
            {
                await ReceiveLoopAsync(channel, dead, () =>
                    Interlocked.Exchange(ref lastHeard, DateTimeOffset.UtcNow.Ticks));
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested)
            {
                // Not a cancellation by the caller: the liveness check gave up.
                // Reported as an error so that the connection loop retries
                // instead of ending.
                throw new TimeoutException(
                    "The main scanner stopped answering - reconnecting.");
            }
            finally
            {
                dead.Cancel();
                try { await heartbeat; } catch (Exception) { }
            }
        }

        /// <summary>How often a keep-alive is sent.</summary>
        private static readonly TimeSpan HeartbeatEvery = TimeSpan.FromSeconds(20);

        /// <summary>
        /// Silence after which the connection counts as dead. More generous
        /// than the keep-alive interval so that a long scan on the other side
        /// or a brief network disruption does not cause an immediate disconnect.
        /// </summary>
        private static readonly TimeSpan SilenceLimit = TimeSpan.FromSeconds(70);

        /// <summary>
        /// Sends a keep-alive at regular intervals and cancels when nothing has
        /// come back for too long.
        /// </summary>
        private static async Task HeartbeatAsync(
            MessageChannel channel, Func<long> lastHeard, CancellationTokenSource dead)
        {
            try
            {
                while (!dead.IsCancellationRequested)
                {
                    await Task.Delay(HeartbeatEvery, dead.Token);

                    if (DateTimeOffset.UtcNow - new DateTimeOffset(lastHeard(), TimeSpan.Zero) > SilenceLimit)
                    {
                        dead.Cancel();
                        return;
                    }

                    // The channel serializes writes itself, so a ping in the
                    // middle of a result cannot tear anything apart.
                    await channel.SendAsync(new SatelliteMessage
                    {
                        Type = MessageType.Ping,
                        ProtocolVersion = SatelliteListener.ProtocolVersion
                    }, dead.Token);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception)
            {
                // A failed write means the connection is gone.
                try { dead.Cancel(); } catch (Exception) { }
            }
        }

        private async Task ReceiveLoopAsync(
            MessageChannel channel, CancellationTokenSource dead, Action heard)
        {
            CancellationToken token = dead.Token;

            while (!token.IsCancellationRequested)
            {
                SatelliteMessage? message = await channel.ReceiveAsync(token);
                if (message is null) return; // peer closed the connection

                // Every message counts as a sign of life, not only a pong.
                heard();

                switch (message.Type)
                {
                    case MessageType.Ping:
                        await channel.SendAsync(new SatelliteMessage
                        {
                            Type = MessageType.Pong,
                            ProtocolVersion = SatelliteListener.ProtocolVersion
                        }, token);
                        break;

                    case MessageType.Welcome:
                        // Approval can arrive later, while the connection is
                        // already up.
                        Report(SatelliteLinkState.Connected, "Approved.");
                        break;

                    case MessageType.Error:
                        Report(SatelliteLinkState.Failed, message.Text ?? "Refused by the main scanner.");
                        return;

                    case MessageType.Job:
                        await StartJobAsync(channel, message, token);
                        break;

                    case MessageType.Cancel:
                        // The job management decides who may cancel: the owner
                        // always, anyone else only if allowed. A refused cancel
                        // is answered rather than swallowed; otherwise pressing
                        // Stop would do nothing visible.
                        if (!Jobs.TryCancel(message.JobId, _receiverKey, out string refused))
                        {
                            await channel.SendAsync(new SatelliteMessage
                            {
                                Type = MessageType.Error,
                                ProtocolVersion = SatelliteListener.ProtocolVersion,
                                JobId = message.JobId,
                                Text = refused
                            }, token);
                        }
                        break;

                    default:
                        break;
                }
            }
        }

        /// <summary>
        /// Accepts a job and runs it in the background.
        /// <para>
        /// In the background so that the connection stays responsive: otherwise
        /// neither a cancel nor a keep-alive would get through during a long
        /// scan.
        /// </para>
        /// </summary>
        private async Task StartJobAsync(MessageChannel channel, SatelliteMessage message, CancellationToken token)
        {
            string jobId = message.JobId ?? MessageChannel.NewJobId();

            if (JobRunner is null)
            {
                await channel.SendAsync(new SatelliteMessage
                {
                    Type = MessageType.Error,
                    ProtocolVersion = SatelliteListener.ProtocolVersion,
                    JobId = jobId,
                    Text = "This instance cannot run jobs - no scan engine is attached."
                }, token);
                return;
            }

            CancellationTokenSource? jobCts = Jobs.TryStart(jobId, _receiverKey, token);

            if (jobCts is null)
            {
                await channel.SendAsync(new SatelliteMessage
                {
                    Type = MessageType.Busy,
                    ProtocolVersion = SatelliteListener.ProtocolVersion,
                    JobId = Jobs.CurrentJobId,
                    Text = $"A job is already running ({Jobs.CurrentJobId})."
                }, token);
                return;
            }

            await channel.SendAsync(new SatelliteMessage
            {
                Type = MessageType.Accepted,
                ProtocolVersion = SatelliteListener.ProtocolVersion,
                JobId = jobId
            }, token);

            _ = Task.Run(async () =>
            {
                try
                {
                    Progress<ProgressPayload> progress = new(p =>
                    {
                        // Progress is transient: if it is lost, only the display
                        // misses an update. Hence fire-and-forget.
                        _ = channel.SendAsync(new SatelliteMessage
                        {
                            Type = MessageType.Progress,
                            ProtocolVersion = SatelliteListener.ProtocolVersion,
                            JobId = jobId,
                            Progress = p
                        }, CancellationToken.None);
                    });

                    string devices = await JobRunner(message.Text ?? string.Empty, progress, jobCts.Token);

                    // A cancelled job also delivers what it has found so far,
                    // marked as partial. The token tells whether it was
                    // cancelled: the job runs on exactly this source.
                    await channel.SendAsync(new SatelliteMessage
                    {
                        Type = MessageType.Result,
                        ProtocolVersion = SatelliteListener.ProtocolVersion,
                        JobId = jobId,
                        Devices = devices,
                        Partial = jobCts.IsCancellationRequested
                    }, CancellationToken.None);
                }
                catch (OperationCanceledException)
                {
                    // Reached only when cancelled before anything was collected;
                    // then there is nothing to send.
                    await TrySend(channel, new SatelliteMessage
                    {
                        Type = MessageType.Cancelled,
                        ProtocolVersion = SatelliteListener.ProtocolVersion,
                        JobId = jobId
                    });
                }
                catch (Exception ex)
                {
                    await TrySend(channel, new SatelliteMessage
                    {
                        Type = MessageType.Error,
                        ProtocolVersion = SatelliteListener.ProtocolVersion,
                        JobId = jobId,
                        Text = ex.Message
                    });
                }
                finally
                {
                    Jobs.Finish(jobId);
                }
            }, CancellationToken.None);
        }

        /// <summary>
        /// Sends without a failure disturbing the caller; for final messages
        /// where the connection may already be gone.
        /// </summary>
        private static async Task TrySend(MessageChannel channel, SatelliteMessage message)
        {
            try { await channel.SendAsync(message, CancellationToken.None); } catch { }
        }

        private void Report(SatelliteLinkState state, string text)
        {
            State = state;
            StateChanged?.Invoke(this, (state, text));
        }

        /// <summary>Stops the client and waits for the connection loop to end.</summary>
        public async ValueTask DisposeAsync()
        {
            Stop();

            if (_loop is not null)
            {
                try { await _loop; } catch { }
            }

            _cts?.Dispose();
        }
    }
}
