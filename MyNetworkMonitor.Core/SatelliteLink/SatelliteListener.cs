// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace MyNetworkMonitor.Core.SatelliteLink
{
    /// <summary>A satellite has announced itself.</summary>
    public sealed class SatelliteAnnouncedEventArgs : EventArgs
    {
        /// <summary>The name the satellite reports for itself.</summary>
        public required string Name { get; init; }

        /// <summary>Fingerprint of the certificate it presented.</summary>
        public required string Fingerprint { get; init; }

        /// <summary>Application version of the satellite.</summary>
        public required string AppVersion { get; init; }

        /// <summary>Operating system of the satellite.</summary>
        public required string Os { get; init; }

        /// <summary>Remote endpoint of the connection.</summary>
        public required string RemoteAddress { get; init; }

        /// <summary>
        /// Where the satellite is located, or <c>null</c> if it reported
        /// nothing. Sent fresh with every login, not only the first time.
        /// </summary>
        public SitePayload? Site { get; init; }
    }

    /// <summary>
    /// The main scanner side: accepts connections from satellites.
    /// <para>
    /// The satellite connects here, not the other way round, see SATELLIT.md,
    /// section 1. That is why this class listens, and why it knows no
    /// satellite addresses: it learns them only when one connects.
    /// </para>
    /// </summary>
    public sealed class SatelliteListener : IAsyncDisposable
    {
        /// <summary>Version of the satellite protocol; both sides must match.</summary>
        public const int ProtocolVersion = 1;

        /// <summary>TCP port the main scanner listens on by default.</summary>
        public const int DefaultPort = 27411;

        private readonly X509Certificate2 _certificate;
        private readonly Func<string, bool> _isApproved;
        private readonly string _ownVersion;

        private TcpListener? _listener;
        private CancellationTokenSource? _cts;
        private Task? _acceptLoop;

        /// <summary>The currently open connections, by fingerprint.</summary>
        private readonly ConcurrentDictionary<string, SatelliteSession> _sessions = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Creates the listener; it accepts nothing before <see cref="Start"/>.</summary>
        /// <param name="certificate">Own certificate with private key, presented to satellites.</param>
        /// <param name="isApproved">Tells whether a fingerprint has been approved.</param>
        /// <param name="ownVersion">Own application version, sent to satellites.</param>
        /// <exception cref="ArgumentNullException"><paramref name="certificate"/> or <paramref name="isApproved"/> is null.</exception>
        public SatelliteListener(X509Certificate2 certificate, Func<string, bool> isApproved, string ownVersion)
        {
            _certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
            _isApproved = isApproved ?? throw new ArgumentNullException(nameof(isApproved));
            _ownVersion = ownVersion ?? string.Empty;
        }

        /// <summary>A satellite has introduced itself: name, identity, origin.</summary>
        public event EventHandler<SatelliteAnnouncedEventArgs>? Announced;

        /// <summary>The connection to a satellite is gone; the argument is its fingerprint.</summary>
        public event EventHandler<string>? Disconnected;

        /// <summary>Something went wrong; plain text for the status line.</summary>
        public event EventHandler<string>? Failed;

        /// <summary>A satellite reports progress: fingerprint and state.</summary>
        public event EventHandler<(string Fingerprint, ProgressPayload Progress)>? ProgressReported;

        /// <summary>
        /// A job has finished: fingerprint, job identifier, the devices found as
        /// JSON, and whether the result is partial.
        /// </summary>
        public event EventHandler<(string Fingerprint, string JobId, string Devices, bool Partial)>? ResultReceived;

        /// <summary>A job ended without a result: cancelled, refused or failed.</summary>
        public event EventHandler<(string Fingerprint, string Text)>? JobEnded;

        /// <summary>True while the listener accepts connections.</summary>
        public bool IsListening => _listener is not null;

        /// <summary>The port passed to the last <see cref="Start"/>.</summary>
        public int Port { get; private set; }

        /// <summary>Fingerprints of the currently connected satellites.</summary>
        public IReadOnlyCollection<string> ConnectedFingerprints => [.. _sessions.Keys];

        /// <summary>
        /// Starts listening on <paramref name="port"/> for IPv4 and IPv6. Stops a
        /// previous listener first. Failures are reported through <see cref="Failed"/>.
        /// </summary>
        /// <param name="port">TCP port to listen on.</param>
        public void Start(int port)
        {
            Stop();

            Port = port;
            _cts = new CancellationTokenSource();

            try
            {
                // IPv6Any with DualMode: accepts satellites over IPv4 and IPv6
                // without running two listeners.
                _listener = new TcpListener(IPAddress.IPv6Any, port);
                _listener.Server.DualMode = true;
                _listener.Start();
            }
            catch (Exception ex)
            {
                _listener = null;
                Failed?.Invoke(this, $"Could not listen on port {port}: {ex.Message}");
                return;
            }

            _acceptLoop = Task.Run(() => AcceptLoopAsync(_cts.Token));
        }

        /// <summary>Stops listening and closes all connections.</summary>
        public void Stop()
        {
            try { _cts?.Cancel(); } catch { }

            try { _listener?.Stop(); } catch { }
            _listener = null;

            foreach (SatelliteSession session in _sessions.Values) session.Dispose();
            _sessions.Clear();
        }

        private async Task AcceptLoopAsync(CancellationToken token)
        {
            while (!token.IsCancellationRequested && _listener is not null)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(token);
                }
                catch (OperationCanceledException) { return; }
                catch (ObjectDisposedException) { return; }
                catch (Exception ex)
                {
                    Failed?.Invoke(this, $"Accepting a satellite failed: {ex.Message}");
                    return;
                }

                // Each connection on its own: a satellite that hangs during the
                // handshake must not hold up the others.
                _ = Task.Run(() => HandshakeAsync(client, token), token);
            }
        }

        private async Task HandshakeAsync(TcpClient client, CancellationToken token)
        {
            string remote = client.Client.RemoteEndPoint?.ToString() ?? "unknown";
            SslStream? tls = null;

            try
            {
                tls = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);

                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = _certificate,
                    ClientCertificateRequired = true,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,

                    // Accepts any certificate: what is checked is not the chain
                    // of trust but the fingerprint against the approval. A
                    // satellite issues its own certificate, so there is no chain.
                    RemoteCertificateValidationCallback = (_, _, _, _) => true
                }, token);

                if (tls.RemoteCertificate is null)
                {
                    throw new AuthenticationException("The satellite did not present a certificate.");
                }

                using X509Certificate2 presented = new(tls.RemoteCertificate);
                string fingerprint = SatelliteIdentity.Fingerprint(presented);

                MessageChannel channel = new(tls);

                SatelliteMessage? hello = await channel.ReceiveAsync(token);
                if (hello is null || !hello.IsHello)
                {
                    throw new InvalidDataException("Expected a hello as the first message.");
                }

                if (hello.ProtocolVersion != ProtocolVersion)
                {
                    await channel.SendAsync(new SatelliteMessage
                    {
                        Type = MessageType.Error,
                        ProtocolVersion = ProtocolVersion,
                        Text = $"Protocol version {hello.ProtocolVersion} is not supported, this one speaks {ProtocolVersion}."
                    }, token);

                    throw new InvalidDataException($"Protocol version {hello.ProtocolVersion} rejected.");
                }

                bool approved = _isApproved(fingerprint);

                await channel.SendAsync(new SatelliteMessage
                {
                    Type = approved ? MessageType.Welcome : MessageType.Pending,
                    ProtocolVersion = ProtocolVersion,
                    AppVersion = _ownVersion,
                    Text = approved
                        ? null
                        : "Waiting for approval on the main scanner. Nothing to do here - the connection stays open."
                }, token);

                SatelliteSession session = new(client, tls, channel, fingerprint);

                // If the same satellite connects a second time, the new
                // connection wins: the old one is almost always a dead
                // connection that the disconnect never reached.
                if (_sessions.TryRemove(fingerprint, out SatelliteSession? stale)) stale.Dispose();
                _sessions[fingerprint] = session;

                // Announces the satellite only now, not right after the hello.
                //
                // "Announced" means to every listener: from here on, messages
                // can be sent to it. Raised before the session is registered, a
                // job sent immediately afterwards would go nowhere: SendJobAsync
                // would find no session and return null. Manual operation never
                // shows this, because seconds pass between login and click.
                Announced?.Invoke(this, new SatelliteAnnouncedEventArgs
                {
                    Name = hello.Name ?? "unnamed",
                    Fingerprint = fingerprint,
                    AppVersion = hello.AppVersion ?? string.Empty,
                    Os = hello.Os ?? string.Empty,
                    RemoteAddress = remote,
                    Site = hello.Site
                });

                await PumpAsync(session, token);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                Failed?.Invoke(this, $"Satellite at {remote}: {ex.Message}");
            }
            finally
            {
                tls?.Dispose();
                client.Dispose();
            }
        }

        /// <summary>Reads what the satellite sends until the connection ends.</summary>
        private async Task PumpAsync(SatelliteSession session, CancellationToken token)
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    SatelliteMessage? message = await session.Channel.ReceiveAsync(token);
                    if (message is null) break; // closed cleanly

                    switch (message.Type)
                    {
                        case MessageType.Pong:
                            break;

                        case MessageType.Ping:
                            await session.Channel.SendAsync(new SatelliteMessage
                            {
                                Type = MessageType.Pong,
                                ProtocolVersion = ProtocolVersion
                            }, token);
                            break;

                        case MessageType.Progress:
                            if (message.Progress is not null)
                            {
                                ProgressReported?.Invoke(this, (session.Fingerprint, message.Progress));
                            }
                            break;

                        case MessageType.Result:
                            ResultReceived?.Invoke(this,
                                (session.Fingerprint, message.JobId ?? string.Empty,
                                 message.Devices ?? "[]", message.Partial));

                            // Acknowledges receipt so that the satellite may
                            // release the result.
                            await session.Channel.SendAsync(new SatelliteMessage
                            {
                                Type = MessageType.ResultAck,
                                ProtocolVersion = ProtocolVersion,
                                JobId = message.JobId
                            }, token);
                            break;

                        case MessageType.Busy:
                            JobEnded?.Invoke(this, (session.Fingerprint,
                                message.Text ?? "The satellite is already running a job."));
                            break;

                        case MessageType.Cancelled:
                            JobEnded?.Invoke(this, (session.Fingerprint, "Job cancelled."));
                            break;

                        case MessageType.Error:
                            JobEnded?.Invoke(this, (session.Fingerprint, message.Text ?? "The satellite reported an error."));
                            break;

                        default:
                            break;
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception) { }
            finally
            {
                // Removes the entry only if *this* session is still the
                // registered one.
                //
                // If the same satellite connects a second time (for example
                // because its user interface and its service connect at the
                // same time), the new session replaces the old one. The old one
                // then ends here, and a blind TryRemove by fingerprint would
                // delete the *new* one from the list: the connection would still
                // be up but unreachable for jobs, and the display would show
                // "offline". This is what happens when the satellite is set up
                // as a service while its window is still connected.
                bool wasCurrent = _sessions.TryRemove(
                    new KeyValuePair<string, SatelliteSession>(session.Fingerprint, session));

                session.Dispose();

                if (wasCurrent) Disconnected?.Invoke(this, session.Fingerprint);
            }
        }

        /// <summary>
        /// Sends a job to a connected satellite.
        /// </summary>
        /// <param name="fingerprint">Fingerprint of the satellite.</param>
        /// <param name="jobText">The job as produced by <see cref="JobRequest.Format"/>.</param>
        /// <param name="token">Cancels the send.</param>
        /// <returns>The job identifier, or <c>null</c> if the satellite is not connected.</returns>
        public async Task<string?> SendJobAsync(string fingerprint, string jobText, CancellationToken token)
        {
            if (!_sessions.TryGetValue(fingerprint, out SatelliteSession? session)) return null;

            string jobId = MessageChannel.NewJobId();

            await session.Channel.SendAsync(new SatelliteMessage
            {
                Type = MessageType.Job,
                ProtocolVersion = ProtocolVersion,
                JobId = jobId,
                Text = jobText
            }, token);

            return jobId;
        }

        /// <summary>
        /// Tells an already connected satellite that it has just been approved.
        /// <para>
        /// Without this it would keep showing "waiting for approval" although
        /// jobs already go through; it would learn of the approval only on the
        /// next connect. When both sides are set up side by side, the satellite
        /// would show something different from the main scanner.
        /// </para>
        /// </summary>
        /// <param name="fingerprint">Fingerprint of the approved satellite.</param>
        /// <param name="token">Cancels the send.</param>
        public async Task NotifyApprovedAsync(string fingerprint, CancellationToken token)
        {
            if (!_sessions.TryGetValue(fingerprint, out SatelliteSession? session)) return;

            await session.Channel.SendAsync(new SatelliteMessage
            {
                Type = MessageType.Welcome,
                ProtocolVersion = ProtocolVersion,
                AppVersion = _ownVersion
            }, token);
        }

        /// <summary>Cancels the running job of a satellite.</summary>
        /// <param name="fingerprint">Fingerprint of the satellite.</param>
        /// <param name="jobId">The job to cancel, or <c>null</c> for whatever is running.</param>
        /// <param name="token">Cancels the send.</param>
        public async Task CancelAsync(string fingerprint, string? jobId, CancellationToken token)
        {
            if (!_sessions.TryGetValue(fingerprint, out SatelliteSession? session)) return;

            await session.Channel.SendAsync(new SatelliteMessage
            {
                Type = MessageType.Cancel,
                ProtocolVersion = ProtocolVersion,
                JobId = jobId
            }, token);
        }

        /// <summary>Stops the listener and waits for the accept loop to end.</summary>
        public async ValueTask DisposeAsync()
        {
            Stop();

            if (_acceptLoop is not null)
            {
                try { await _acceptLoop; } catch { }
            }

            _cts?.Dispose();
        }

        /// <summary>An open connection to a satellite.</summary>
        private sealed class SatelliteSession(
            TcpClient client, SslStream stream, MessageChannel channel, string fingerprint) : IDisposable
        {
            public MessageChannel Channel { get; } = channel;
            public string Fingerprint { get; } = fingerprint;

            public void Dispose()
            {
                try { stream.Dispose(); } catch { }
                try { client.Dispose(); } catch { }
            }
        }
    }
}
