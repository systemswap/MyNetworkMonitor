using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace MyNetworkMonitor.Core.SatelliteLink
{
    /// <summary>Ein Satellit hat sich gemeldet.</summary>
    public sealed class SatelliteAnnouncedEventArgs : EventArgs
    {
        public required string Name { get; init; }
        public required string Fingerprint { get; init; }
        public required string AppVersion { get; init; }
        public required string Os { get; init; }
        public required string RemoteAddress { get; init; }
    }

    /// <summary>
    /// Die Seite des Hauptscanners: nimmt Verbindungen von Satelliten an.
    /// <para>
    /// Der Satellit verbindet sich hierher, nicht umgekehrt - siehe
    /// SATELLIT.md, Abschnitt 1. Darum lauscht diese Klasse, und darum kennt
    /// sie keine Adressen von Satelliten: die erfaehrt sie erst, wenn einer
    /// anklopft.
    /// </para>
    /// </summary>
    public sealed class SatelliteListener : IAsyncDisposable
    {
        public const int ProtocolVersion = 1;
        public const int DefaultPort = 27411;

        private readonly X509Certificate2 _certificate;
        private readonly Func<string, bool> _isApproved;
        private readonly string _ownVersion;

        private TcpListener? _listener;
        private CancellationTokenSource? _cts;
        private Task? _acceptLoop;

        /// <summary>Die derzeit offenen Verbindungen, nach Fingerabdruck.</summary>
        private readonly ConcurrentDictionary<string, SatelliteSession> _sessions = new(StringComparer.OrdinalIgnoreCase);

        public SatelliteListener(X509Certificate2 certificate, Func<string, bool> isApproved, string ownVersion)
        {
            _certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
            _isApproved = isApproved ?? throw new ArgumentNullException(nameof(isApproved));
            _ownVersion = ownVersion ?? string.Empty;
        }

        /// <summary>Ein Satellit hat sich vorgestellt - Name, Kennung, Herkunft.</summary>
        public event EventHandler<SatelliteAnnouncedEventArgs>? Announced;

        /// <summary>Die Verbindung zu einem Satelliten ist weg.</summary>
        public event EventHandler<string>? Disconnected;

        /// <summary>Etwas ist schiefgegangen - Klartext fuer die Statuszeile.</summary>
        public event EventHandler<string>? Failed;

        public bool IsListening => _listener is not null;
        public int Port { get; private set; }

        /// <summary>Fingerabdruecke der gerade verbundenen Satelliten.</summary>
        public IReadOnlyCollection<string> ConnectedFingerprints => [.. _sessions.Keys];

        public void Start(int port)
        {
            Stop();

            Port = port;
            _cts = new CancellationTokenSource();

            try
            {
                // IPv6Any mit DualMode: so werden Satelliten ueber IPv4 und
                // IPv6 angenommen, ohne zwei Lauscher zu betreiben.
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

                // Jede Verbindung fuer sich: ein Satellit, der beim Handschlag
                // haengt, darf die uebrigen nicht aufhalten.
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

                    // Jedes Zertifikat annehmen: geprueft wird nicht die
                    // Vertrauenskette, sondern der Fingerabdruck gegen die
                    // Freigabe. Ein Satellit stellt sein Zertifikat selbst aus,
                    // eine Kette gaebe es also gar nicht.
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

                Announced?.Invoke(this, new SatelliteAnnouncedEventArgs
                {
                    Name = hello.Name ?? "unnamed",
                    Fingerprint = fingerprint,
                    AppVersion = hello.AppVersion ?? string.Empty,
                    Os = hello.Os ?? string.Empty,
                    RemoteAddress = remote
                });

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

                // Meldet sich derselbe Satellit ein zweites Mal, gilt die neue
                // Verbindung: die alte ist dann fast immer eine Leiche, die der
                // Abbruch nicht erreicht hat.
                if (_sessions.TryRemove(fingerprint, out SatelliteSession? stale)) stale.Dispose();
                _sessions[fingerprint] = session;

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

        /// <summary>Liest, was der Satellit schickt, bis die Verbindung endet.</summary>
        private async Task PumpAsync(SatelliteSession session, CancellationToken token)
        {
            try
            {
                while (!token.IsCancellationRequested)
                {
                    SatelliteMessage? message = await session.Channel.ReceiveAsync(token);
                    if (message is null) break; // sauber aufgelegt

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

                        // Auftrag, Fortschritt und Ergebnis kommen, sobald die
                        // Ausfuehrung gebaut ist - siehe SATELLIT.md.
                        default:
                            break;
                    }
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception) { }
            finally
            {
                _sessions.TryRemove(session.Fingerprint, out _);
                session.Dispose();
                Disconnected?.Invoke(this, session.Fingerprint);
            }
        }

        public async ValueTask DisposeAsync()
        {
            Stop();

            if (_acceptLoop is not null)
            {
                try { await _acceptLoop; } catch { }
            }

            _cts?.Dispose();
        }

        /// <summary>Eine offene Verbindung zu einem Satelliten.</summary>
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
