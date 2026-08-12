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

        /// <summary>
        /// Wo der Satellit steht - oder <c>null</c>, wenn er nichts gemeldet
        /// hat. Kommt bei jeder Anmeldung frisch, nicht nur beim ersten Mal.
        /// </summary>
        public SitePayload? Site { get; init; }
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

        /// <summary>Ein Satellit meldet Fortschritt: Fingerabdruck und Stand.</summary>
        public event EventHandler<(string Fingerprint, ProgressPayload Progress)>? ProgressReported;

        /// <summary>
        /// Ein Auftrag ist fertig: Fingerabdruck, Auftragskennung und der
        /// gefundene Bestand als JSON.
        /// </summary>
        public event EventHandler<(string Fingerprint, string JobId, string Devices, bool Partial)>? ResultReceived;

        /// <summary>Ein Auftrag endete ohne Ergebnis - abgebrochen oder gescheitert.</summary>
        public event EventHandler<(string Fingerprint, string Text)>? JobEnded;

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

                // Erst jetzt melden, dass er da ist - nicht schon nach der
                // Begruessung.
                //
                // "Angemeldet" heisst fuer jeden Zuhoerer: ab hier kann man ihm
                // etwas schicken. Wurde das Ereignis noch vor dem Eintragen der
                // Sitzung ausgeloest, lief ein Auftrag, den jemand unmittelbar
                // darauf abschickte, ins Leere - SendJobAsync fand keine
                // Sitzung und gab null zurueck. Von Hand fiel das nie auf, weil
                // zwischen Anmeldung und Klick immer Sekunden liegen.
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

                            // Empfang bestaetigen, damit der Satellit das
                            // Ergebnis loslassen darf.
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
                // Nur austragen, wenn *diese* Sitzung noch die eingetragene ist.
                //
                // Meldet sich derselbe Satellit ein zweites Mal - etwa weil auf
                // seiner Seite die Oberflaeche und der Dienst gleichzeitig
                // verbinden -, ersetzt die neue Sitzung die alte. Die alte
                // laeuft danach hier aus, und ein blindes TryRemove nach dem
                // Fingerabdruck loeschte die *neue* wieder aus der Liste: die
                // Verbindung stuende noch, waere aber fuer Auftraege
                // unerreichbar, und die Anzeige meldete "offline". Genau so
                // sah es aus, wenn man den Satelliten als Dienst einrichtete,
                // waehrend sein Fenster noch verbunden war.
                bool wasCurrent = _sessions.TryRemove(
                    new KeyValuePair<string, SatelliteSession>(session.Fingerprint, session));

                session.Dispose();

                if (wasCurrent) Disconnected?.Invoke(this, session.Fingerprint);
            }
        }

        /// <summary>
        /// Schickt einen Auftrag an einen verbundenen Satelliten. Gibt die
        /// Auftragskennung zurueck, oder <c>null</c>, wenn er nicht verbunden
        /// ist.
        /// </summary>
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
        /// Sagt einem bereits verbundenen Satelliten, dass er soeben
        /// freigegeben wurde.
        /// <para>
        /// Ohne das bliebe er auf "wartet auf Freigabe" stehen, obwohl
        /// Auftraege schon durchgehen - er erfuehre es erst beim naechsten
        /// Verbinden. Wer beide Seiten nebeneinander einrichtet, saehe dann am
        /// Satelliten etwas anderes als am Hauptscanner.
        /// </para>
        /// </summary>
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

        /// <summary>Bricht den laufenden Auftrag eines Satelliten ab.</summary>
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
