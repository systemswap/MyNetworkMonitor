using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace MyNetworkMonitor.Core.SatelliteLink
{
    /// <summary>Was der Satellit gerade tut - fuer die Anzeige.</summary>
    public enum SatelliteLinkState
    {
        Idle,
        Connecting,
        WaitingForApproval,
        Connected,
        Failed
    }

    /// <summary>
    /// Die Seite des Satelliten: verbindet sich hinaus zu einem Hauptscanner
    /// und haelt die Verbindung offen.
    /// <para>
    /// Ausgehend, weil damit keine Freigabe in das fremde Segment hinein
    /// noetig ist und der Satellit selbst auf nichts lauscht - siehe
    /// SATELLIT.md, Abschnitt 1. Der Hauptscanner darf seine Adresse wechseln,
    /// solange sein Name gleich bleibt; wiedererkannt wird er ohnehin am
    /// Fingerabdruck.
    /// </para>
    /// </summary>
    public sealed class SatelliteClient : IAsyncDisposable
    {
        private readonly X509Certificate2 _certificate;
        private readonly string _ownName;
        private readonly string _ownVersion;

        private CancellationTokenSource? _cts;
        private Task? _loop;

        public SatelliteClient(X509Certificate2 certificate, string ownName, string ownVersion)
        {
            _certificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
            _ownName = string.IsNullOrWhiteSpace(ownName) ? Environment.MachineName : ownName;
            _ownVersion = ownVersion ?? string.Empty;
        }

        /// <summary>Zustandsaenderung samt Klartext fuer die Anzeige.</summary>
        public event EventHandler<(SatelliteLinkState State, string Text)>? StateChanged;

        /// <summary>
        /// Der Fingerabdruck des Hauptscanners, wie er beim ersten
        /// erfolgreichen Verbinden gemerkt wurde. Leer heisst: noch keiner -
        /// dann wird der naechste uebernommen (Vertrauen beim ersten Mal).
        /// </summary>
        public string PinnedFingerprint { get; set; } = string.Empty;

        /// <summary>Meldet sich, wenn ein Fingerabdruck neu uebernommen wurde.</summary>
        public event EventHandler<string>? FingerprintPinned;

        /// <summary>
        /// Fuehrt einen Auftrag aus und liefert den gefundenen Bestand als
        /// JSON zurueck.
        /// <para>
        /// Als Rueckruf und nicht als Abhaengigkeit: der Transport soll die
        /// Scan-Engine nicht kennen. So bleibt er fuer sich testbar, und wer
        /// ihn benutzt, entscheidet, was ein Auftrag bewirkt.
        /// </para>
        /// </summary>
        public Func<string, IProgress<ProgressPayload>, CancellationToken, Task<string>>? JobRunner { get; set; }

        /// <summary>
        /// Die gemeinsame Auftragsverwaltung. Gemeinsam ueber alle Empfaenger:
        /// nur so laesst sich "einer zur Zeit" halten und beantworten, wer
        /// abbrechen darf.
        /// </summary>
        public SatelliteJobHost Jobs { get; set; } = new();

        /// <summary>
        /// Wie dieser Empfaenger heisst - der Hauptscanner, mit dem diese
        /// Verbindung spricht. Dient als Kennung des Auftraggebers.
        /// </summary>
        private string _receiverKey = string.Empty;

        /// <summary>Laeuft gerade ein Auftrag - und welcher.</summary>
        public string? CurrentJobId => Jobs.CurrentJobId;

        public SatelliteLinkState State { get; private set; } = SatelliteLinkState.Idle;

        /// <summary>
        /// Verbindet und haelt die Verbindung, mit wachsendem Abstand nach
        /// einem Fehlschlag. Kehrt erst zurueck, wenn abgebrochen wird.
        /// </summary>
        public void Start(string host, int port)
        {
            Stop();

            _receiverKey = $"{host}:{port}";
            _cts = new CancellationTokenSource();
            _loop = Task.Run(() => ConnectLoopAsync(host, port, _cts.Token));
        }

        public void Stop()
        {
            try { _cts?.Cancel(); } catch { }
            Report(SatelliteLinkState.Idle, "Not connected.");
        }

        private async Task ConnectLoopAsync(string host, int port, CancellationToken token)
        {
            // Wachsender Abstand: ein Hauptscanner, der aus ist, soll nicht
            // sekuendlich angeklopft bekommen. Deckel bei einer Minute, damit
            // das Wiederkommen nicht ewig dauert.
            TimeSpan wait = TimeSpan.FromSeconds(2);
            TimeSpan maxWait = TimeSpan.FromMinutes(1);

            while (!token.IsCancellationRequested)
            {
                try
                {
                    await ConnectOnceAsync(host, port, token);

                    // Sauber getrennt: sofort wieder versuchen, das war kein
                    // Fehler.
                    wait = TimeSpan.FromSeconds(2);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (Exception ex)
                {
                    Report(SatelliteLinkState.Failed, ex.Message);
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

                    // Vertrauen beim ersten Mal: ist noch keiner gemerkt, wird
                    // dieser uebernommen. Danach muss er passen - ein anderer
                    // Schluessel ist ein anderer Gegenueber, egal wie der Name
                    // lautet.
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

            await channel.SendAsync(new SatelliteMessage
            {
                Type = MessageType.Hello,
                ProtocolVersion = SatelliteListener.ProtocolVersion,
                Name = _ownName,
                AppVersion = _ownVersion,
                Os = RuntimeInformation.OSDescription
            }, token);

            SatelliteMessage? answer = await channel.ReceiveAsync(token)
                ?? throw new AuthenticationException("The main scanner closed the connection without answering.");

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
        /// Haelt die Verbindung und beantwortet, was hereinkommt. Endet, wenn
        /// die Gegenstelle auflegt.
        /// </summary>
        private async Task PumpAsync(MessageChannel channel, CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                SatelliteMessage? message = await channel.ReceiveAsync(token);
                if (message is null) return; // Gegenstelle hat aufgelegt

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
                        // Freigabe kann nachtraeglich kommen, waehrend die
                        // Verbindung schon steht.
                        Report(SatelliteLinkState.Connected, "Approved.");
                        break;

                    case MessageType.Error:
                        Report(SatelliteLinkState.Failed, message.Text ?? "Refused by the main scanner.");
                        return;

                    case MessageType.Job:
                        await StartJobAsync(channel, message, token);
                        break;

                    case MessageType.Cancel:
                        // Wer abbrechen darf, entscheidet die Auftragsverwaltung:
                        // der Auftraggeber immer, jeder andere nur, wenn es
                        // erlaubt ist. Ein abgelehnter Abbruch wird beantwortet
                        // statt verschluckt - sonst drueckt jemand auf Stopp und
                        // nichts geschieht.
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
        /// Nimmt einen Auftrag an und laesst ihn im Hintergrund laufen.
        /// <para>
        /// Im Hintergrund, damit die Verbindung waehrenddessen ansprechbar
        /// bleibt: sonst kaeme waehrend eines langen Scans weder ein Abbruch
        /// noch ein Lebenszeichen durch.
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
                        // Fortschritt ist fluechtig: geht er verloren, fehlt nur
                        // die Anzeige. Darum ohne Warten und ohne Aufhebens.
                        _ = channel.SendAsync(new SatelliteMessage
                        {
                            Type = MessageType.Progress,
                            ProtocolVersion = SatelliteListener.ProtocolVersion,
                            JobId = jobId,
                            Progress = p
                        }, CancellationToken.None);
                    });

                    string devices = await JobRunner(message.Text ?? string.Empty, progress, jobCts.Token);

                    await channel.SendAsync(new SatelliteMessage
                    {
                        Type = MessageType.Result,
                        ProtocolVersion = SatelliteListener.ProtocolVersion,
                        JobId = jobId,
                        Devices = devices
                    }, CancellationToken.None);
                }
                catch (OperationCanceledException)
                {
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
        /// Sendet, ohne dass ein Fehlschlag den Aufrufer stoert - fuer
        /// Abschlussmeldungen, bei denen die Verbindung schon weg sein kann.
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
