using System.IO.Pipes;
using System.Text.Json;
using MyNetworkMonitor.Core.SatelliteLink;

namespace MyNetworkMonitor.Core.ServiceLink
{
    /// <summary>
    /// Die Seite der Oberflaeche: fragt den Dienst im Sekundentakt, was er
    /// gerade tut, und kann ihm zwei Dinge sagen.
    /// <para>
    /// Fragen statt zuhoeren: der Dienst laeuft weiter, waehrend das Fenster
    /// zu ist, und laeuft womoeglich schon Tage. Eine Verbindung, die nur
    /// solange lebt, wie jemand hinsieht, ist die einfachere Sache - sie kann
    /// nicht veralten, und ein Neustart des Fensters raeumt sie von selbst auf.
    /// </para>
    /// </summary>
    public sealed class ServiceControlClient : IAsyncDisposable
    {
        private CancellationTokenSource? _cts;
        private Task? _loop;

        /// <summary>Wie oft nachgefragt wird.</summary>
        public TimeSpan Interval { get; set; } = TimeSpan.FromSeconds(1);

        /// <summary>Eine neue Momentaufnahme ist da.</summary>
        public event EventHandler<ServiceSnapshot>? SnapshotReceived;

        /// <summary>
        /// Die Verbindung steht oder steht nicht - damit die Anzeige den
        /// Unterschied zwischen "Dienst laeuft nicht" und "Dienst antwortet
        /// nicht" zeigen kann.
        /// </summary>
        public event EventHandler<bool>? ReachableChanged;

        private bool _reachable;

        public void Start()
        {
            Stop();

            _cts = new CancellationTokenSource();
            _loop = Task.Run(() => PollLoopAsync(_cts.Token));
        }

        public void Stop()
        {
            try { _cts?.Cancel(); } catch { }
            SetReachable(false);
        }

        private void SetReachable(bool value)
        {
            if (_reachable == value) return;

            _reachable = value;
            ReachableChanged?.Invoke(this, value);
        }

        private async Task PollLoopAsync(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await using NamedPipeClientStream pipe = new(
                        ".", ServicePipe.Name, PipeDirection.InOut, PipeOptions.Asynchronous);

                    await pipe.ConnectAsync(3000, token);
                    SetReachable(true);

                    MessageChannel channel = new(pipe);

                    // Die Verbindung bleibt offen, solange sie traegt - das
                    // erspart je Sekunde einen Verbindungsaufbau.
                    while (!token.IsCancellationRequested && pipe.IsConnected)
                    {
                        await channel.SendAsync(new SatelliteMessage { Type = ServiceMessageType.Status }, token);

                        SatelliteMessage? answer = await channel.ReceiveAsync(token);
                        if (answer is null) break;

                        if (answer.Type == ServiceMessageType.StatusReply && answer.Text is { } json)
                        {
                            ServiceSnapshot? snapshot = JsonSerializer.Deserialize<ServiceSnapshot>(json);
                            if (snapshot is not null) SnapshotReceived?.Invoke(this, snapshot);
                        }

                        await Task.Delay(Interval, token);
                    }
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (Exception)
                {
                    // Kein Dienst da, oder er wurde gerade angehalten. Das ist
                    // der Normalfall auf einer Anlage ohne Dienst und keine
                    // Meldung wert - nur die Anzeige faellt zurueck.
                    SetReachable(false);
                }

                try { await Task.Delay(TimeSpan.FromSeconds(3), token); }
                catch (OperationCanceledException) { return; }
            }
        }

        /// <summary>
        /// Schickt einen einzelnen Befehl und gibt die Antwort im Klartext
        /// zurueck. Eigene, kurzlebige Verbindung - der Abfragelauf soll davon
        /// nichts merken.
        /// </summary>
        public static async Task<string> SendCommandAsync(string type, CancellationToken token)
        {
            try
            {
                await using NamedPipeClientStream pipe = new(
                    ".", ServicePipe.Name, PipeDirection.InOut, PipeOptions.Asynchronous);

                await pipe.ConnectAsync(3000, token);

                MessageChannel channel = new(pipe);
                await channel.SendAsync(new SatelliteMessage { Type = type }, token);

                SatelliteMessage? answer = await channel.ReceiveAsync(token);
                return answer?.Text ?? "No answer from the service.";
            }
            catch (Exception ex)
            {
                return $"The service could not be reached: {ex.Message}";
            }
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
