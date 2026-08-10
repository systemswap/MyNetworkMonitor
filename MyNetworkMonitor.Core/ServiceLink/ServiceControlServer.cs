using System.IO.Pipes;
using System.Text.Json;
using MyNetworkMonitor.Core.SatelliteLink;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Core.ServiceLink
{
    /// <summary>
    /// Die Seite des Dienstes: nimmt Verbindungen der Oberflaeche auf einer
    /// benannten Pipe an und beantwortet sie.
    /// <para>
    /// Eine Pipe und kein Port auf localhost: es gibt keinen Port zu vergeben,
    /// nichts, was mit einer anderen Anwendung kollidiert, und keine
    /// Firewall-Regel. Die Zugriffsrechte regelt das Betriebssystem - unter
    /// Windows ueber die Zugriffsliste der Pipe, unter Linux ueber die Rechte
    /// der Socketdatei.
    /// </para>
    /// </summary>
    public sealed class ServiceControlServer : IAsyncDisposable
    {
        private readonly Func<ServiceSnapshot> _snapshot;
        private readonly Func<string, string> _command;

        private CancellationTokenSource? _cts;
        private Task? _loop;

        /// <param name="snapshot">Liefert den aktuellen Zustand.</param>
        /// <param name="command">
        /// Fuehrt einen Befehl aus und gibt Klartext zurueck. Bekommt eine der
        /// Konstanten aus <see cref="ServiceMessageType"/>.
        /// </param>
        public ServiceControlServer(Func<ServiceSnapshot> snapshot, Func<string, string> command)
        {
            _snapshot = snapshot ?? throw new ArgumentNullException(nameof(snapshot));
            _command = command ?? throw new ArgumentNullException(nameof(command));
        }

        /// <summary>Meldet, was schiefging - fuer das Protokoll des Dienstes.</summary>
        public event EventHandler<string>? Failed;

        public void Start()
        {
            Stop();

            _cts = new CancellationTokenSource();
            _loop = Task.Run(() => AcceptLoopAsync(_cts.Token));
        }

        public void Stop()
        {
            try { _cts?.Cancel(); } catch { }
        }

        /// <summary>
        /// Immer nur eine Verbindung zur Zeit, dafuer beliebig oft
        /// hintereinander. Mehr braucht es nicht: es sitzt hoechstens ein
        /// Fenster davor, und wer ein zweites oeffnet, wartet einen Wimpernschlag.
        /// </summary>
        private async Task AcceptLoopAsync(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                NamedPipeServerStream? pipe = null;

                try
                {
                    pipe = PlatformServices.CreatePipeServer(ServicePipe.Name);

                    await pipe.WaitForConnectionAsync(token);
                    await ServeAsync(pipe, token);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (Exception ex)
                {
                    Failed?.Invoke(this, $"The control pipe failed: {ex.Message}");

                    // Kurz durchatmen, sonst dreht die Schleife bei einem
                    // dauerhaften Fehler mit voller Kraft.
                    try { await Task.Delay(TimeSpan.FromSeconds(5), token); }
                    catch (OperationCanceledException) { return; }
                }
                finally
                {
                    try { pipe?.Dispose(); } catch { }
                }
            }
        }

        private async Task ServeAsync(NamedPipeServerStream pipe, CancellationToken token)
        {
            MessageChannel channel = new(pipe);

            while (!token.IsCancellationRequested && pipe.IsConnected)
            {
                SatelliteMessage? message = await channel.ReceiveAsync(token);
                if (message is null) return;

                switch (message.Type)
                {
                    case ServiceMessageType.Status:
                        await channel.SendAsync(new SatelliteMessage
                        {
                            Type = ServiceMessageType.StatusReply,
                            Text = JsonSerializer.Serialize(_snapshot())
                        }, token);
                        break;

                    case ServiceMessageType.StopJob:
                    case ServiceMessageType.Reconnect:
                        await channel.SendAsync(new SatelliteMessage
                        {
                            Type = ServiceMessageType.Done,
                            Text = _command(message.Type)
                        }, token);
                        break;

                    default:
                        // Unbekanntes wird beantwortet statt verschluckt - sonst
                        // wartet die Gegenseite auf etwas, das nie kommt.
                        await channel.SendAsync(new SatelliteMessage
                        {
                            Type = ServiceMessageType.Done,
                            Text = $"Unknown request \"{message.Type}\"."
                        }, token);
                        break;
                }
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
