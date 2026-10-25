using System.IO.Pipes;
using System.Text.Json;
using MyNetworkMonitor.Core.SatelliteLink;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Core.ServiceLink
{
    /// <summary>
    /// The service side: accepts connections from the user interface on a
    /// named pipe and answers them.
    /// <para>
    /// A pipe rather than a port on localhost: there is no port to assign,
    /// nothing that collides with another application, and no firewall rule.
    /// The operating system controls access - on Windows through the access
    /// control list of the pipe, on Linux through the permissions of the
    /// socket file.
    /// </para>
    /// </summary>
    public sealed class ServiceControlServer : IAsyncDisposable
    {
        private readonly Func<ServiceSnapshot> _snapshot;
        private readonly Func<string, string> _command;

        private CancellationTokenSource? _cts;
        private Task? _loop;

        /// <summary>Creates the server.</summary>
        /// <param name="snapshot">Returns the current state.</param>
        /// <param name="command">
        /// Executes a command and returns plain text. Receives one of the
        /// constants in <see cref="ServiceMessageType"/>.
        /// </param>
        /// <exception cref="ArgumentNullException"><paramref name="snapshot"/> or <paramref name="command"/> is <c>null</c>.</exception>
        public ServiceControlServer(Func<ServiceSnapshot> snapshot, Func<string, string> command)
        {
            _snapshot = snapshot ?? throw new ArgumentNullException(nameof(snapshot));
            _command = command ?? throw new ArgumentNullException(nameof(command));
        }

        /// <summary>Reports what went wrong, for the service log.</summary>
        public event EventHandler<string>? Failed;

        /// <summary>Starts accepting connections; a running accept loop is stopped first.</summary>
        public void Start()
        {
            Stop();

            _cts = new CancellationTokenSource();
            _loop = Task.Run(() => AcceptLoopAsync(_cts.Token));
        }

        /// <summary>Stops accepting connections.</summary>
        public void Stop()
        {
            try { _cts?.Cancel(); } catch { }
        }

        /// <summary>
        /// Serves one connection at a time, any number of times in a row. That
        /// is sufficient: at most one window is attached, and a second window
        /// waits only a moment.
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

                    // Pause briefly; otherwise a persistent error would make
                    // the loop spin at full speed.
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
                        // Unknown requests are answered instead of ignored -
                        // otherwise the peer waits for a reply that never comes.
                        await channel.SendAsync(new SatelliteMessage
                        {
                            Type = ServiceMessageType.Done,
                            Text = $"Unknown request \"{message.Type}\"."
                        }, token);
                        break;
                }
            }
        }

        /// <summary>Stops the server and waits for the accept loop to end.</summary>
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
