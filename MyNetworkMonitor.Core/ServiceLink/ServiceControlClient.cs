// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.IO.Pipes;
using System.Text.Json;
using MyNetworkMonitor.Core.SatelliteLink;

namespace MyNetworkMonitor.Core.ServiceLink
{
    /// <summary>
    /// The user interface side: polls the service every second for what it is
    /// doing and can send it two commands.
    /// <para>
    /// Polling instead of listening: the service keeps running while the
    /// window is closed and may have been running for days. A connection that
    /// lives only while the window is open is simpler - it cannot go stale,
    /// and restarting the window cleans it up automatically.
    /// </para>
    /// </summary>
    public sealed class ServiceControlClient : IAsyncDisposable
    {
        private CancellationTokenSource? _cts;
        private Task? _loop;

        /// <summary>The polling interval.</summary>
        public TimeSpan Interval { get; set; } = TimeSpan.FromSeconds(1);

        /// <summary>Raised when a new snapshot has been received.</summary>
        public event EventHandler<ServiceSnapshot>? SnapshotReceived;

        /// <summary>
        /// Raised when the connection is established or lost, so that the
        /// display can distinguish "service not running" from "service not
        /// responding".
        /// </summary>
        public event EventHandler<bool>? ReachableChanged;

        private bool _reachable;

        /// <summary>Starts polling; a running poll loop is stopped first.</summary>
        public void Start()
        {
            Stop();

            _cts = new CancellationTokenSource();
            _loop = Task.Run(() => PollLoopAsync(_cts.Token));
        }

        /// <summary>Stops polling and reports the service as unreachable.</summary>
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

                    // The connection stays open as long as it works, which
                    // saves a connection setup every second.
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
                    // No service present, or it has just been stopped. This is
                    // the normal case on an installation without the service
                    // and not worth a message - only the display falls back.
                    SetReachable(false);
                }

                try { await Task.Delay(TimeSpan.FromSeconds(3), token); }
                catch (OperationCanceledException) { return; }
            }
        }

        /// <summary>
        /// Sends a single command and returns the answer as plain text. Uses a
        /// separate, short-lived connection so that the poll loop is not
        /// affected.
        /// </summary>
        /// <param name="type">One of the constants in <see cref="ServiceMessageType"/>.</param>
        /// <param name="token">Cancels the request.</param>
        /// <returns>The answer of the service, or an error text if it could not be reached.</returns>
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

        /// <summary>Stops polling and waits for the poll loop to end.</summary>
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
