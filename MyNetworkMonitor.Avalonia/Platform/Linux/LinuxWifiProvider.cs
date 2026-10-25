// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System;
using System.Threading;
using System.Threading.Tasks;
using MyNetworkMonitor.Core.Models;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Avalonia.Platform.Linux
{
    /// <summary>
    /// Linux implementation of <see cref="IWifiProvider"/> based on "nmcli".
    /// Polls the active Wi-Fi network at an interval and reports its signal
    /// quality (0-100), using the same dBm approximation as the Windows
    /// provider: (signal - 100) * 2.
    /// </summary>
    public sealed class LinuxWifiProvider : IWifiProvider
    {
        public event EventHandler<WiFiSignalResult>? WiFiSignalStrengthUpdated;

        private CancellationTokenSource? _cts;
        private bool _isScanning;

        public bool IsScanning => _isScanning;

        public async Task StartScanningAsync(int intervalMs = 2000)
        {
            if (_isScanning) return;
            _cts = new CancellationTokenSource();
            _isScanning = true;
            var token = _cts.Token;

            await Task.Run(async () =>
            {
                while (!token.IsCancellationRequested)
                {
                    try { await ScanOnceAsync(token).ConfigureAwait(false); }
                    catch { /* Ignore scan errors and keep polling. */ }

                    try { await Task.Delay(intervalMs, token).ConfigureAwait(false); }
                    catch (OperationCanceledException) { break; }
                }
            }, token).ConfigureAwait(false);
        }

        private async Task ScanOnceAsync(CancellationToken cancellationToken)
        {
            // -t = terse, machine-readable output (":"-separated); only the active network (ACTIVE=yes) counts.
            string output = await ProcessRunner.RunAsync("nmcli", "-t -f ACTIVE,SSID,SIGNAL dev wifi", cancellationToken)
                .ConfigureAwait(false);

            foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var fields = line.Split(':');
                if (fields.Length < 3) continue;
                if (!string.Equals(fields[0], "yes", StringComparison.OrdinalIgnoreCase)) continue;

                string ssid = fields[1];
                if (!int.TryParse(fields[2], out int signal)) continue;

                WiFiSignalStrengthUpdated?.Invoke(this, new WiFiSignalResult
                {
                    SSID = ssid,
                    SignalStrength = signal,
                    SignalStrengthDbm = (signal - 100) * 2,
                    Timestamp = DateTime.Now
                });
            }
        }

        public void StopScanning()
        {
            if (!_isScanning) return;
            _cts?.Cancel();
            _isScanning = false;
        }
    }
}
