using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using MyNetworkMonitor.Core.Models;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Platform
{
    /// <summary>
    /// Windows-Implementierung von <see cref="IArpProvider"/>.
    /// Kapselt die plattformspezifischen ARP-Primitiven (Win32 SendARP sowie das
    /// arp-Kommandozeilenwerkzeug), damit die Scan-Logik davon unabhängig bleibt.
    /// </summary>
    public sealed class WindowsArpProvider : IArpProvider
    {
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int destIp, int srcIp, byte[] macAddr, ref uint physicalAddrLen);

        public Task<string?> ResolveMacAsync(IPAddress ip, CancellationToken cancellationToken = default)
        {
            return Task.Run(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();

                byte[] macAddr = new byte[6];
                uint macAddrLen = (uint)macAddr.Length;

                int result = SendARP(BitConverter.ToInt32(ip.GetAddressBytes(), 0), 0, macAddr, ref macAddrLen);
                if (result != 0)
                    return (string?)null; // keine Auflösung möglich

                return string.Join("-", macAddr.Take((int)macAddrLen).Select(b => b.ToString("x2")));
            }, cancellationToken);
        }

        public async Task<IReadOnlyList<ArpEntry>> GetArpTableAsync(CancellationToken cancellationToken = default)
        {
            string output = await RunArpAsync("-a", cancellationToken).ConfigureAwait(false);

            var entries = new List<ArpEntry>();
            foreach (var line in output.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var pieces = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (pieces.Length == 3)
                {
                    entries.Add(new ArpEntry { IpAddress = pieces[0], MacAddress = pieces[1] });
                }
            }
            return entries;
        }

        public bool FlushArpCache()
        {
            try
            {
                var p = Process.Start(new ProcessStartInfo("arp", "-d")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true
                });
                p?.WaitForExit();
                p?.Close();
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static async Task<string> RunArpAsync(string arguments, CancellationToken cancellationToken)
        {
            Process? p = null;
            try
            {
                p = Process.Start(new ProcessStartInfo("arp", arguments)
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true
                });

                if (p == null) return string.Empty;

                string output = await p.StandardOutput.ReadToEndAsync().WaitAsync(cancellationToken).ConfigureAwait(false);
                await p.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
                return output;
            }
            finally
            {
                p?.Close();
            }
        }
    }
}
