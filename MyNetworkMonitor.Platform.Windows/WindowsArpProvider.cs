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

namespace MyNetworkMonitor.Platform.Windows
{
    /// <summary>
    /// Windows implementation of <see cref="IArpProvider"/>.
    /// Encapsulates the platform-specific ARP primitives (Win32 SendARP and the
    /// arp command-line tool) so that the scan logic stays independent of them.
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
                    return (string?)null; // address could not be resolved

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

                // Three tokens alone are not enough: header and interface lines
                // ("Interface: 192.0.2.5 --- 0xc") can also split into three
                // tokens, depending on the Windows version and language. Only
                // when the first token is an IP address is the line an entry
                // rather than a header.
                if (pieces.Length == 3 && IPAddress.TryParse(pieces[0], out _))
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
            catch (OperationCanceledException)
            {
                // Otherwise "arp -a" keeps running in the background although the
                // scan has been cancelled; short-lived, but needless across many
                // targets in a row.
                if (p is not null)
                {
                    try { p.Kill(entireProcessTree: true); } catch (InvalidOperationException) { /* already exited */ }
                }
                throw;
            }
            finally
            {
                p?.Close();
            }
        }
    }
}
