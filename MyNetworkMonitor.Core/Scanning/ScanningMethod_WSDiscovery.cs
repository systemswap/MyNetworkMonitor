// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace MyNetworkMonitor
{
    /// <summary>
    /// WS-Discovery: asks "who is there?" by multicast and evaluates who answers.
    /// <para>
    /// <b>Why it is needed:</b> all other methods only find what answers a targeted request. A
    /// Windows computer with the default firewall does not answer ping, often has no PTR record
    /// and shows no open ports, so it stays invisible. It does answer WS-Discovery, and so do
    /// network printers and scanners: it is the mechanism Windows itself uses to fill its network
    /// view.
    /// </para>
    /// <para>
    /// <b>Why two probes:</b> there are two versions of the protocol with different namespaces.
    /// The 2005 version (namespace 2005/04) is answered by ONVIF devices, the OASIS WS-Discovery 1.1
    /// version of 2009 by Windows devices and printers. Sending only one finds only half of the
    /// devices. That is the difference to <see cref="ScanningMethod_ONVIF_IPCam"/>, which uses
    /// the same technique but asks specifically for cameras.
    /// </para>
    /// </summary>
    public class ScanningMethod_WSDiscovery
    {
        private const string MulticastAddress = "239.255.255.250";
        private const int DiscoveryPort = 3702;

        /// <summary>The namespace of the 2005 version: ONVIF and older devices.</summary>
        private const string Discovery2005 = "http://schemas.xmlsoap.org/ws/2005/04/discovery";

        /// <summary>The namespace of the 2009 version: Windows, printers, scanners.</summary>
        private const string Discovery2009 = "http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01";

        private const string Addressing2004 = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
        private const string Addressing2005 = "http://www.w3.org/2005/08/addressing";

        /// <summary>Reports progress as (probes sent, devices answered, 0, status).</summary>
        public event Action<int, int, int, ScanStatus>? ProgressUpdated;

        /// <summary>Raised once for every address that answered.</summary>
        public event Action<WsDiscoveryResult>? WSDiscovery_DeviceFound;

        /// <summary>Raised when the listening time has ended or the scan was stopped.</summary>
        public event Action<ScanStatus>? WSDiscovery_Scan_Finished;

        private int current;
        private int responded;
        private int total;

        private CancellationTokenSource _cts = new();

        /// <summary>
        /// Cancels the running scan and reports <see cref="ScanStatus.stopped"/>.
        /// </summary>
        public void StopScan()
        {
            if (_cts != null && !_cts.IsCancellationRequested)
            {
                // Only cancel, do not replace: the loops read _cts through the field, and a
                // fresh source would report "running" to them again.
                _cts.Cancel();
            }

            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.stopped);
        }

        private void StartNewScan()
        {
            if (_cts != null)
            {
                if (!_cts.IsCancellationRequested) _cts.Cancel();
                _cts.Dispose();
            }

            _cts = new CancellationTokenSource();

            current = 0;
            responded = 0;
            total = 0;
        }

        /// <summary>
        /// Sends the probes and listens for answers for the given time.
        /// </summary>
        /// <param name="localAddress">
        /// The local IPv4 address the endpoint is bound to. Without the binding, Windows sends the
        /// probe through the adapter with the lowest metric, so with several adapters possibly
        /// into the wrong network.
        /// </param>
        /// <param name="listenMs">Listening time in milliseconds.</param>
        /// <exception cref="ArgumentNullException"><paramref name="localAddress"/> is <see langword="null"/>.</exception>
        public async Task DiscoverAsync(IPAddress localAddress, int listenMs = 5000)
        {
            ArgumentNullException.ThrowIfNull(localAddress);

            StartNewScan();

            // Each address counts only once, even if a device answers both versions and each of
            // the three probes.
            HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

            using UdpClient client = new(new IPEndPoint(localAddress, 0));
            client.EnableBroadcast = true;
            client.MulticastLoopback = false;

            IPEndPoint target = new(IPAddress.Parse(MulticastAddress), DiscoveryPort);

            try
            {
                // Both versions, each three times: the probe is sent by UDP and may get lost.
                // Three attempts, as in the camera search, cost less than a second.
                foreach (string ns in new[] { Discovery2009, Discovery2005 })
                {
                    for (int attempt = 0; attempt < 3; attempt++)
                    {
                        if (_cts.Token.IsCancellationRequested) break;

                        byte[] probe = Encoding.UTF8.GetBytes(BuildProbe(ns));
                        await client.SendAsync(probe, probe.Length, target);

                        int sent = Interlocked.Increment(ref current);
                        ProgressUpdated?.Invoke(sent, responded, total, ScanStatus.running);

                        await Task.Delay(200, _cts.Token);
                    }
                }

                DateTime until = DateTime.UtcNow.AddMilliseconds(listenMs);

                while (DateTime.UtcNow < until && !_cts.Token.IsCancellationRequested)
                {
                    Task<UdpReceiveResult> receive = client.ReceiveAsync(_cts.Token).AsTask();
                    Task finished = await Task.WhenAny(receive, Task.Delay(200, _cts.Token));

                    if (finished != receive) continue;

                    UdpReceiveResult result = await receive;
                    string address = result.RemoteEndPoint.Address.ToString();

                    if (!seen.Add(address)) continue;

                    WsDiscoveryResult found = Parse(Encoding.UTF8.GetString(result.Buffer), address);

                    int respondedValue = Interlocked.Increment(ref responded);
                    ProgressUpdated?.Invoke(current, respondedValue, total, ScanStatus.running);

                    WSDiscovery_DeviceFound?.Invoke(found);
                }
            }
            catch (OperationCanceledException) { }
            catch (SocketException) { }
            finally
            {
                WSDiscovery_Scan_Finished?.Invoke(ScanStatus.finished);
            }
        }

        /// <summary>
        /// The probe. Deliberately <b>without</b> a <c>Types</c> element, so that it addresses
        /// every device. A type filter is what the camera search uses, and here it would exclude
        /// the computers and printers this scan looks for.
        /// </summary>
        private static string BuildProbe(string discoveryNamespace)
        {
            string addressing = discoveryNamespace == Discovery2009 ? Addressing2005 : Addressing2004;
            string action = $"{discoveryNamespace}/Probe";

            return $"""
                <?xml version="1.0" encoding="UTF-8"?>
                <e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
                            xmlns:w="{addressing}"
                            xmlns:d="{discoveryNamespace}">
                  <e:Header>
                    <w:MessageID>urn:uuid:{Guid.NewGuid()}</w:MessageID>
                    <w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
                    <w:Action e:mustUnderstand="true">{action}</w:Action>
                  </e:Header>
                  <e:Body>
                    <d:Probe/>
                  </e:Body>
                </e:Envelope>
                """;
        }

        /// <summary>
        /// Reads from the answer what kind of device it is.
        /// <para>
        /// Evaluated are <c>Types</c>, which holds the device class, and <c>XAddrs</c>, the address
        /// of the management interface. The friendly name is <em>not</em> in the answer; it would
        /// take a second request to the XAddrs address. The main finding is a different one anyway:
        /// that the address answered at all.
        /// </para>
        /// </summary>
        private static WsDiscoveryResult Parse(string soap, string address)
        {
            try
            {
                XDocument document = XDocument.Parse(soap);

                // Search without namespace: answers of both versions arrive, and the element names
                // are the same in both.
                string? types = FindValue(document, "Types");
                string? xaddrs = FindValue(document, "XAddrs");
                string? scopes = FindValue(document, "Scopes");

                return new WsDiscoveryResult
                {
                    Address = address,
                    Kind = DescribeTypes(types),
                    Info = BuildInfoText(types, xaddrs, scopes)
                };
            }
            catch (Exception)
            {
                // An unreadable answer is still an answer: the address is alive, and that is the
                // finding.
                return new WsDiscoveryResult
                {
                    Address = address,
                    Info = "Replied, but the response could not be read."
                };
            }
        }

        private static string? FindValue(XDocument document, string localName) =>
            document.Descendants()
                .FirstOrDefault(e => string.Equals(e.Name.LocalName, localName, StringComparison.OrdinalIgnoreCase))
                ?.Value?.Trim();

        /// <summary>
        /// Builds the lines shown in the detail view. The device class is translated separately
        /// (<see cref="DescribeTypes"/>): <c>pub:Computer</c> means something to a network
        /// specialist, but not to everyone else.
        /// </summary>
        private static string BuildInfoText(string? types, string? xaddrs, string? scopes)
        {
            List<string> lines = [];

            if (!string.IsNullOrWhiteSpace(types)) lines.Add($"Types: {types}");
            if (!string.IsNullOrWhiteSpace(xaddrs)) lines.Add($"Address: {xaddrs}");

            // On Windows computers the scopes often contain the domain or workgroup name.
            if (!string.IsNullOrWhiteSpace(scopes)) lines.Add($"Scopes: {scopes}");

            return lines.Count > 0 ? string.Join(Environment.NewLine, lines) : "Replied.";
        }

        /// <summary>
        /// Translates the types into plain text. The prefixes are freely chosen, so the check is
        /// on the local name, not on the whole string.
        /// </summary>
        private static string? DescribeTypes(string? types)
        {
            if (string.IsNullOrWhiteSpace(types)) return null;

            List<string> kinds = [];

            if (types.Contains("PrintDeviceType", StringComparison.OrdinalIgnoreCase) ||
                types.Contains("Print", StringComparison.OrdinalIgnoreCase))
            {
                kinds.Add("printer");
            }

            if (types.Contains("ScanDeviceType", StringComparison.OrdinalIgnoreCase))
            {
                kinds.Add("scanner");
            }

            if (types.Contains("Computer", StringComparison.OrdinalIgnoreCase))
            {
                kinds.Add("Windows computer");
            }

            if (types.Contains("NetworkVideoTransmitter", StringComparison.OrdinalIgnoreCase))
            {
                kinds.Add("camera");
            }

            return kinds.Count > 0 ? string.Join(", ", kinds) : null;
        }
    }

    /// <summary>
    /// What a WS-Discovery answer reveals about its sender.
    /// <para>
    /// Deliberately a separate type instead of further fields on <see cref="IPToScan"/>: that
    /// structure already carries about forty fields, of which each method fills three. A new
    /// method does not need to extend it further.
    /// </para>
    /// </summary>
    public sealed class WsDiscoveryResult
    {
        /// <summary>The address the answer came from.</summary>
        public required string Address { get; init; }

        /// <summary>
        /// The device class in plain text, such as "Windows computer" or "printer", or
        /// <c>null</c> if the types contained nothing known.
        /// </summary>
        public string? Kind { get; init; }

        /// <summary>The complete information for the detail view.</summary>
        public string Info { get; init; } = string.Empty;
    }
}
