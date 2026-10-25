// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    /// <summary>
    /// What the mDNS answers of one device reported.
    /// </summary>
    public class MdnsDeviceInfo
    {
        /// <summary>The service name of the last PTR record.</summary>
        public string Service { get; set; }

        /// <summary>The device name from the TXT record "name", otherwise the PTR target.</summary>
        public string DeviceName { get; set; }

        /// <summary>The first label of the PTR target, unless it starts with an underscore.</summary>
        public string TargetHost { get; set; } 

        /// <summary>The IPv4 address of the device.</summary>
        public string IP { get; set; }

        /// <summary>The value of the TXT record "group", if present.</summary>
        public string Group { get; set; }

        /// <summary>All TXT records as key and value.</summary>
        public Dictionary<string, string> TxtRecords { get; set; } = new();

        /// <summary>Milliseconds from the start of the scan to the last answer of the device.</summary>
        public double LastResponse { get; set; }

        /// <summary>
        /// Formats the information as lines of label and value, separated by a tab, as for
        /// SNMPInfos and the detected services. The result table shows such values aligned in
        /// columns instead of as running text.
        /// </summary>
        /// <returns>The information as multi-line text.</returns>
        public string AsMultilineString()
        {
            var sb = new StringBuilder();
            sb.AppendLine($"ResponseTime:\t{Math.Round(LastResponse)}ms");
            sb.AppendLine($"Dienst:\t{Service}");
            sb.AppendLine($"Device:\t{DeviceName}");
            sb.AppendLine($"TargetHost:\t{TargetHost}");
            sb.AppendLine($"IP:\t{IP}");
            sb.AppendLine($"Group:\t{Group}");

            // The TXT key belongs to the label so that all values are in the same second column.
            foreach (var kv in TxtRecords)
                sb.AppendLine($"TXT {kv.Key}:\t{kv.Value}");

            return sb.ToString().Trim();
        }
    }



    /// <summary>
    /// Finds devices by mDNS / DNS-SD (RFC 6762, RFC 6763): sends PTR queries for common services to
    /// the multicast group and evaluates the answers.
    /// </summary>
    public class ScanningMethod_mDNS
    {

        /// <summary>Raised for every answer of a device, already during the listening window.</summary>
        public event Action<IPToScan> found_mDNS_Device;

        /// <summary>Raised when the scan starts and finishes.</summary>
        public event Action<ScanStatus> mDNS_ScanStatus;

        /// <summary>Reports progress as (remaining seconds, devices found, 0, status).</summary>
        public event Action<int, int, int, ScanStatus> ProgressUpdated;

  
        private int responded = 0;

        DateTime startTime;

        private const int MdnsPort = 5353;
        private const string MdnsMulticast = "224.0.0.251";
        private readonly Dictionary<string, MdnsDeviceInfo> foundDevices = new();


        /// <summary>
        /// Returns the first IPv4 address of a network interface.
        /// </summary>
        /// <param name="interfaceName">The name or description of the interface.</param>
        /// <returns>The first IPv4 unicast address of the interface.</returns>
        /// <exception cref="Exception">The interface does not exist or has no IPv4 address.</exception>
        public IPAddress GetIPAddressFromInterfaceName(string interfaceName)
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces();

            foreach (var ni in interfaces)
            {
                if (ni.Name == interfaceName || ni.Description == interfaceName)
                {
                    var ipProps = ni.GetIPProperties();

                    foreach (var unicast in ipProps.UnicastAddresses)
                    {
                        if (unicast.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            return unicast.Address;
                        }
                    }
                }
            }

            throw new Exception($"Keine IPv4-Adresse für Interface '{interfaceName}' gefunden.");
        }


        /// <summary>
        /// The service names queried by the scan.
        /// </summary>
        /// <returns>The DNS-SD service names, starting with the service enumeration (RFC 6763, section 9).</returns>
        public List<string> ListOf_mDNS_ServiceQueryStrings()
        {
            return new List<string>
            {
                "_services._dns-sd._udp.local",   // Service enumeration: lists available services

                "_http._tcp.local",               // Web server
                "_smb._tcp.local",                // SMB file sharing
                "_ftp._tcp.local",                // FTP server
                "_afpovertcp._tcp.local",         // Apple File Sharing (AFP)
                "_nfs._tcp.local",                // NFS shares

                "_workstation._tcp.local",        // Device host name information
                "_ssh._tcp.local",                // SSH-capable devices
                "_telnet._tcp.local",             // Telnet-capable devices
                "_rdp._tcp.local",                // Windows Remote Desktop

                "_airplay._tcp.local",            // Apple AirPlay
                "_raop._tcp.local",               // AirPlay Audio (RAOP)

                "_ipp._tcp.local",                // IP Printing (AirPrint)
                "_ipps._tcp.local",               // IP Printing (secure)
                "_printer._tcp.local",            // Generic printers

                "_hap._tcp.local",                // HomeKit Accessory
                "_homekit._tcp.local",            // HomeKit (alternative name)
                "_googlecast._tcp.local",         // Chromecast

                "_mqtt._tcp.local",               // MQTT Broker
                "_xbmc-jsonrpc-h._tcp.local",     // Kodi Media Center

                "_esphomelib._tcp.local",         // ESPHome IoT devices
                "_ewelink._tcp.local",            // eWeLink Smart Devices
                "_ewelink-wifi-smart-switch._tcp.local", // Sonoff etc.

                "_mediaremotetv._tcp.local",      // Apple TV Remote
                "_vnc._tcp.local",                // VNC access
                "_vlc-http._tcp.local",           // VLC Media Server
                "_mieleathome._dns-sd._udp.local",
            };
        }



        /// <summary>
        /// Sends the service queries on one interface and listens for answers for the given time.
        /// Devices are reported through <see cref="found_mDNS_Device"/> as soon as they answer.
        /// </summary>
        /// <param name="NetworkInterfaceName">The name or description of the interface that joins the multicast group.</param>
        /// <param name="listenTimeMs">The listening window in milliseconds.</param>
        /// <param name="cancellationToken">Cancels the scan.</param>
        /// <returns>All devices that answered.</returns>
        /// <exception cref="OperationCanceledException"><paramref name="cancellationToken"/> was cancelled.</exception>
        public async Task<List<MdnsDeviceInfo>> DiscoverAsync(
            string NetworkInterfaceName, int listenTimeMs = 30000, CancellationToken cancellationToken = default)
        {
            startTime = DateTime.UtcNow;

            mDNS_ScanStatus?.Invoke(ScanStatus.running);
            responded = 0;

            string selectedInterfaceName = NetworkInterfaceName;
            IPAddress localIp = GetIPAddressFromInterfaceName(selectedInterfaceName);

            using var udp = new UdpClient(AddressFamily.InterNetwork);
            udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            udp.ExclusiveAddressUse = false;

            // Binds to IPAddress.Any, not to localIp: on Linux a socket bound to a specific unicast
            // address receives no multicast packets. They are addressed to 224.0.0.251, not to the
            // local address, and the kernel does not deliver them. With the same query, a socket
            // bound to IPAddress.Any received 16 answers, one bound to the local address none.
            // JoinMulticastGroup with localIp selects the interface that joins the group; that is
            // the right place for it, not the bind. See docs/FEHLERGEDAECHTNIS.md, No. 5.
            udp.Client.Bind(new IPEndPoint(IPAddress.Any, MdnsPort));
            udp.JoinMulticastGroup(IPAddress.Parse(MdnsMulticast), localIp);

            using CancellationTokenSource windowCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            windowCts.CancelAfter(listenTimeMs);

            // Timer that reports the remaining time every second.
            Timer progressTimer = null;
            int remainingTime = listenTimeMs;

            progressTimer = new Timer(_ =>
            {
                remainingTime = (int)Math.Floor(((listenTimeMs - (DateTime.UtcNow - startTime).TotalMilliseconds) / 1000));
                if (remainingTime >= 0)
                {
                    ProgressUpdated?.Invoke(remainingTime, foundDevices.Count, 0, ScanStatus.running);
                }
                else
                {
                    progressTimer?.Change(Timeout.Infinite, Timeout.Infinite);
                }
            }, null, 0, 1000); // Interval: 1000 ms

            void ReportDevice(string ip)
            {
                if (!foundDevices.TryGetValue(ip, out MdnsDeviceInfo device)) return;

                IPToScan ipToScan = new IPToScan
                {
                    UsedScanMethod = ScanMethod.mDNS,
                    IPorHostname = device.IP,
                    mDNS_Service = device.Service,
                    mDNS_Group = device.Group,
                    mDNS_DeviceName = device.DeviceName,
                    mDNS_TxtRecords = device.TxtRecords,
                    mDNS_toMultiLineString = device.AsMultilineString()
                };

                found_mDNS_Device?.Invoke(ipToScan);
            }

            // Start receiving before sending the queries. The receive loop waits asynchronously; a
            // polling loop without a delay would keep a CPU core busy while no packet is pending.
            // Each device is reported at once instead of after the full listening window.
            var receiveTask = Task.Run(async () =>
            {
                while (!windowCts.IsCancellationRequested)
                {
                    UdpReceiveResult result;

                    try
                    {
                        result = await udp.ReceiveAsync(windowCts.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (SocketException)
                    {
                        // A single dropped packet does not end the listening.
                        continue;
                    }

                    try
                    {
                        string ip = result.RemoteEndPoint.Address.ToString();
                        ParseResponse(result.Buffer, ip, startTime);
                        ReportDevice(ip);
                    }
                    catch (Exception ex)
                    {
                        // A broken or unexpected packet must not end the listening silently; an
                        // unhandled exception in the parser (such as an IndexOutOfRangeException in
                        // ReadName) would stop the loop without mDNS_ScanStatus ever reporting
                        // "finished".
                        Debug.WriteLine("Fehler beim Auswerten einer mDNS-Antwort: " + ex.Message);
                    }

                    ProgressUpdated?.Invoke(remainingTime, foundDevices.Count, 0, ScanStatus.running);
                }
            }, cancellationToken);

            // Send queries one by one and wait for responses
            foreach (var query in ListOf_mDNS_ServiceQueryStrings())
            {
                if (windowCts.IsCancellationRequested) break;

                byte[] byte_query = CreateQuery(query);

                try
                {
                    // Send query and wait for the task to continue after response
                    await udp.SendAsync(byte_query, byte_query.Length, new IPEndPoint(IPAddress.Parse(MdnsMulticast), MdnsPort));
                }
                catch (Exception ex)
                {
                    Debug.WriteLine("Fehler beim Senden der mDNS-Anfrage: " + ex.Message);
                }

                try
                {
                    await Task.Delay(100, windowCts.Token);  // Short delay to avoid flooding the network
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }

            // Wait until the receiving task completes
            await receiveTask;

            // Stop the timer once the scan is complete.
            progressTimer?.Change(Timeout.Infinite, Timeout.Infinite);

            // The devices have already been reported during the run (see ReportDevice above);
            // only the result is returned here.
            mDNS_ScanStatus?.Invoke(ScanStatus.finished);

            cancellationToken.ThrowIfCancellationRequested();

            return new List<MdnsDeviceInfo>(foundDevices.Values);
        }







        private void ParseResponse(byte[] data, string ip, DateTime startTime)
        {
            var info = GetOrCreate(ip);
            info.LastResponse = (DateTime.UtcNow - startTime).TotalMilliseconds;

            int ptr = 12; // Skip DNS header
            if (data.Length < ptr) return;

            while (ptr < data.Length)
            {
                var name = ReadName(data, ref ptr);
                if (ptr + 10 > data.Length) break;

                var type = (data[ptr] << 8) | data[ptr + 1];
                var dataClass = (data[ptr + 2] << 8) | data[ptr + 3];
                var ttl = (data[ptr + 4] << 24) | (data[ptr + 5] << 16) | (data[ptr + 6] << 8) | data[ptr + 7];
                var dataLen = (data[ptr + 8] << 8) | data[ptr + 9];
                ptr += 10;

                if (ptr + dataLen > data.Length) break;

                switch (type)
                {
                    case 0x0010: // TXT record
                        {
                            int end = ptr + dataLen;
                            while (ptr < end)
                            {
                                int len = data[ptr++];
                                if (ptr + len > end) break;

                                var txt = Encoding.UTF8.GetString(data, ptr, len);
                                var split = txt.Split('=', 2);
                                if (split.Length == 2)
                                    info.TxtRecords[split[0]] = split[1];

                                ptr += len;
                            }

                            // Take the "group" from the TXT records.
                            if (info.TxtRecords.TryGetValue("group", out var group))
                                info.Group = group;

                            // Take the device name, if present.
                            if (info.TxtRecords.TryGetValue("name", out var deviceName))
                                info.DeviceName = deviceName;

                            break;
                        }

                    case 0x000C: // PTR record
                        {
                            var ptrName = ReadName(data, ref ptr);
                            info.Service = name;
                            info.DeviceName ??= ptrName;

                            // Use the first label of the PTR name as the target host.
                            if (!string.IsNullOrEmpty(ptrName))
                            {
                                int dotIndex = ptrName.IndexOf('.');
                                if (dotIndex > 0)
                                {
                                    string targetHostCandidate = ptrName.Substring(0, dotIndex);

                                    // Set the target host if it is not set yet and the label does not start with "_".
                                    if (string.IsNullOrEmpty(info.TargetHost) && !targetHostCandidate.StartsWith("_"))
                                    {
                                        info.TargetHost = targetHostCandidate;
                                    }
                                }
                            }
                            break;
                        }

                    case 0x0001 when dataLen == 4: // A record (IPv4)
                        {
                            var ipAddress = new IPAddress(new byte[] { data[ptr], data[ptr + 1], data[ptr + 2], data[ptr + 3] });
                            info.IP = ipAddress.ToString();
                            ptr += 4;
                            break;
                        }

                    default:
                        ptr += dataLen;
                        break;
                }
            }
        }




        private string ReadName(byte[] data, ref int offset)
        {
            StringBuilder sb = new StringBuilder();
            int original = offset;
            bool jumped = false;
            int jumps = 0;

            while (offset < data.Length)
            {
                byte len = data[offset++];
                if (len == 0)
                    break;

                if ((len & 0xC0) == 0xC0) // DNS name compression (RFC 1035, section 4.1.4)
                {
                    // The second pointer byte can be missing in a truncated packet; read without
                    // this check it throws an IndexOutOfRangeException that aborts the whole scan.
                    if (offset >= data.Length) break;

                    if (!jumped)
                        original = offset + 1;

                    jumped = true;
                    offset = ((len & 0x3F) << 8) | data[offset];
                    if (++jumps > 5) break;  // Limits pointer chains in malformed compression
                    continue;
                }

                if (offset + len > data.Length) break;
                if (sb.Length > 0) sb.Append('.');
                sb.Append(Encoding.UTF8.GetString(data, offset, len));
                offset += len;
            }

            // If the name was compressed, continue after the first pointer.
            if (!jumped)
                return sb.ToString();
            else
            {
                offset = original;
                return sb.ToString();
            }
        }




        private MdnsDeviceInfo GetOrCreate(string ip)
        {
            if (!foundDevices.TryGetValue(ip, out var info))
            {
                info = new MdnsDeviceInfo { IP = ip };
                foundDevices[ip] = info;
            }
            return info;
        }

        

        private byte[] CreateQuery(string service)
        {
            List<byte> query = new();

            // Header
            query.AddRange(new byte[] {
                0x00, 0x00, // ID
                0x00, 0x00, // flags
                0x00, 0x01, // questions
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // other counts
            });

            foreach (var label in service.Split('.'))
            {
                query.Add((byte)label.Length);
                query.AddRange(Encoding.UTF8.GetBytes(label));
            }

            query.Add(0x00);             // null terminator
            query.AddRange(new byte[] {
                0x00, 0x0C, // Type: PTR
                0x00, 0x01  // Class: IN
            });

            return query.ToArray();
        }
    }
}
