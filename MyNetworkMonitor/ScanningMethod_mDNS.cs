using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace MyNetworkMonitor
{
    public class MdnsDeviceInfo
    {
        public string Service { get; set; }
        public string DeviceName { get; set; }
        //public string Hostname { get; set; }
        public string TargetHost { get; set; } 
        public string IP { get; set; }
        //public int? Port { get; set; }
        public string Group { get; set; }
        public Dictionary<string, string> TxtRecords { get; set; } = new();

        public double LastResponse { get; set; }

        public string AsMultilineString()
        {
            var sb = new StringBuilder();
            sb.AppendLine($"ResponseTime: {Math.Round(LastResponse)}ms");
            sb.AppendLine($"Dienst: {Service}");
            sb.AppendLine($"Device: {DeviceName}");
            //sb.AppendLine($"Hostname: {Hostname}");
            sb.AppendLine($"TargetHost: {TargetHost}");
            sb.AppendLine($"IP: {IP}");
            //sb.AppendLine($"Port: {Port}");
            sb.AppendLine($"Group: {Group}");
            foreach (var kv in TxtRecords)
                sb.AppendLine($"TXT: {kv.Key} = {kv.Value}");
            return sb.ToString().Trim();
        }
    }



    public class ScanningMethod_mDNS
    {

        public event Action<IPToScan> found_mDNS_Device;

        public event Action<ScanStatus> mDNS_ScanStatus;
        public event Action<int, int, int, ScanStatus> ProgressUpdated;

  
        private int responded = 0;

        DateTime startTime;

        private const int MdnsPort = 5353;
        private const string MdnsMulticast = "224.0.0.251";
        private readonly Dictionary<string, MdnsDeviceInfo> foundDevices = new();


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
                            return unicast.Address; // IPv4-Adresse
                        }
                    }
                }
            }

            throw new Exception($"Keine IPv4-Adresse für Interface '{interfaceName}' gefunden.");
        }


        public List<string> ListOf_mDNS_ServiceQueryStrings()
        {
            return new List<string>
            {
                "_services._dns-sd._udp.local",   // Root – listet verfügbare Dienste

                "_http._tcp.local",               // Webserver
                "_smb._tcp.local",                // Windows/SMB Dateifreigabe
                "_ftp._tcp.local",                // FTP-Server
                "_afpovertcp._tcp.local",         // Apple File Sharing (AFP)
                "_nfs._tcp.local",                // NFS-Freigaben

                "_workstation._tcp.local",        // Geräte-Hostname-Infos
                "_ssh._tcp.local",                // SSH-fähige Geräte
                "_telnet._tcp.local",             // Telnet-fähige Geräte
                "_rdp._tcp.local",                // Windows Remote Desktop

                "_airplay._tcp.local",            // Apple AirPlay
                "_raop._tcp.local",               // AirPlay Audio (RAOP)

                "_ipp._tcp.local",                // IP Printing (AirPrint)
                "_ipps._tcp.local",               // IP Printing (secure)
                "_printer._tcp.local",            // Allgemeine Drucker

                "_hap._tcp.local",                // HomeKit Accessory
                "_homekit._tcp.local",            // Alternative HomeKit
                "_googlecast._tcp.local",         // Chromecast

                "_mqtt._tcp.local",               // MQTT Broker
                "_xbmc-jsonrpc-h._tcp.local",     // Kodi Media Center

                "_esphomelib._tcp.local",         // ESPHome IoT Geräte
                "_ewelink._tcp.local",            // eWeLink Smart Devices
                "_ewelink-wifi-smart-switch._tcp.local", // Sonoff etc.

                "_mediaremotetv._tcp.local",      // Apple TV Remote
                "_vnc._tcp.local",                // VNC-Zugriff
                "_vlc-http._tcp.local",           // VLC Media Server
                "_mieleathome._dns-sd._udp.loca",
            };
        }


        //public async Task<List<MdnsDeviceInfo>> DiscoverAsync(string NetworkInterfaceName, int listenTimeMs = 30000)
        //{
        //    startTime = DateTime.UtcNow;

        //    mDNS_ScanStatus?.Invoke(ScanStatus.running);

        //    responded = 0;


        //    string selectedInterfaceName = NetworkInterfaceName; // z. B. aus deinem Dropdown
        //    IPAddress localIp = GetIPAddressFromInterfaceName(selectedInterfaceName);


        //    using var udp = new UdpClient(AddressFamily.InterNetwork);
        //    udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        //    udp.ExclusiveAddressUse = false;
        //    udp.Client.Bind(new IPEndPoint(localIp, MdnsPort));
        //    udp.JoinMulticastGroup(IPAddress.Parse(MdnsMulticast), localIp);

        //    // Aktive Anfrage senden
        //    //byte[] query = CreateQuery("_services._dns-sd._udp.local");

        //    foreach (var query in ListOf_mDNS_ServiceQueryStrings())
        //    {
        //        byte[] byte_query = CreateQuery(query);

        //        try
        //        {
        //            await udp.SendAsync(byte_query, byte_query.Length, new IPEndPoint(IPAddress.Parse(MdnsMulticast), MdnsPort));
        //        }
        //        catch (Exception ex)
        //        {
        //            Debug.WriteLine("Fehler beim Senden der mDNS-Anfrage: " + ex.Message);
        //            //throw; // Optional, oder Logging
        //        }
        //        await Task.Delay(100);
        //    }           



        //    // Timer initialisieren, der jede Sekunde das Event auslöst
        //    Timer progressTimer = null;
        //    int remainingTime = listenTimeMs;

        //    progressTimer = new Timer(_ =>
        //    {
        //        // Der verbleibende Timer-Wert wird jede Sekunde heruntergezählt
        //        remainingTime = (int)Math.Floor(((listenTimeMs - (DateTime.UtcNow - startTime).TotalMilliseconds) / 1000));


        //        // Wenn die verbleibende Zeit noch größer als 0 ist, dann das Event mit dem Fortschritt aufrufen
        //        if (remainingTime >= 0)
        //        {
        //            ProgressUpdated?.Invoke(remainingTime, foundDevices.Count, 0, ScanStatus.running);
        //        }
        //        else
        //        {
        //            // Timer stoppen, wenn die Zeit abgelaufen ist
        //            progressTimer?.Change(Timeout.Infinite, Timeout.Infinite);
        //        }
        //    }, null, 0, 1000); // Intervall: 1000 ms = 1 Sekunde





        //    var end = DateTime.UtcNow.AddMilliseconds(listenTimeMs);
        //    while (DateTime.UtcNow < end)
        //    {
        //        if (udp.Available > 0)
        //        {
        //            var result = await udp.ReceiveAsync();
        //            ParseResponse(result.Buffer, result.RemoteEndPoint.Address.ToString(), startTime);

        //            ProgressUpdated?.Invoke(remainingTime, foundDevices.Count, 0, ScanStatus.running);
        //        }
        //        //else
        //        //{
        //        //    await Task.Delay(10);
        //        //}
        //    }


        //    // Timer stoppen, wenn der Scan abgeschlossen ist
        //    progressTimer?.Change(Timeout.Infinite, Timeout.Infinite);

        //    foreach (var device in foundDevices.Values)
        //    {
        //        IPToScan ipToScan = new IPToScan();
        //        ipToScan.UsedScanMethod = ScanMethod.mDNS;
        //        ipToScan.IPorHostname = device.IP;
        //        //ipToScan.mDNS_Hostname = device.Hostname;
        //        ipToScan.mDNS_Service = device.Service;
        //        ipToScan.mDNS_Group = device.Group;
        //        ipToScan.mDNS_DeviceName = device.DeviceName;
        //        //ipToScan.mDNS_Port = device.Port;
        //        ipToScan.mDNS_TxtRecords = device.TxtRecords;
        //        ipToScan.mDNS_toMultiLineString = device.AsMultilineString();

        //        found_mDNS_Device?.Invoke(ipToScan);
        //    }

        //    mDNS_ScanStatus?.Invoke(ScanStatus.finished);

        //    return new List<MdnsDeviceInfo>(foundDevices.Values);
        //}



        public async Task<List<MdnsDeviceInfo>> DiscoverAsync(string NetworkInterfaceName, int listenTimeMs = 30000)
        {
            startTime = DateTime.UtcNow;

            mDNS_ScanStatus?.Invoke(ScanStatus.running);
            responded = 0;

            string selectedInterfaceName = NetworkInterfaceName; // z. B. aus deinem Dropdown
            IPAddress localIp = GetIPAddressFromInterfaceName(selectedInterfaceName);

            using var udp = new UdpClient(AddressFamily.InterNetwork);
            udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            udp.ExclusiveAddressUse = false;
            udp.Client.Bind(new IPEndPoint(localIp, MdnsPort));
            udp.JoinMulticastGroup(IPAddress.Parse(MdnsMulticast), localIp);

            // Timer initialisieren, der jede Sekunde das Event auslöst
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
            }, null, 0, 1000); // Intervall: 1000 ms = 1 Sekunde

            // Start receiving before sending requests
            var end = DateTime.UtcNow.AddMilliseconds(listenTimeMs);
            var receiveTask = Task.Run(async () =>
            {
                while (DateTime.UtcNow < end)
                {
                    if (udp.Available > 0)
                    {
                        var result = await udp.ReceiveAsync();
                        ParseResponse(result.Buffer, result.RemoteEndPoint.Address.ToString(), startTime);
                        ProgressUpdated?.Invoke(remainingTime, foundDevices.Count, 0, ScanStatus.running);
                    }
                    //await Task.Delay(10);  // Non-blocking delay to allow for periodic response checks
                }
            });

            // Send queries one by one and wait for responses
            foreach (var query in ListOf_mDNS_ServiceQueryStrings())
            {
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

                await Task.Delay(100);  // Optional: Slight delay to avoid flooding the network
            }

            // Wait until the receiving task completes
            await receiveTask;

            // Timer stoppen, wenn der Scan abgeschlossen ist
            progressTimer?.Change(Timeout.Infinite, Timeout.Infinite);

            // Process the found devices and invoke the callback
            foreach (var device in foundDevices.Values)
            {
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

            mDNS_ScanStatus?.Invoke(ScanStatus.finished);
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

                            // Extrahiere den "group" aus TXT-Records
                            if (info.TxtRecords.TryGetValue("group", out var group))
                                info.Group = group;

                            // Extrahiere den Gerätenamen, falls vorhanden
                            if (info.TxtRecords.TryGetValue("name", out var deviceName))
                                info.DeviceName = deviceName;

                            break;
                        }

                    case 0x000C: // PTR record
                        {
                            var ptrName = ReadName(data, ref ptr);
                            info.Service = name;
                            info.DeviceName ??= ptrName;

                            // Extrahiere den ersten Teil des PTR-Namens als Zielhost
                            if (!string.IsNullOrEmpty(ptrName))
                            {
                                int dotIndex = ptrName.IndexOf('.');
                                if (dotIndex > 0)
                                {
                                    string targetHostCandidate = ptrName.Substring(0, dotIndex);

                                    // Wenn der TargetHost noch nicht gesetzt ist oder der Name nicht mit _ beginnt, dann setze ihn
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

                if ((len & 0xC0) == 0xC0) // DNS Pointer Compression
                {
                    if (!jumped)
                        original = offset + 1;

                    jumped = true;
                    offset = ((len & 0x3F) << 8) | data[offset];
                    if (++jumps > 5) break;  // Verhindere zu tiefe Rekursion bei fehlerhafter Kompression
                    continue;
                }

                if (offset + len > data.Length) break;
                if (sb.Length > 0) sb.Append('.');
                sb.Append(Encoding.UTF8.GetString(data, offset, len));
                offset += len;
            }

            // Wenn der Name komprimiert wurde, gehe zurück zum ursprünglichen Offset
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
