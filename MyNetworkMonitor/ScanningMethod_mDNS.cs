using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace MdnsScanner
{
    public class MdnsDeviceInfo
    {
        public string Dienst { get; set; }
        public string DeviceName { get; set; }
        public string Hostname { get; set; }
        public string IP { get; set; }
        public int? Port { get; set; }
        public string Group { get; set; }
        public Dictionary<string, string> TxtRecords { get; set; } = new();

        public string AsMultilineString()
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Dienst: {Dienst}");
            sb.AppendLine($"Device: {DeviceName}");
            sb.AppendLine($"Hostname: {Hostname}");
            sb.AppendLine($"IP: {IP}");
            sb.AppendLine($"Port: {Port}");
            sb.AppendLine($"Group: {Group}");
            foreach (var kv in TxtRecords)
                sb.AppendLine($"TXT: {kv.Key} = {kv.Value}");
            return sb.ToString();
        }
    }

    public class ScanningMethod_mDNS
    {
        private const int MdnsPort = 5353;
        private const string MdnsMulticast = "224.0.0.251";
        private readonly Dictionary<string, MdnsDeviceInfo> foundDevices = new();

        public async Task<List<MdnsDeviceInfo>> DiscoverAsync(int listenTimeMs = 10000)
        {
            using var udp = new UdpClient(AddressFamily.InterNetwork);
            udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            udp.ExclusiveAddressUse = false;
            udp.Client.Bind(new IPEndPoint(IPAddress.Any, MdnsPort));
            udp.JoinMulticastGroup(IPAddress.Parse(MdnsMulticast));

            // Aktive Anfrage senden
            byte[] query = CreateQuery("_services._dns-sd._udp.local");
            await udp.SendAsync(query, query.Length, new IPEndPoint(IPAddress.Parse(MdnsMulticast), MdnsPort));

            var end = DateTime.UtcNow.AddMilliseconds(listenTimeMs);
            while (DateTime.UtcNow < end)
            {
                if (udp.Available > 0)
                {
                    var result = await udp.ReceiveAsync();
                    ParseResponse(result.Buffer, result.RemoteEndPoint.Address.ToString());
                }
                else
                {
                    await Task.Delay(10);
                }
            }

            return new List<MdnsDeviceInfo>(foundDevices.Values);
        }

        private void ParseResponse(byte[] data, string ip)
        {
            int ptr = 12; // skip header
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

                if (type == 0x0010) // TXT record
                {
                    var info = GetOrCreate(ip);
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

                    if (info.TxtRecords.ContainsKey("group"))
                        info.Group = info.TxtRecords["group"];
                }
                else if (type == 0x000C) // PTR record
                {
                    var ptrName = ReadName(data, ref ptr);
                    var info = GetOrCreate(ip);
                    info.Dienst = name;
                    info.DeviceName ??= ptrName;
                }
                else if (type == 0x0001 && dataLen == 4) // A record
                {
                    var ipAddress = new IPAddress(new byte[] { data[ptr], data[ptr + 1], data[ptr + 2], data[ptr + 3] });
                    var info = GetOrCreate(ip);
                    info.IP = ipAddress.ToString();
                    ptr += 4;
                }
                else
                {
                    ptr += dataLen;
                }
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

        private static string ReadName(byte[] data, ref int offset)
        {
            StringBuilder sb = new();
            int original = offset;
            bool jumped = false;
            int jumps = 0;

            while (offset < data.Length)
            {
                byte len = data[offset++];
                if (len == 0)
                    break;

                if ((len & 0xC0) == 0xC0)
                {
                    if (!jumped)
                        original = offset + 1;

                    jumped = true;
                    offset = ((len & 0x3F) << 8) | data[offset];
                    if (++jumps > 5) break;
                    continue;
                }

                if (offset + len > data.Length) break;
                if (sb.Length > 0) sb.Append('.');
                sb.Append(Encoding.UTF8.GetString(data, offset, len));
                offset += len;
            }

            if (!jumped)
                return sb.ToString();
            else
            {
                offset = original;
                return sb.ToString();
            }
        }

        private static byte[] CreateQuery(string service)
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
