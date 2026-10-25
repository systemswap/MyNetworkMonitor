// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Buffers.Binary;
using System.Text;

namespace MyNetworkMonitor.Core.Network
{
    /// <summary>One entry of the name table of a NetBIOS node status response.</summary>
    /// <param name="Name">The name without trailing padding.</param>
    /// <param name="Suffix">The 16th byte of the NetBIOS name (service type, e.g. 0x00 workstation, 0x20 file server, 0x1E browser).</param>
    /// <param name="IsGroup">Whether the name is a group name (G bit of NAME_FLAGS) rather than a unique name.</param>
    public readonly record struct NetBiosName(string Name, byte Suffix, bool IsGroup);

    /// <summary>The evaluated node status response of one host.</summary>
    /// <param name="Names">The name table in the order of the response.</param>
    /// <param name="UnitId">The unit ID from the statistics (usually the MAC address, "AA-BB-CC-DD-EE-FF"); empty if missing.</param>
    public sealed record NetBiosNodeStatusResult(IReadOnlyList<NetBiosName> Names, string UnitId)
    {
        /// <summary>
        /// The host name: the first unique name with suffix 0x20 (file server), otherwise the first unique name with suffix 0x00
        /// (workstation); null if there is none. Group names are never taken: the workgroup carries the same suffix 0x00 as the
        /// workstation and would otherwise win whenever it comes first in the list.
        /// </summary>
        public string? HostName =>
            Names.FirstOrDefault(n => !n.IsGroup && n.Suffix == 0x20 && n.Name.Length > 0).Name
            ?? Names.FirstOrDefault(n => !n.IsGroup && n.Suffix == 0x00 && n.Name.Length > 0).Name;

        /// <summary>The workgroup or domain: the first group name with suffix 0x00, otherwise with suffix 0x1E; null if there is none.</summary>
        public string? Workgroup =>
            Names.FirstOrDefault(n => n.IsGroup && n.Suffix == 0x00 && n.Name.Length > 0).Name
            ?? Names.FirstOrDefault(n => n.IsGroup && n.Suffix == 0x1E && n.Name.Length > 0).Name;
    }

    /// <summary>
    /// NetBIOS node status query (NBSTAT) over UDP port 137: builds the request for the wildcard name "*" and evaluates the
    /// response, after RFC 1002, sections 4.2.17 (NODE STATUS REQUEST) and 4.2.18 (NODE STATUS RESPONSE), with the name
    /// encoding of RFC 1001, section 14.1.
    /// </summary>
    /// <remarks>
    /// Pure functions without network access; every length and offset of the response is checked against the data.
    /// See docs/FEHLERGEDAECHTNIS.md, No. 15.
    /// </remarks>
    public static class NetBiosNodeStatus
    {
        /// <summary>UDP port of the NetBIOS name service.</summary>
        public const int Port = 137;

        private const ushort TypeNbstat = 0x0021;
        private const ushort ClassIn = 0x0001;
        private const int HeaderLength = 12;
        private const int NameEntryLength = 18;   // 15 bytes name, 1 byte suffix, 2 bytes NAME_FLAGS

        /// <summary>Builds a node status request for the wildcard name "*".</summary>
        /// <param name="transactionId">NAME_TRN_ID; the response carries the same value.</param>
        /// <returns>The 50-byte request.</returns>
        public static byte[] BuildRequest(ushort transactionId)
        {
            byte[] packet = new byte[HeaderLength + 34 + 4];
            BinaryPrimitives.WriteUInt16BigEndian(packet, transactionId);
            // Flags 0 (query, opcode 0, no recursion), QDCOUNT 1, ANCOUNT, NSCOUNT, ARCOUNT 0
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4), 1);
            // QUESTION_NAME: "*" padded with 15 zero bytes, each half byte encoded as 'A' + value (RFC 1001, 14.1)
            packet[HeaderLength] = 32;
            Span<byte> name = stackalloc byte[16];
            name.Clear();
            name[0] = (byte)'*';
            for (int i = 0; i < 16; i++)
            {
                packet[HeaderLength + 1 + 2 * i] = (byte)('A' + (name[i] >> 4));
                packet[HeaderLength + 2 + 2 * i] = (byte)('A' + (name[i] & 0x0F));
            }
            packet[HeaderLength + 33] = 0;   // end of the name (empty scope)
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(HeaderLength + 34), TypeNbstat);
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(HeaderLength + 36), ClassIn);
            return packet;
        }

        /// <summary>Evaluates a node status response.</summary>
        /// <param name="response">The received datagram.</param>
        /// <param name="transactionId">NAME_TRN_ID of the request.</param>
        /// <returns>The name table and unit ID, or null if the data is not a node status response to this request.</returns>
        public static NetBiosNodeStatusResult? Parse(ReadOnlySpan<byte> response, ushort transactionId)
        {
            if (response.Length < HeaderLength) return null;
            if (BinaryPrimitives.ReadUInt16BigEndian(response) != transactionId) return null;
            ushort flags = BinaryPrimitives.ReadUInt16BigEndian(response[2..]);
            if ((flags & 0x8000) == 0) return null;                      // R bit: must be a response
            if ((flags & 0x000F) != 0) return null;                      // RCODE: error
            if (BinaryPrimitives.ReadUInt16BigEndian(response[6..]) == 0) return null;   // ANCOUNT

            int at = SkipName(response, HeaderLength);
            if (at < 0 || at + 10 > response.Length) return null;
            ushort type = BinaryPrimitives.ReadUInt16BigEndian(response[at..]);
            ushort rrClass = BinaryPrimitives.ReadUInt16BigEndian(response[(at + 2)..]);
            int dataLength = BinaryPrimitives.ReadUInt16BigEndian(response[(at + 8)..]);
            at += 10;
            if (type != TypeNbstat || rrClass != ClassIn || dataLength < 1) return null;

            // A response cut off inside the data part still yields the complete names it contains
            ReadOnlySpan<byte> rdata = response.Slice(at, Math.Min(dataLength, response.Length - at));
            if (rdata.IsEmpty) return null;
            int count = rdata[0];
            List<NetBiosName> names = new(count);
            int offset = 1;
            for (int i = 0; i < count && offset + NameEntryLength <= rdata.Length; i++, offset += NameEntryLength)
            {
                string name = Encoding.ASCII.GetString(rdata.Slice(offset, 15)).TrimEnd(' ', '\0').Trim();
                byte suffix = rdata[offset + 15];
                bool isGroup = (rdata[offset + 16] & 0x80) != 0;
                names.Add(new NetBiosName(name, suffix, isGroup));
            }

            // STATISTICS start with the 6-byte UNIT_ID
            string unitId = offset + 6 <= rdata.Length ? BitConverter.ToString(rdata.Slice(offset, 6).ToArray()) : string.Empty;
            return new NetBiosNodeStatusResult(names, unitId);
        }

        /// <summary>Skips an encoded name (labels or a compression pointer) and returns the offset after it, or -1 if it is damaged.</summary>
        private static int SkipName(ReadOnlySpan<byte> data, int at)
        {
            for (int labels = 0; labels < 64; labels++)
            {
                if (at >= data.Length) return -1;
                byte length = data[at];
                if (length == 0) return at + 1;
                if ((length & 0xC0) == 0xC0) return at + 2 <= data.Length ? at + 2 : -1;   // pointer ends the name
                if ((length & 0xC0) != 0) return -1;
                at += 1 + length;
            }
            return -1;
        }
    }
}
