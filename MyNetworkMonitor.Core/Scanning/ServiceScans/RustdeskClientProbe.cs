// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// RustDesk client with direct IP access. A device that answers here can
    /// be remote-controlled directly in the LAN, which is why it is kept
    /// separate from the server service.
    /// <para>
    /// The client greets as soon as the connection is established, regardless
    /// of the content of the packet sent. Only the fixed marker and the
    /// structure of the first field are checked: the numbers in between are
    /// lengths (of the protobuf body and of the device ID), and the length of
    /// an ID cannot be known from outside. Fixing them would reject every
    /// client whose ID has a different length.
    /// </para>
    /// </summary>
    public sealed class RustdeskClientProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.RustdeskClient;
        public override string Group => ServiceGroups.Remote;
        public override IReadOnlyList<int> DefaultPorts => [21118];

        /// <summary>
        /// A RustDesk client request with placeholder values; the client
        /// greets regardless of its content. The field descriptions are
        /// interpretations of the bytes.
        /// </summary>
        public override byte[] Hello => new byte[]
            {
                0x59, 0x01,                                                                 // magic number / ID
                0x3A, 0x54,                                                                 // packet length (probably 84 bytes)
                0x0A, 0x0C,                                                                 // length of the following IP address (12 bytes)
                0x31, 0x39, 0x38, 0x2E, 0x35, 0x31, 0x2E, 0x31, 0x30, 0x30, 0x2E, 0x31,     // IP address (ASCII), documentation range RFC 5737
                0x22, 0x09,                                                                 // length of the client ID (9 bytes)
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,                       // client ID (ASCII), placeholder
                0x2A, 0x06,                                                                 // length of the client key (6 bytes)
                0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x32,                                   // client key (ASCII), placeholder; 0x32 already belongs to the next field
                0x14, 0x48, 0x02,                                                           // unknown flags/settings
                0x52, 0x10,                                                                 // version string / protocol
                0x08, 0x01, 0x10, 0x01, 0x18, 0x01, 0x28, 0x01, 0x30, 0x01,                 // connection options (e.g. encryption, P2P)
                0x3A, 0x04, 0x10, 0x01, 0x18, 0x01,                                         // encryption parameters
                0x50, 0xFA, 0x8E, 0xF4, 0xBD, 0xDD, 0x8F, 0x88, 0xF0, 0x9F, 0x01,           // probably a signature or hash
                0x5A, 0x05, 0x31, 0x2E, 0x33, 0x2E, 0x37,                                   // RustDesk version "1.3.7"
                0x62, 0x00,                                                                 // unknown (possibly terminator/separator)
                0x6A, 0x07, 0x57, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73,                       // platform (Windows)
                0x08,                                                                       // packet type (possibly ACK or keep-alive)
                0x2A,                                                                       // possibly a status code or an ID
                0x00                                                                        // end of packet
            };

        /// <summary>Matches the client greeting by its fixed marker and the structure of its first field.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;

            // RustDesk client with "Direct IP Access" (port 21118)
            //
            // The client greets on its own when connected, regardless of what it
            // is sent. Cross-checked with the correct packet, with garbage and with
            // no payload at all: the answer came every time. Unlike the server
            // (which stays silent on everything except its hello), the filter here
            // is not the packet sent but this check alone; otherwise every service
            // on 21118 that greets on connect would pass as a RustDesk client.
            //
            // The layout, measured on four live clients:
            //
            //   b0 │ 4a │ 2a │ 0a 20 <32 chars> │ 12 06 <6 chars>
            //   ^    ^    ^    ^                  ^
            //   |    |    |    field 1: ID        field 2: challenge
            //   |    |    length of the protobuf body
            //   |    protobuf field 9, length-delimited  <- constant
            //   frame length, shifted left by two bits
            //
            // Only two bytes are fixed: 0x4A at offset 1 and 0x0A at offset 3.
            // Everything else is lengths or content.
            //
            // Byte 0 is the RustDesk frame: the length of the rest, shifted left
            // by two bits; the lower two bits tell how many bytes the length
            // itself occupies. Measured:
            //
            //   Client A   19 bytes   0x48 -> 18 == 19-1   ID  6 chars
            //   Client B   19 bytes   0x48 -> 18 == 19-1   ID  6 chars
            //   Client C   45 bytes   0xb0 -> 44 == 45-1   ID 32 chars
            //   Client D   45 bytes   0xb0 -> 44 == 45-1   ID 32 chars
            //
            // 0x48 is therefore not a fixed marker but 18<<2, a length: a client
            // with a longer ID sends something else there and must still match.
            // For the same reason 0x10 and 0x06 are not fixed either: they are the
            // lengths of the body and of the ID. The length of an ID cannot be
            // known from outside.
            //
            // An exact length check is also unreliable: in roughly one of eight
            // attempts the client sends three more bytes (a second frame,
            // 08 2a 00) that arrive in the same read, so the device would be
            // detected only sometimes. The check is therefore ">= frame length",
            // not equality.
            //
            // This separates the client from the server service (21115/21116/21117):
            // a device that answers like this can be remote-controlled directly
            // via its IP in the LAN.
            if (service == ServiceType.RustdeskClient)
            {
                // Only the single-byte frame is evaluated; it covers up to 63 bytes
                // of body and thus every measured ID. For a longer one the length
                // occupies several bytes; their order has not been measured and is
                // not guessed. The frame is then left out of the check, but the
                // structure below it is still checked.
                bool singleByteFrame = response.Length > 0 && (response[0] & 0x03) == 0;
                int framed = response.Length > 0 ? response[0] >> 2 : 0;

                serviceMatched = response.Length >= 6
                    && response[1] == 0x4A                          // protobuf field 9
                    && response[3] == 0x0A                          // field 1: the ID
                    && response[4] > 0                              // it is not empty
                    && response[2] >= response[4] + 2               // the body contains it
                    && response.Length >= 5 + response[4]           // ... and it is present
                    && (!singleByteFrame
                        || (response.Length >= framed + 1           // frame complete
                            && response[2] == framed - 2));         // and matches the body
            }

            return serviceMatched;
        }
    }
}
