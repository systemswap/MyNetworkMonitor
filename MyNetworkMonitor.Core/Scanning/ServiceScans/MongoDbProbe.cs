// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Text;
namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>MongoDB. Asks with a wire protocol request.</summary>
    public sealed class MongoDbProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.MongoDB;
        public override string Group => ServiceGroups.NoSqlDatabases;
        public override IReadOnlyList<int> DefaultPorts => [27017];

        /// <summary>
        /// OP_QUERY on <c>admin.$cmd</c> with <c>{ ismaster: 1, helloOk: true }</c>; the optional client metadata (program,
        /// driver, operating system) is left out. See docs/FEHLERGEDAECHTNIS.md, No. 14.
        /// </summary>
        public override byte[] Hello => new byte[]
            {
                0x44, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xD4, 0x07, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x61, 0x64, 0x6D, 0x69, 0x6E, 0x2E, 0x24, 0x63, 0x6D, 0x64, 0x00, 0x00,
                0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x1D, 0x00, 0x00, 0x00, 0x10, 0x69, 0x73, 0x6D, 0x61,
                0x73, 0x74, 0x65, 0x72, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x4F,
                0x6B, 0x00, 0x01, 0x00
            };

        /// <summary>Matches the reply header and the fields <c>helloOk</c> and <c>topologyVersion</c>.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;
            string str_serviceResponse = Encoding.ASCII.GetString(response);

            if (service == ServiceType.MongoDB)
            {
                // Typical MongoDB header in the answer
                byte[] bjsonHeader = { 0x49, 0x01, 0x00, 0x00 };  // start of the expected reply

                bool bjsonHeaderMatched = response.Take(4).SequenceEqual(bjsonHeader);
                bool str_ContainsHelloOK = str_serviceResponse.ToLower().Contains("hellook");
                bool str_Contains_topologyVersion = str_serviceResponse.ToLower().Contains("topologyversion");

                if (bjsonHeaderMatched && str_ContainsHelloOK && str_Contains_topologyVersion)
                {
                    serviceMatched = true;
                }
            }

            return serviceMatched;
        }

        /// <summary>
        /// Evaluates the answer to <c>isMaster</c>, the request the detection
        /// packet sends anyway and that every server answers before any login,
        /// because a client learns from it where it may write.
        /// <para>
        /// The answer contains no version number; <c>buildInfo</c> does, but
        /// may require a login depending on the configuration. What it does
        /// contain is <c>maxWireVersion</c>, the wire protocol revision, which
        /// is tied to the server release line.
        /// </para>
        /// </summary>
        protected override string? Describe(byte[] response)
        {
            List<string> lines = [];

            if (TryReadInt32Field(response, "maxWireVersion", out int wire))
            {
                string release = ReleaseOf(wire);

                lines.Add(release.Length > 0
                    ? $"Version: {release} (wire protocol {wire})"
                    : $"Wire protocol: {wire}");
            }

            // A message "isdbgrid" identifies the router in front of a sharded
            // cluster, not a server with its own data.
            string role = ReadStringField(response, "msg") == "isdbgrid"
                ? "mongos router"
                : RoleOf(response);

            if (role.Length > 0) lines.Add($"Role: {role}");

            string replicaSet = ReadStringField(response, "setName");
            if (replicaSet.Length > 0) lines.Add($"Replica set: {replicaSet}");

            // How the server names itself. Often a name unknown to DNS: the
            // internal name within the replica set.
            string me = ReadStringField(response, "me");
            if (me.Length > 0) lines.Add($"Reports itself as: {me}");

            return lines.Count > 0 ? string.Join(Environment.NewLine, lines) : null;
        }

        /// <summary>
        /// The role in the replica set. MongoDB 5.0 renamed the field from
        /// <c>ismaster</c> to <c>isWritablePrimary</c>; both are read, because
        /// servers of both kinds are in use.
        /// </summary>
        private static string RoleOf(byte[] response)
        {
            bool writable =
                ReadBoolField(response, "isWritablePrimary") == true ||
                ReadBoolField(response, "ismaster") == true;

            if (writable) return "primary";

            return ReadBoolField(response, "secondary") == true ? "secondary" : string.Empty;
        }

        /// <summary>
        /// The server release for a wire protocol revision. The mapping is
        /// defined by MongoDB and does not change retroactively: a server with
        /// revision 21 is a 7.0. Unknown here means "newer than known at build
        /// time"; then only the number is shown.
        /// </summary>
        private static string ReleaseOf(int wireVersion) => wireVersion switch
        {
            6 => "3.6",
            7 => "4.0",
            8 => "4.2",
            9 => "4.4",
            13 => "5.0",
            14 => "5.1",
            17 => "6.0",
            21 => "7.0",
            25 => "8.0",
            _ => string.Empty
        };

        /// <summary>
        /// Finds a field in the BSON answer and returns the position where its
        /// value starts, plus the type before it. BSON lists fields as
        /// <c>&lt;type&gt;&lt;name&gt;\0&lt;value&gt;</c>; the search includes the
        /// zero after the name, so that "me" does not match inside "message".
        /// </summary>
        private static bool TryFindField(byte[] data, string name, out int valueStart, out byte type)
        {
            valueStart = 0;
            type = 0;

            byte[] pattern = Encoding.ASCII.GetBytes(name + "\0");

            for (int i = 1; i <= data.Length - pattern.Length; i++)
            {
                bool match = true;

                for (int j = 0; j < pattern.Length; j++)
                {
                    if (data[i + j] != pattern[j]) { match = false; break; }
                }

                if (!match) continue;

                // The byte before the name is the type of the field.
                type = data[i - 1];
                valueStart = i + pattern.Length;

                return valueStart < data.Length;
            }

            return false;
        }

        /// <summary>A 32-bit integer field (type 0x10), little-endian.</summary>
        private static bool TryReadInt32Field(byte[] data, string name, out int value)
        {
            value = 0;

            if (!TryFindField(data, name, out int start, out byte type)) return false;
            if (type != 0x10 || start + 4 > data.Length) return false;

            value = data[start] | data[start + 1] << 8 | data[start + 2] << 16 | data[start + 3] << 24;

            return true;
        }

        /// <summary>A Boolean field (type 0x08). <c>null</c> if it is missing.</summary>
        private static bool? ReadBoolField(byte[] data, string name)
        {
            if (!TryFindField(data, name, out int start, out byte type)) return null;
            if (type != 0x08 || start >= data.Length) return null;

            return data[start] != 0;
        }

        /// <summary>
        /// A string field (type 0x02). Layout: four bytes length including the
        /// terminating zero, then the text.
        /// </summary>
        private static string ReadStringField(byte[] data, string name)
        {
            if (!TryFindField(data, name, out int start, out byte type)) return string.Empty;
            if (type != 0x02 || start + 4 > data.Length) return string.Empty;

            int length = data[start] | data[start + 1] << 8 | data[start + 2] << 16 | data[start + 3] << 24;

            // The length includes the zero; implausible values are rejected
            // instead of reading blindly into the buffer.
            if (length is < 2 or > 256) return string.Empty;
            if (start + 4 + length > data.Length) return string.Empty;

            return Printable(Encoding.UTF8.GetString(data, start + 4, length - 1), 80);
        }
    }
}
