using System.Text;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// InfluxDB 2. Listens on 8086, a port that is also in the web list; both
    /// probes check it, and the answer decides which finding stands.
    /// </summary>
    public sealed class InfluxDb2Probe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.InfluxDB2;
        public override string Group => ServiceGroups.NoSqlDatabases;
        public override IReadOnlyList<int> DefaultPorts => [8086];

        /// <summary>An HTTP request for <c>/health</c>, which InfluxDB answers without login.</summary>
        public override byte[] Hello => Encoding.ASCII.GetBytes(
                "GET /health HTTP/1.1\r\nHost: influxdb\r\nConnection: close\r\n\r\n");

        /// <summary>Matches when the answer contains "influxdb", case-insensitive.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;
            string str_serviceResponse = Encoding.ASCII.GetString(response);

            if (service == ServiceType.InfluxDB2)
            {
                if (str_serviceResponse.ToLower().Contains("influxdb"))
                {
                    serviceMatched = true;
                }
            }

            return serviceMatched;
        }

        /// <summary>
        /// Reads version and status from the answer to <c>/health</c>, the
        /// status page InfluxDB provides without login for exactly this purpose.
        /// It is requested anyway; the answer carries the version both in the
        /// <c>X-Influxdb-Version</c> header and in the body.
        /// </summary>
        protected override string? Describe(byte[] response)
        {
            string text = Encoding.ASCII.GetString(response);

            List<string> lines = [];

            string version = HeaderValue(text, "X-Influxdb-Version");
            if (version.Length > 0) lines.Add($"Version: {version}");

            string build = HeaderValue(text, "X-Influxdb-Build");
            if (build.Length > 0) lines.Add($"Build: {build}");

            // The status report is JSON in the body. Read without a parser: a
            // single field is needed, which does not justify a dependency.
            string status = JsonValue(text, "status");
            if (status.Length > 0) lines.Add($"Status: {status}");

            return lines.Count > 0 ? string.Join(Environment.NewLine, lines) : null;
        }

        /// <summary>The value of an HTTP header field, or empty.</summary>
        private static string HeaderValue(string response, string name)
        {
            foreach (string raw in response.Split('\n'))
            {
                string line = raw.TrimEnd('\r');

                if (!line.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase)) continue;

                return Printable(line[(name.Length + 1)..].Trim(), 60);
            }

            return string.Empty;
        }

        /// <summary>
        /// The value of a JSON field from the body. Deliberately simple: it
        /// searches for the quoted name and takes the string after it. That
        /// does not work for nested fields, but the answer here is flat.
        /// </summary>
        private static string JsonValue(string response, string field)
        {
            int key = response.IndexOf($"\"{field}\"", StringComparison.OrdinalIgnoreCase);
            if (key < 0) return string.Empty;

            int colon = response.IndexOf(':', key);
            if (colon < 0) return string.Empty;

            int open = response.IndexOf('"', colon);
            if (open < 0) return string.Empty;

            int close = response.IndexOf('"', open + 1);
            if (close <= open) return string.Empty;

            return Printable(response[(open + 1)..close], 60);
        }
    }
}
