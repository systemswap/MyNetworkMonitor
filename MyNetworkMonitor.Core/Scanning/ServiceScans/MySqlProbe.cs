// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Text;
namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// MySQL and the servers that speak the same protocol. Greets unprompted
    /// with the handshake packet; its structure is checked, and the variant is
    /// in its version text.
    /// <para>
    /// Shares port 3306 with MariaDB, and the distinction lies solely in this
    /// text: if it contains "-MariaDB" or the fake prefix "5.5.5-", the
    /// finding belongs there, otherwise here. Derivatives such as Percona or
    /// TiDB report their version without this marker and therefore end up
    /// here; the product line is right, the vendor is not implied.
    /// </para>
    /// </summary>
    public sealed class MySqlProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.MySQL;
        public override string Group => ServiceGroups.SqlDatabases;
        public override IReadOnlyList<int> DefaultPorts => [3306];

        /// <summary>Greets on its own; there is nothing to send.</summary>
        public override byte[] Hello => [];

        /// <summary>Matches a MySQL-family greeting or rejection that does not identify MariaDB.</summary>
        public override bool Identify(byte[] response)
        {
            ServiceType service = Service;
            bool serviceMatched = false;
            string str_serviceResponse = Encoding.ASCII.GetString(response);

            // MariaDB / MySQL: both greet unprompted with the same handshake
            // packet. Its structure decides whether it is one (see
            // ReadMySqlServerVersion); its version text decides which of the
            // two is running.
            //
            // Checking only a few fixed bytes is not enough: a sequence number 0
            // at offset 3 and a 10 at offset 4 also occur in other protocols, and
            // treating "no 'mariadb' anywhere in the buffer" as MySQL would count
            // answers that are no greeting at all. See docs/FEHLERGEDAECHTNIS.md, No. 2.
            if (service == ServiceType.MariaDB || service == ServiceType.MySQL)
            {
                string? serverVersion = ReadMySqlServerVersion(response);

                if (serverVersion is not null)
                {
                    // MariaDB 10.0 and later prefixes the real version with the
                    // fake "5.5.5-", so that old clients do not consider the major
                    // version too old, and appends "-MariaDB"; measured on a 10.0
                    // server: "5.5.5-10.0.20-MariaDB". No server of the MySQL line
                    // carries either; it reports its version plainly, such as
                    // "8.0.36" or "5.7.44-log".
                    bool isMariaDb =
                        serverVersion.Contains("mariadb", StringComparison.OrdinalIgnoreCase) ||
                        serverVersion.StartsWith("5.5.5-", StringComparison.Ordinal);

                    serviceMatched = service == ServiceType.MariaDB ? isMariaDb : !isMariaDb;
                }
                else if (response.Length >= 7 && response[3] == 0x00 && response[4] == 0xFF)
                {
                    // Instead of greeting, the server rejects the connection:
                    // "Host ... is not allowed to connect to this MariaDB server",
                    // "blocked because of many connection errors". That is an ERR
                    // packet (0xff) and equally proves that a server is running;
                    // which one, it states in plain text.
                    bool namesMariaDb = str_serviceResponse.Contains("mariadb", StringComparison.OrdinalIgnoreCase);
                    bool namesMySql = str_serviceResponse.Contains("mysql", StringComparison.OrdinalIgnoreCase);

                    serviceMatched = service == ServiceType.MariaDB
                        ? namesMariaDb
                        : namesMySql && !namesMariaDb;
                }
            }

            return serviceMatched;
        }

        /// <summary>
        /// The version text from the greeting, the same string by which
        /// detection decides whether MySQL or MariaDB is running.
        /// </summary>
        protected override string? Describe(byte[] response) => MySqlDetails(response);
    }
}
