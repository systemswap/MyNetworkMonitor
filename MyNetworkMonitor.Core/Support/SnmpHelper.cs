using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;

namespace MyNetworkMonitor
{
    /// <summary>
    /// Wraps SNMP access based on Lextm.SharpSnmpLib in the form the scan
    /// methods expect:
    ///  - Get/Walk return an OID-to-value map (or null on error or no answer).
    ///  - Binary OctetStrings (such as MAC addresses) are returned as a hex string
    ///    with spaces (for example "00 1a 2b 3c 4d 5e"), printable ones as text.
    /// </summary>
    public static class SnmpHelper
    {
        /// <summary>Default timeout in milliseconds.</summary>
        public const int DefaultTimeout = 2000;

        /// <summary>Checks whether the target host is a valid IP address, which is required for an endpoint.</summary>
        /// <param name="host">The target as text.</param>
        /// <param name="endpoint">The endpoint if the address is valid; otherwise <c>null</c>.</param>
        /// <param name="port">The SNMP port.</param>
        /// <returns><c>true</c> if <paramref name="host"/> is an IP address.</returns>
        public static bool TryGetEndpoint(string host, out IPEndPoint endpoint, int port = 161)
        {
            endpoint = null;
            if (string.IsNullOrWhiteSpace(host)) return false;
            if (!IPAddress.TryParse(host.Trim(), out IPAddress address)) return false;
            endpoint = new IPEndPoint(address, port);
            return true;
        }

        /// <summary>
        /// Performs an SNMP GET for one or more OIDs.
        /// </summary>
        /// <param name="host">IP address of the target.</param>
        /// <param name="version">SNMP version.</param>
        /// <param name="community">Community string; <c>null</c> uses "public".</param>
        /// <param name="oids">The OIDs to query.</param>
        /// <param name="timeout">Timeout in milliseconds.</param>
        /// <returns>An OID-to-value map, or <c>null</c> if there is no result.</returns>
        public static Dictionary<string, string> Get(string host, VersionCode version, string community,
            IEnumerable<string> oids, int timeout = DefaultTimeout)
        {
            if (!TryGetEndpoint(host, out IPEndPoint endpoint)) return null;

            try
            {
                var variables = oids.Select(o => new Variable(new ObjectIdentifier(o))).ToList();
                if (variables.Count == 0) return null;

                IList<Variable> result = Messenger.Get(version, endpoint,
                    new OctetString(community ?? "public"), variables, timeout);

                if (result == null || result.Count == 0) return null;

                var dict = new Dictionary<string, string>();
                foreach (var v in result)
                    dict[v.Id.ToString()] = DataToString(v.Data);
                return dict;
            }
            catch
            {
                // Timeout, NoSuchName (SNMPv1) and similar are treated as "no result".
                return null;
            }
        }

        /// <summary>
        /// Performs an SNMP walk over an OID subtree.
        /// </summary>
        /// <param name="host">IP address of the target.</param>
        /// <param name="version">SNMP version.</param>
        /// <param name="community">Community string; <c>null</c> uses "public".</param>
        /// <param name="tableOid">Root OID of the subtree.</param>
        /// <param name="timeout">Timeout in milliseconds.</param>
        /// <returns>An OID-to-value map, or <c>null</c> on error or no answer.</returns>
        public static Dictionary<string, string> Walk(string host, VersionCode version, string community,
            string tableOid, int timeout = DefaultTimeout)
        {
            if (!TryGetEndpoint(host, out IPEndPoint endpoint)) return null;

            try
            {
                var list = new List<Variable>();
                Messenger.Walk(version, endpoint, new OctetString(community ?? "public"),
                    new ObjectIdentifier(tableOid), list, timeout, WalkMode.WithinSubtree);

                if (list.Count == 0) return null;

                var dict = new Dictionary<string, string>();
                foreach (var v in list)
                    dict[v.Id.ToString()] = DataToString(v.Data);
                return dict;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Converts an SNMP value to a string: printable OctetStrings as text,
        /// binary ones (such as MAC addresses) as hex with spaces.
        /// </summary>
        /// <param name="data">The SNMP value.</param>
        /// <returns>The value as text; empty for <c>null</c> or an empty OctetString.</returns>
        public static string DataToString(ISnmpData data)
        {
            if (data is OctetString os)
            {
                byte[] raw = os.GetRaw();
                if (raw == null || raw.Length == 0) return string.Empty;

                bool printable = raw.All(b => b == 0x09 || b == 0x0a || b == 0x0d || (b >= 0x20 && b <= 0x7e));
                if (printable) return os.ToString();

                return string.Join(" ", raw.Select(b => b.ToString("x2")));
            }

            return data?.ToString() ?? string.Empty;
        }
    }
}
