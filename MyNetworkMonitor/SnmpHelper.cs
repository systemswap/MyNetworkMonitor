using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;

namespace MyNetworkMonitor
{
    /// <summary>
    /// Kapselt die SNMP-Zugriffe auf Basis von Lextm.SharpSnmpLib und bildet das
    /// frühere SnmpSharpNet-Verhalten nach:
    ///  - Get/Walk liefern eine geordnete OID->Wert Zuordnung (oder null bei Fehler/keine Antwort).
    ///  - Binäre OctetStrings (z.B. MAC-Adressen) werden als Hex-String mit Leerzeichen
    ///    ausgegeben (z.B. "00 1a 2b 3c 4d 5e"), druckbare als Text.
    /// </summary>
    internal static class SnmpHelper
    {
        public const int DefaultTimeout = 2000;

        /// <summary>Prüft, ob der Zielhost eine gültige IP-Adresse ist (Voraussetzung für einen Endpoint).</summary>
        public static bool TryGetEndpoint(string host, out IPEndPoint endpoint, int port = 161)
        {
            endpoint = null;
            if (string.IsNullOrWhiteSpace(host)) return false;
            if (!IPAddress.TryParse(host.Trim(), out IPAddress address)) return false;
            endpoint = new IPEndPoint(address, port);
            return true;
        }

        /// <summary>
        /// Führt einen SNMP-GET für eine oder mehrere OIDs aus.
        /// Gibt eine OID->Wert Zuordnung zurück oder null, wenn kein Ergebnis vorliegt.
        /// </summary>
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
                // Timeout, NoSuchName (SNMPv1) usw. -> wie zuvor als "kein Ergebnis" behandeln.
                return null;
            }
        }

        /// <summary>
        /// Führt einen SNMP-WALK über einen OID-Teilbaum aus.
        /// Gibt eine OID->Wert Zuordnung zurück oder null bei Fehler/keiner Antwort.
        /// </summary>
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
        /// Wandelt einen SNMP-Wert in einen String um und bildet dabei das SnmpSharpNet-Verhalten nach:
        /// druckbare OctetStrings als Text, binäre (z.B. MAC-Adressen) als Hex mit Leerzeichen.
        /// </summary>
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
