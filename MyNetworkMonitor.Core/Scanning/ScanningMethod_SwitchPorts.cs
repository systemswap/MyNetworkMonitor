using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using Lextm.SharpSnmpLib;

namespace MyNetworkMonitor
{
    /// <summary>
    /// Fragt einen Switch, welche MAC-Adresse an welchem seiner Ports haengt -
    /// und in welchem VLAN dieser Port liegt.
    /// <para>
    /// <b>Warum ueber SNMP und nicht ueber LLDP-Mithoeren:</b> wer LLDP-Frames
    /// am eigenen Adapter mithoert, erfaehrt genau eines - woran der eigene
    /// Rechner haengt. Zudem braucht das Raw-Sockets, also npcap unter Windows
    /// und <c>CAP_NET_RAW</c> unter Linux. Der Switch dagegen fuehrt die
    /// Zuordnung fuer <em>alle</em> seine Ports ohnehin und gibt sie ueber
    /// SNMP heraus. Das ist mehr Auskunft ohne jede Installation.
    /// </para>
    /// <para>
    /// <b>Der Weg durch die Tabellen</b> - vier Abfragen, die ineinandergreifen:
    /// die Weiterleitungstabelle (dot1dTpFdb) nennt je MAC eine Bridge-Portnummer;
    /// dot1dBasePortIfIndex uebersetzt die in einen Schnittstellenindex;
    /// ifName gibt dazu den sprechenden Namen wie "GigabitEthernet1/0/12"; und
    /// dot1qPvid nennt das VLAN des Ports. Erst die Kette ergibt einen Satz,
    /// den ein Mensch lesen kann.
    /// </para>
    /// </summary>
    public class ScanningMethod_SwitchPorts
    {
        // --- Bridge-MIB: welche MAC an welchem Bridge-Port ---------------------

        /// <summary>dot1dTpFdbPort - Wert ist die Bridge-Portnummer, der OID-Rest die MAC.</summary>
        private const string FdbPort = "1.3.6.1.2.1.17.4.3.1.2";

        /// <summary>dot1dBasePortIfIndex - Bridge-Port zu Schnittstellenindex.</summary>
        private const string BasePortIfIndex = "1.3.6.1.2.1.17.1.4.1.2";

        // --- Schnittstellennamen ----------------------------------------------

        /// <summary>ifName - der kurze Name, "Gi1/0/12".</summary>
        private const string IfName = "1.3.6.1.2.1.31.1.1.1.1";

        /// <summary>ifDescr - der lange Name, falls ifName fehlt.</summary>
        private const string IfDescr = "1.3.6.1.2.1.2.2.1.2";

        // --- VLAN --------------------------------------------------------------

        /// <summary>dot1qPvid - das VLAN, in dem ein Bridge-Port liegt.</summary>
        private const string PortVlan = "1.3.6.1.2.1.17.7.1.4.5.1.1";

        // --- Der Switch selbst -------------------------------------------------

        /// <summary>sysName - wie der Switch sich nennt.</summary>
        private const string SysName = "1.3.6.1.2.1.1.5.0";

        /// <summary>lldpLocSysName - der Name aus der LLDP-Sicht, als zweite Quelle.</summary>
        private const string LldpLocSysName = "1.0.8802.1.1.2.1.3.3.0";

        public event Action<int, int, int, ScanStatus>? ProgressUpdated;
        public event Action<SwitchPortResult>? SwitchPortFound;

        private int current;
        private int responded;
        private int total;

        private CancellationTokenSource _cts = new();

        /// <summary>Die Gemeinschaftskennung, mit der gefragt wird.</summary>
        public string Community { get; set; } = "public";

        public int TimeoutMs { get; set; } = 2000;

        public void StopScan()
        {
            if (_cts != null && !_cts.IsCancellationRequested) _cts.Cancel();

            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.stopped);
        }

        private void StartNewScan()
        {
            if (_cts != null)
            {
                if (!_cts.IsCancellationRequested) _cts.Cancel();
                _cts.Dispose();
            }

            _cts = new CancellationTokenSource();

            current = 0;
            responded = 0;
            total = 0;
        }

        /// <summary>
        /// Fragt die genannten Switches ab. Als Switch gilt hier schlicht jede
        /// Adresse, die man ihm nennt - meist die Gateways der Bereiche.
        /// </summary>
        public async Task ScanAsync(IReadOnlyList<string> switches)
        {
            ArgumentNullException.ThrowIfNull(switches);

            StartNewScan();

            total = switches.Count;
            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running);

            foreach (string switchAddress in switches)
            {
                if (_cts.Token.IsCancellationRequested) break;

                // SNMP-Abfragen der Bibliothek sind blockierend. Ein Walk ueber
                // eine grosse Weiterleitungstabelle dauert; auf dem
                // Oberflaechenfaden waere das ein eingefrorenes Fenster.
                List<SwitchPortResult> results =
                    await Task.Run(() => QuerySwitch(switchAddress), _cts.Token);

                int done = Interlocked.Increment(ref current);

                if (results.Count > 0)
                {
                    int found = Interlocked.Increment(ref responded);
                    ProgressUpdated?.Invoke(done, found, total, ScanStatus.running);

                    foreach (SwitchPortResult result in results) SwitchPortFound?.Invoke(result);
                }
                else
                {
                    ProgressUpdated?.Invoke(done, responded, total, ScanStatus.running);
                }
            }
        }

        /// <summary>
        /// Holt die vier Tabellen und setzt sie zusammen. Faellt eine aus, wird
        /// das Ergebnis duenner, aber nicht falsch - fehlt etwa der
        /// Schnittstellenname, steht dort die Bridge-Portnummer.
        /// </summary>
        private List<SwitchPortResult> QuerySwitch(string switchAddress)
        {
            List<SwitchPortResult> results = [];

            try
            {
                Dictionary<string, string>? fdb =
                    SnmpHelper.Walk(switchAddress, VersionCode.V2, Community, FdbPort, TimeoutMs);

                // Kein Eintrag heisst: entweder kein Switch, oder die
                // Gemeinschaftskennung stimmt nicht. Beides ist kein Fehler,
                // ueber den man stolpern sollte - es gibt schlicht nichts.
                if (fdb is null || fdb.Count == 0) return results;

                Dictionary<string, string> bridgeToIf =
                    SnmpHelper.Walk(switchAddress, VersionCode.V2, Community, BasePortIfIndex, TimeoutMs) ?? [];

                Dictionary<string, string> names =
                    SnmpHelper.Walk(switchAddress, VersionCode.V2, Community, IfName, TimeoutMs)
                    ?? SnmpHelper.Walk(switchAddress, VersionCode.V2, Community, IfDescr, TimeoutMs)
                    ?? [];

                Dictionary<string, string> vlans =
                    SnmpHelper.Walk(switchAddress, VersionCode.V2, Community, PortVlan, TimeoutMs) ?? [];

                string switchName = ReadSwitchName(switchAddress) ?? switchAddress;

                foreach (KeyValuePair<string, string> entry in fdb)
                {
                    if (_cts.Token.IsCancellationRequested) break;

                    string? mac = MacFromOid(entry.Key, FdbPort);
                    if (mac is null) continue;

                    string bridgePort = entry.Value.Trim();
                    if (bridgePort.Length == 0 || bridgePort == "0") continue;

                    string? ifIndex = Lookup(bridgeToIf, BasePortIfIndex, bridgePort);
                    string? portName = ifIndex is null ? null : Lookup(names, IfName, ifIndex)
                                                                ?? Lookup(names, IfDescr, ifIndex);

                    string? vlan = Lookup(vlans, PortVlan, bridgePort);

                    results.Add(new SwitchPortResult
                    {
                        Mac = mac,
                        SwitchAddress = switchAddress,
                        SwitchName = switchName,

                        // Ohne sprechenden Namen bleibt die Portnummer - die
                        // ist immer noch besser als gar keine Angabe.
                        Port = portName ?? $"Bridge port {bridgePort}",
                        Vlan = vlan
                    });
                }
            }
            catch (Exception)
            {
                // Ein Geraet, das nicht antwortet oder kein Switch ist, darf den
                // Lauf ueber die uebrigen nicht abbrechen.
            }

            return results;
        }

        private string? ReadSwitchName(string switchAddress)
        {
            Dictionary<string, string>? name =
                SnmpHelper.Get(switchAddress, VersionCode.V2, Community, [SysName], TimeoutMs)
                ?? SnmpHelper.Get(switchAddress, VersionCode.V2, Community, [LldpLocSysName], TimeoutMs);

            string? value = name?.Values.FirstOrDefault()?.Trim();

            return string.IsNullOrWhiteSpace(value) ? null : value;
        }

        /// <summary>
        /// Sucht in einer gewalkten Tabelle den Wert zu einem Index. Die
        /// Schluessel sind volle OIDs, der Index haengt hinten dran.
        /// </summary>
        private static string? Lookup(Dictionary<string, string> table, string baseOid, string index)
        {
            string wanted = $"{baseOid}.{index}";

            foreach (KeyValuePair<string, string> entry in table)
            {
                if (entry.Key.TrimStart('.') == wanted.TrimStart('.'))
                {
                    string value = entry.Value.Trim();
                    return value.Length == 0 ? null : value;
                }
            }

            return null;
        }

        /// <summary>
        /// Zieht die MAC-Adresse aus dem OID-Rest.
        /// <para>
        /// Der Kniff der Bridge-MIB: die Zeile ist nach der MAC indiziert, die
        /// steht also nicht im Wert, sondern im Schluessel - als sechs
        /// Dezimalzahlen hinter der Tabellen-OID. Aus
        /// <c>…17.4.3.1.2.0.26.75.12.34.56</c> wird <c>00-1A-4B-0C-22-38</c>.
        /// </para>
        /// </summary>
        private static string? MacFromOid(string oid, string baseOid)
        {
            string trimmed = oid.TrimStart('.');
            string prefix = baseOid.TrimStart('.') + ".";

            if (!trimmed.StartsWith(prefix, StringComparison.Ordinal)) return null;

            string[] parts = trimmed[prefix.Length..].Split('.', StringSplitOptions.RemoveEmptyEntries);

            // Bei manchen Switches steht die VLAN-Nummer vor der MAC. Genommen
            // werden darum die letzten sechs Zahlen, nicht die ersten.
            if (parts.Length < 6) return null;

            string[] macParts = parts[^6..];
            byte[] bytes = new byte[6];

            for (int i = 0; i < 6; i++)
            {
                if (!byte.TryParse(macParts[i], NumberStyles.Integer, CultureInfo.InvariantCulture, out bytes[i]))
                {
                    return null;
                }
            }

            return string.Join("-", bytes.Select(b => b.ToString("X2")));
        }
    }

    /// <summary>Wo eine MAC-Adresse am Netz haengt.</summary>
    public sealed class SwitchPortResult
    {
        /// <summary>Die MAC in der Schreibweise <c>00-1A-4B-0C-22-38</c>.</summary>
        public required string Mac { get; init; }

        public required string SwitchAddress { get; init; }
        public required string SwitchName { get; init; }

        /// <summary>Der Port, sprechend benannt oder als Bridge-Portnummer.</summary>
        public required string Port { get; init; }

        /// <summary>Das VLAN des Ports, falls der Switch es herausgibt.</summary>
        public string? Vlan { get; init; }

        public PhysicalAddress? ParsedMac =>
            PhysicalAddress.TryParse(Mac, out PhysicalAddress? parsed) ? parsed : null;
    }
}
