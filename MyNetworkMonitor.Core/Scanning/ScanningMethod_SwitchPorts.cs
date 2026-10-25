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
    /// Asks a switch which MAC address is attached to which of its ports, and in which VLAN that
    /// port is.
    /// <para>
    /// <b>Why SNMP and not listening for LLDP:</b> listening for LLDP frames on the local adapter
    /// reveals exactly one thing, where the local computer is attached. It also needs raw sockets,
    /// that is npcap on Windows and <c>CAP_NET_RAW</c> on Linux. The switch keeps the mapping for
    /// <em>all</em> its ports anyway and provides it by SNMP: more information without any
    /// installation.
    /// </para>
    /// <para>
    /// <b>The path through the tables</b>, four queries that build on each other: the forwarding
    /// table (dot1dTpFdb, RFC 4188) gives a bridge port number per MAC; dot1dBasePortIfIndex
    /// translates it into an interface index; ifName (RFC 2863) adds the readable name such as
    /// "GigabitEthernet1/0/12"; and dot1qPvid (RFC 4363) gives the VLAN of the port. Only the
    /// whole chain yields a human-readable result.
    /// </para>
    /// </summary>
    public class ScanningMethod_SwitchPorts
    {
        // --- BRIDGE-MIB: which MAC on which bridge port -------------------------

        /// <summary>dot1dTpFdbPort: the value is the bridge port number, the rest of the OID the MAC.</summary>
        private const string FdbPort = "1.3.6.1.2.1.17.4.3.1.2";

        /// <summary>dot1dBasePortIfIndex: bridge port to interface index.</summary>
        private const string BasePortIfIndex = "1.3.6.1.2.1.17.1.4.1.2";

        // --- Interface names ---------------------------------------------------

        /// <summary>ifName: the short name, such as "Gi1/0/12".</summary>
        private const string IfName = "1.3.6.1.2.1.31.1.1.1.1";

        /// <summary>ifDescr: the long name, used if ifName is missing.</summary>
        private const string IfDescr = "1.3.6.1.2.1.2.2.1.2";

        // --- VLAN --------------------------------------------------------------

        /// <summary>dot1qPvid: the VLAN of a bridge port.</summary>
        private const string PortVlan = "1.3.6.1.2.1.17.7.1.4.5.1.1";

        // --- The switch itself -------------------------------------------------

        /// <summary>sysName: the name of the switch.</summary>
        private const string SysName = "1.3.6.1.2.1.1.5.0";

        /// <summary>lldpLocSysName (LLDP-MIB, IEEE 802.1AB): the LLDP system name, as a second source.</summary>
        private const string LldpLocSysName = "1.0.8802.1.1.2.1.3.3.0";

        /// <summary>Reports progress as (switches queried, switches with entries, total, status).</summary>
        public event Action<int, int, int, ScanStatus>? ProgressUpdated;

        /// <summary>Raised for every MAC address found on a switch port.</summary>
        public event Action<SwitchPortResult>? SwitchPortFound;

        private int current;
        private int responded;
        private int total;

        private CancellationTokenSource _cts = new();

        /// <summary>The SNMP community used for the queries.</summary>
        public string Community { get; set; } = "public";

        /// <summary>The time limit per SNMP request, in milliseconds.</summary>
        public int TimeoutMs { get; set; } = 2000;

        /// <summary>
        /// Cancels the running scan and reports <see cref="ScanStatus.stopped"/>.
        /// </summary>
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
        /// Queries the given switches. Every address passed in counts as a switch; usually these
        /// are the gateways of the scopes.
        /// </summary>
        /// <param name="switches">The addresses of the switches.</param>
        /// <exception cref="ArgumentNullException"><paramref name="switches"/> is <see langword="null"/>.</exception>
        public async Task ScanAsync(IReadOnlyList<string> switches)
        {
            ArgumentNullException.ThrowIfNull(switches);

            StartNewScan();

            total = switches.Count;
            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running);

            foreach (string switchAddress in switches)
            {
                if (_cts.Token.IsCancellationRequested) break;

                // The SNMP calls of the library block. A walk over a large forwarding table takes
                // time; on the UI thread that would freeze the window.
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
        /// Reads the four tables and combines them. If one is missing, the result has less detail
        /// but is not wrong; without the interface name, for example, the bridge port number is
        /// shown.
        /// </summary>
        private List<SwitchPortResult> QuerySwitch(string switchAddress)
        {
            List<SwitchPortResult> results = [];

            try
            {
                Dictionary<string, string>? fdb =
                    SnmpHelper.Walk(switchAddress, VersionCode.V2, Community, FdbPort, TimeoutMs);

                // No entry means either no switch or a wrong community. Neither is an error; there
                // is simply nothing to report.
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

                        // Without a readable name the port number remains, which is still better
                        // than no information.
                        Port = portName ?? $"Bridge port {bridgePort}",
                        Vlan = vlan
                    });
                }
            }
            catch (Exception)
            {
                // A device that does not answer or is no switch must not abort the run over the
                // others.
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
        /// Looks up the value for an index in a walked table. The keys are full OIDs with the
        /// index appended.
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
        /// Extracts the MAC address from the rest of the OID.
        /// <para>
        /// The BRIDGE-MIB table is indexed by the MAC, so the MAC is not in the value but in the
        /// key, as six decimal numbers after the table OID:
        /// <c>…17.4.3.1.2.0.26.75.12.34.56</c> becomes <c>00-1A-4B-0C-22-38</c>.
        /// </para>
        /// </summary>
        private static string? MacFromOid(string oid, string baseOid)
        {
            string trimmed = oid.TrimStart('.');
            string prefix = baseOid.TrimStart('.') + ".";

            if (!trimmed.StartsWith(prefix, StringComparison.Ordinal)) return null;

            string[] parts = trimmed[prefix.Length..].Split('.', StringSplitOptions.RemoveEmptyEntries);

            // Some switches put the VLAN number before the MAC, so the last six numbers are
            // taken, not the first.
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

    /// <summary>Where a MAC address is attached to the network.</summary>
    public sealed class SwitchPortResult
    {
        /// <summary>The MAC in the notation <c>00-1A-4B-0C-22-38</c>.</summary>
        public required string Mac { get; init; }

        /// <summary>The address of the switch that was queried.</summary>
        public required string SwitchAddress { get; init; }

        /// <summary>The name of the switch, or its address if it reports no name.</summary>
        public required string SwitchName { get; init; }

        /// <summary>The port, with its readable name or as a bridge port number.</summary>
        public required string Port { get; init; }

        /// <summary>The VLAN of the port, if the switch provides it.</summary>
        public string? Vlan { get; init; }

        /// <summary>The MAC as <see cref="PhysicalAddress"/>, or <see langword="null"/> if it cannot be parsed.</summary>
        public PhysicalAddress? ParsedMac =>
            PhysicalAddress.TryParse(Mac, out PhysicalAddress? parsed) ? parsed : null;
    }
}
