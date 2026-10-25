// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>How urgent a finding is.</summary>
    public enum FindingSeverity
    {
        /// <summary>Good to know; no action required.</summary>
        Note = 0,

        /// <summary>Should be looked at.</summary>
        Warning = 1,

        /// <summary>Something is broken or exposed and should be fixed.</summary>
        Critical = 2
    }

    /// <summary>
    /// The area a finding belongs to. Groups the list so it stays clear as it
    /// grows.
    /// <para>
    /// <see cref="RouterAdvertisement"/> has no rule that produces findings
    /// yet. It is defined anyway so the order of the categories stays stable;
    /// categories inserted later would shift the whole display.
    /// </para>
    /// </summary>
    public enum FindingCategory
    {
        /// <summary>Addresses and names: duplicate, contradictory, orphaned.</summary>
        Addressing,

        /// <summary>Services and ports.</summary>
        Services,

        /// <summary>The local computer: adapters, DNS servers, privileges.</summary>
        LocalMachine,

        /// <summary>Router advertisements and prefixes.</summary>
        RouterAdvertisement,

        /// <summary>Reachability from outside, NAT and firewall gaps.</summary>
        Reachability
    }

    /// <summary>
    /// A single finding. Deliberately flat and independent of the UI, so the
    /// rule results can also be printed or saved.
    /// </summary>
    public sealed class Finding
    {
        /// <summary>How urgent the finding is.</summary>
        public required FindingSeverity Severity { get; init; }

        /// <summary>The area the finding belongs to.</summary>
        public required FindingCategory Category { get; init; }

        /// <summary>
        /// The affected address family, or <c>null</c> if it does not matter.
        /// Carries the colour scheme (teal for IPv4, indigo for IPv6) into this
        /// list so IPv6 findings are recognisable at a glance.
        /// </summary>
        public IpFamily? Family { get; init; }

        /// <summary>Short name of the rule, e.g. "Duplicate address".</summary>
        public required string Title { get; init; }

        /// <summary>What exactly was found, in one sentence.</summary>
        public required string Detail { get; init; }

        /// <summary>What it concerns: device name or adapter.</summary>
        public string Subject { get; init; } = string.Empty;

        /// <summary>
        /// The affected device, if any. Used to jump to the device list; a
        /// finding that cannot be located is of limited use.
        /// </summary>
        public Device? Device { get; init; }

        /// <summary>The severity as upper-case label.</summary>
        public string SeverityText => Severity switch
        {
            FindingSeverity.Critical => "CRITICAL",
            FindingSeverity.Warning => "WARNING",
            _ => "NOTE"
        };

        /// <summary>The category as display label.</summary>
        public string CategoryText => Category switch
        {
            FindingCategory.Addressing => "Addressing",
            FindingCategory.Services => "Services",
            FindingCategory.LocalMachine => "This machine",
            FindingCategory.RouterAdvertisement => "Router",
            FindingCategory.Reachability => "Reachability",
            _ => string.Empty
        };

        /// <summary>Short label of the address family for the narrow column.</summary>
        public string FamilyText => Family switch
        {
            IpFamily.IPv4 => "v4",
            IpFamily.IPv6 => "v6",
            _ => string.Empty
        };

        public override string ToString() => $"[{SeverityText}] {Title}: {Detail}";
    }

    /// <summary>
    /// Collects all findings in one place.
    /// <para>
    /// The detection itself happens elsewhere: address conflicts in the
    /// <see cref="DuplicateDetector"/>, the adapter check in
    /// <see cref="NetworkAdapters"/>. Here they are only collected and sorted
    /// by urgency. Spread across the device table, a finding is only noticed
    /// by someone who already knows it exists.
    /// </para>
    /// </summary>
    public sealed partial class FindingsViewModel : ObservableObject
    {
        private readonly DeviceStore _store;

        /// <summary>Creates the view model.</summary>
        /// <param name="store">The device store whose devices are evaluated.</param>
        /// <exception cref="ArgumentNullException"><paramref name="store"/> is <see langword="null"/>.</exception>
        public FindingsViewModel(DeviceStore store)
        {
            _store = store ?? throw new ArgumentNullException(nameof(store));
        }

        /// <summary>The findings shown, sorted by severity, title and subject.</summary>
        public ObservableCollection<Finding> Findings { get; } = [];

        /// <summary>The selected finding.</summary>
        [ObservableProperty] private Finding? _selected;

        /// <summary>Shows critical findings only.</summary>
        [ObservableProperty] private bool _criticalOnly;

        partial void OnCriticalOnlyChanged(bool value) => Refresh();

        [ObservableProperty] private int _criticalCount;
        [ObservableProperty] private int _warningCount;
        [ObservableProperty] private int _noteCount;

        /// <summary>When the rules last ran.</summary>
        [ObservableProperty] private DateTimeOffset _lastRun;

        /// <summary>At least one finding is shown.</summary>
        public bool HasFindings => Findings.Count > 0;

        /// <summary>
        /// The text shown when nothing was found. An empty screen would leave
        /// open whether a check ran or whether nothing is displayed.
        /// </summary>
        public string EmptyText =>
            LastRun == default
                ? "Nothing checked yet. Run a scan, then the rules run over the result."
                : "No findings. Every rule ran and none of them matched.";

        /// <summary>Runs all rules over the current devices and adapters and rebuilds the list and counters.</summary>
        [RelayCommand]
        public void Refresh()
        {
            Findings.Clear();

            List<Finding> found = [];

            lock (_store.SyncRoot)
            {
                CollectDuplicates(found);
                CollectServices(found);
                CollectDnsCrossChecks(found);
                CollectDhcpServers(found);
                CollectCertificates(found);
            }

            CollectAdapters(found);

            IEnumerable<Finding> visible = CriticalOnly
                ? found.Where(f => f.Severity == FindingSeverity.Critical)
                : found;

            foreach (Finding finding in visible
                         .OrderByDescending(f => (int)f.Severity)
                         .ThenBy(f => f.Title, StringComparer.CurrentCulture)
                         .ThenBy(f => f.Subject, StringComparer.CurrentCulture))
            {
                Findings.Add(finding);
            }

            CriticalCount = found.Count(f => f.Severity == FindingSeverity.Critical);
            WarningCount = found.Count(f => f.Severity == FindingSeverity.Warning);
            NoteCount = found.Count(f => f.Severity == FindingSeverity.Note);

            LastRun = DateTimeOffset.Now;

            OnPropertyChanged(nameof(HasFindings));
            OnPropertyChanged(nameof(EmptyText));
        }

        // ------------------------------------------------------------- Rules

        /// <summary>
        /// Duplicate addresses and names. The detector has already determined
        /// them at the end of the run; here they are only translated into
        /// findings.
        /// </summary>
        private void CollectDuplicates(List<Finding> found)
        {
            foreach (Device device in _store.Devices.Where(d => d.HasConflict))
            {
                foreach (string line in device.ConflictDetails
                             .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    found.Add(new Finding
                    {
                        // A duplicate address loses packets, a duplicate name
                        // only causes confusion; the severity differs.
                        Severity = device.Conflicts.HasFlag(DeviceConflict.Address)
                            ? FindingSeverity.Critical
                            : FindingSeverity.Warning,
                        Category = FindingCategory.Addressing,
                        Title = TitleFor(device.Conflicts),
                        Detail = line,
                        Subject = device.DisplayName,
                        Device = device
                    });
                }
            }
        }

        private static string TitleFor(DeviceConflict conflicts) =>
            conflicts.HasFlag(DeviceConflict.Address) ? "Duplicate address" :
            conflicts.HasFlag(DeviceConflict.DnsMultipleAddresses) ? "Name resolves to several addresses" :
            conflicts.HasFlag(DeviceConflict.HostName) ? "Duplicate host name" :
            conflicts.HasFlag(DeviceConflict.DuplicateAlias) ? "Duplicate alias" :
            conflicts.HasFlag(DeviceConflict.DnsMismatch) ? "DNS points elsewhere" :
            conflicts.HasFlag(DeviceConflict.MultipleIpv4) ? "Several IPv4 addresses" :
            "Duplicate assignment";

        /// <summary>
        /// DNS servers that answer differently for the same address.
        /// <para>
        /// The finding is not "the name is wrong" but "the servers disagree",
        /// and it names the server. Without that, the problem would be known
        /// but not where to look.
        /// </para>
        /// </summary>
        private void CollectDnsCrossChecks(List<Finding> found)
        {
            foreach (Device device in _store.Devices)
            {
                if (device.DnsCrossCheck is not { HasMismatch: true } check) continue;

                found.Add(new Finding
                {
                    // If the servers contradict each other, the same name
                    // resolves differently depending on the client, which
                    // affects operation immediately. A silent or orphaned
                    // entry is a maintenance issue and weighs less.
                    Severity = check.DistinctNames.Count > 1
                        ? FindingSeverity.Critical
                        : FindingSeverity.Warning,
                    Category = FindingCategory.Addressing,
                    Title = check.DistinctNames.Count > 1
                        ? "DNS servers disagree"
                        : "DNS server does not resolve cleanly",
                    Detail = check.Summary,
                    Subject = device.DisplayName,
                    Device = device
                });
            }
        }

        /// <summary>
        /// Rules over the discovered services: SMB 1.0 still enabled, services
        /// open over IPv6 only, and open ports on a globally routable address.
        /// </summary>
        private void CollectServices(List<Finding> found)
        {
            foreach (Device device in _store.Devices)
            {
                foreach (DeviceServiceResult service in device.OpenServices)
                {
                    // SMB 1.0 is long deprecated and the route by which
                    // WannaCry spread through networks.
                    if (string.Equals(service.ServiceName, "SMB", StringComparison.OrdinalIgnoreCase) &&
                        service.PortLog?.Contains("1.0", StringComparison.Ordinal) == true)
                    {
                        found.Add(new Finding
                        {
                            Severity = FindingSeverity.Critical,
                            Category = FindingCategory.Services,
                            Title = "SMB 1.0 still enabled",
                            Detail = $"{device.DisplayName} still answers SMB 1.0 ({service.PortLog}). " +
                                     "The protocol is deprecated and should be switched off.",
                            Subject = device.DisplayName,
                            Device = device
                        });
                    }

                    // This finding only exists because both address families
                    // are compared.
                    if (service.IsExposedOnlyViaIpv6)
                    {
                        found.Add(new Finding
                        {
                            Severity = FindingSeverity.Critical,
                            Category = FindingCategory.Reachability,
                            Family = IpFamily.IPv6,
                            Title = "Service open over IPv6 only",
                            Detail = $"{service.ServiceName} on {device.DisplayName} answers over IPv6 but not " +
                                     "over IPv4 - a firewall rule that covers only IPv4.",
                            Subject = device.DisplayName,
                            Device = device
                        });
                    }
                }

                if (device.HasGloballyRoutableAddress && device.OpenPortCount > 0)
                {
                    found.Add(new Finding
                    {
                        Severity = FindingSeverity.Warning,
                        Category = FindingCategory.Reachability,
                        Title = "Open ports on a globally routable address",
                        Detail = $"{device.DisplayName} has {device.OpenPortCount} open port(s) and an address " +
                                 "reachable from the internet without NAT.",
                        Subject = device.DisplayName,
                        Device = device
                    });
                }
            }
        }

        /// <summary>
        /// More than one DHCP server answering in the same network.
        /// <para>
        /// A classic hard-to-find fault: a privately connected router is
        /// plugged in the wrong way round and hands out addresses. Only clients
        /// that happen to get its answer first are affected, so individual
        /// clients lose connectivity while a check from the administrator's
        /// workstation finds nothing.
        /// </para>
        /// <para>
        /// Two servers are not always wrong; redundancy is built exactly this
        /// way. Hence a warning rather than a critical finding: only the
        /// operator can decide whether the second server belongs there, so all
        /// of them are listed by name.
        /// </para>
        /// </summary>
        private void CollectDhcpServers(List<Finding> found)
        {
            List<Device> servers = [.. _store.Devices.Where(HasDhcpService)];

            if (servers.Count < 2) return;

            string names = string.Join(", ", servers.Select(d => d.DisplayName));

            foreach (Device device in servers)
            {
                found.Add(new Finding
                {
                    Severity = FindingSeverity.Warning,
                    Category = FindingCategory.Services,
                    Title = "More than one DHCP server answered",
                    Detail = $"{servers.Count} DHCP servers replied in this network: {names}. " +
                             "If that is not deliberate redundancy, one of them is handing out " +
                             "addresses it should not.",
                    Subject = device.DisplayName,
                    Device = device
                });
            }
        }

        private static bool HasDhcpService(Device device) =>
            device.OpenServices.Any(s =>
                s.ServiceName.Contains("DHCP", StringComparison.OrdinalIgnoreCase));

        /// <summary>
        /// Rules over the TLS certificates that were read.
        /// <para>
        /// Expired certificates teach people to click away security warnings,
        /// including the genuine ones. Self-signed certificates, on the other
        /// hand, are normal for devices and not worth a finding on their own;
        /// they are only mentioned together with an expiry.
        /// </para>
        /// </summary>
        private void CollectCertificates(List<Finding> found)
        {
            foreach (Device device in _store.Devices.Where(d => d.CertificateIsExpired))
            {
                string since = device.CertificateExpires is { } expires
                    ? expires.ToString("yyyy-MM-dd")
                    : "an unknown date";

                found.Add(new Finding
                {
                    Severity = FindingSeverity.Warning,
                    Category = FindingCategory.Services,
                    Title = "Expired TLS certificate",
                    Detail = $"The web interface of {device.DisplayName} presents a certificate that " +
                             $"expired on {since}" +
                             (device.CertificateIsSelfSigned ? " and is self-signed." : "."),
                    Subject = device.DisplayName,
                    Device = device
                });
            }
        }

        /// <summary>
        /// The local side: adapters that have accumulated too many DNS servers.
        /// Every failing server costs waiting time, and the problem is not
        /// visible anywhere else.
        /// </summary>
        private static void CollectAdapters(List<Finding> found)
        {
            foreach (AdapterInfo adapter in NetworkAdapters.Read().Where(a => a.HasTooManyDnsServers))
            {
                found.Add(new Finding
                {
                    Severity = FindingSeverity.Warning,
                    Category = FindingCategory.LocalMachine,
                    Title = "Too many DNS servers on one adapter",
                    Detail = $"{adapter.Name} has {adapter.DnsServerCount} DNS servers ({adapter.DnsText}). " +
                             "Usually a leftover from repeated DHCP leases.",
                    Subject = adapter.Name
                });
            }
        }
    }
}
