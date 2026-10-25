// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Text.RegularExpressions;
using CommunityToolkit.Mvvm.ComponentModel;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.ViewModels
{
    /// <summary>
    /// The filter above the result table. All conditions are combined with
    /// AND: whatever is set must match; whatever is empty does not filter.
    /// <para>
    /// Covers free-text search, column filters, services, ports, scopes,
    /// address family, state and feature switches. Deliberately independent
    /// of the UI so the logic can be tested without opening a window.
    /// </para>
    /// </summary>
    public partial class DeviceFilter : ObservableObject
    {
        // --- Free-text search (two fields) -----------------------------------
        [ObservableProperty] private string _text1 = string.Empty;
        [ObservableProperty] private string _text2 = string.Empty;

        // --- Column filters --------------------------------------------------
        [ObservableProperty] private string _ip = string.Empty;
        [ObservableProperty] private string _hostName = string.Empty;
        [ObservableProperty] private string _internalName = string.Empty;
        [ObservableProperty] private string _mac = string.Empty;
        [ObservableProperty] private string _vendor = string.Empty;

        // --- Services and ports ----------------------------------------------

        /// <summary>
        /// Free port input: single ports, comma-separated or as a range.
        /// </summary>
        [ObservableProperty] private string _ports = string.Empty;

        /// <summary>
        /// Selected service names. Empty means: do not filter by service.
        /// A device matches if <b>any</b> of the selected services applies;
        /// combined with OR, because AND would hardly ever match anything.
        /// </summary>
        public HashSet<string> Services { get; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Only consider services that are actually running.</summary>
        [ObservableProperty] private bool _onlyRunningServices;

        // --- Source scopes ---------------------------------------------------

        /// <summary>
        /// Selected scan scopes, matched against <see cref="Device.GroupDescription"/>.
        /// Empty means: do not filter by scope.
        /// <para>
        /// Combined with OR, as with services: a device comes from exactly one
        /// scope, so with AND the result would be empty from the second check
        /// mark on.
        /// </para>
        /// </summary>
        public HashSet<string> Scopes { get; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// The key for devices without a scope. Such devices exist (the ARP
        /// table or a broadcast query can return a device outside every entered
        /// scope), and without their own entry they would be the only ones that
        /// cannot be filtered.
        /// </summary>
        public const string NoScopeKey = "(no range)";

        // --- Address family ----------------------------------------------------
        [ObservableProperty] private bool _showIPv4 = true;
        [ObservableProperty] private bool _showIPv6 = true;

        /// <summary>
        /// Only devices with a global IPv6 address. Combined with the port
        /// filter this answers the question that makes IPv6 relevant: what is
        /// reachable from outside without NAT?
        /// </summary>
        [ObservableProperty] private bool _onlyGloballyReachable;

        // --- State -------------------------------------------------------------
        [ObservableProperty] private bool _onlyOnline;

        /// <summary>
        /// Only devices with an address conflict. Used when the status bar
        /// reports conflicts; among several hundred rows they are otherwise
        /// hard to find.
        /// </summary>
        [ObservableProperty] private bool _onlyConflicts;

        // --- Feature switches --------------------------------------------------
        [ObservableProperty] private bool _isCamera;
        [ObservableProperty] private bool _hasSsdp;
        [ObservableProperty] private bool _hasSmb;
        [ObservableProperty] private bool _hasSnmp;
        [ObservableProperty] private bool _hasNetBios;

        /// <summary>Raised whenever any condition changes.</summary>
        public event Action? Changed;

        /// <summary>Creates an empty filter that raises <see cref="Changed"/> on every property change.</summary>
        public DeviceFilter()
        {
            PropertyChanged += (_, _) => Changed?.Invoke();
        }

        /// <summary>Call after changing <see cref="Services"/>.</summary>
        public void NotifyServicesChanged() => Changed?.Invoke();

        /// <summary>Call after changing <see cref="Scopes"/>.</summary>
        public void NotifyScopesChanged() => Changed?.Invoke();

        /// <summary>Returns the key under which a device appears in the scope filter.</summary>
        /// <param name="device">The device.</param>
        /// <returns>The device's <see cref="Device.GroupDescription"/>, or <see cref="NoScopeKey"/> if it has none.</returns>
        public static string ScopeKeyOf(Device device) =>
            string.IsNullOrWhiteSpace(device.GroupDescription) ? NoScopeKey : device.GroupDescription;

        /// <summary>Nothing is set; all devices are visible.</summary>
        public bool IsEmpty =>
            string.IsNullOrWhiteSpace(Text1) && string.IsNullOrWhiteSpace(Text2) &&
            string.IsNullOrWhiteSpace(Ip) && string.IsNullOrWhiteSpace(HostName) &&
            string.IsNullOrWhiteSpace(InternalName) && string.IsNullOrWhiteSpace(Mac) &&
            string.IsNullOrWhiteSpace(Vendor) && string.IsNullOrWhiteSpace(Ports) &&
            Services.Count == 0 && Scopes.Count == 0 && !OnlyRunningServices && !OnlyOnline &&
            !OnlyGloballyReachable && ShowIPv4 && ShowIPv6 &&
            !IsCamera && !HasSsdp && !HasSmb && !HasSnmp && !HasNetBios;

        /// <summary>Clears all conditions and raises <see cref="Changed"/> once.</summary>
        public void Reset()
        {
            Text1 = Text2 = Ip = HostName = InternalName = Mac = Vendor = Ports = string.Empty;
            Services.Clear();
            Scopes.Clear();
            OnlyRunningServices = OnlyOnline = OnlyGloballyReachable = false;
            IsCamera = HasSsdp = HasSmb = HasSnmp = HasNetBios = false;
            ShowIPv4 = ShowIPv6 = true;
            Changed?.Invoke();
        }

        // --------------------------------------------------------------- Matching

        /// <summary>Checks a device against all set conditions.</summary>
        /// <param name="device">The device to check.</param>
        /// <returns><see langword="true"/> if the device passes the filter.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="device"/> is <see langword="null"/>.</exception>
        public bool Matches(Device device)
        {
            ArgumentNullException.ThrowIfNull(device);

            if (!MatchesFamily(device)) return false;
            if (OnlyOnline && !device.IsOnline) return false;
            if (OnlyConflicts && !device.HasConflict) return false;
            if (OnlyGloballyReachable && !device.HasGloballyRoutableAddress) return false;

            if (!MatchesFreeText(device, Text1)) return false;
            if (!MatchesFreeText(device, Text2)) return false;

            if (!MatchesAddress(device, Ip)) return false;
            if (!Contains(device.HostName, HostName)) return false;
            if (!Contains(device.InternalName, InternalName)) return false;
            if (!Contains(MacText(device), Mac)) return false;
            if (!Contains(device.Vendor, Vendor)) return false;

            if (!MatchesScope(device)) return false;
            if (!MatchesPorts(device)) return false;
            if (!MatchesServices(device)) return false;
            if (!MatchesFeatures(device)) return false;

            return true;
        }

        /// <summary>
        /// A device is excluded only if <b>none</b> of its addresses belongs to
        /// a visible family. A dual-stack device therefore stays visible as
        /// long as either family is enabled.
        /// </summary>
        private bool MatchesFamily(Device device)
        {
            if (ShowIPv4 && ShowIPv6) return true;
            if (!ShowIPv4 && !ShowIPv6) return false;

            return ShowIPv4 ? device.Ipv4Addresses.Any() : device.Ipv6Addresses.Any();
        }

        /// <summary>Searches everything shown in the table.</summary>
        private static bool MatchesFreeText(Device device, string needle)
        {
            if (string.IsNullOrWhiteSpace(needle)) return true;

            string n = needle.Trim();

            if (Contains(device.DisplayName, n) ||
                Contains(device.HostName, n) ||
                Contains(device.InternalName, n) ||
                Contains(device.NetBiosName, n) ||
                Contains(device.Vendor, n) ||
                Contains(device.Domain, n) ||
                Contains(device.GroupDescription, n) ||
                Contains(MacText(device), n))
            {
                return true;
            }

            if (device.Addresses.Any(a => a.Info.Canonical.Contains(n, StringComparison.OrdinalIgnoreCase)))
                return true;

            // DNS data is searched too: an alias or an address registered in
            // DNS identifies the device behind it.
            if (device.Aliases.Any(a => a.Contains(n, StringComparison.OrdinalIgnoreCase)) ||
                device.LookupAddresses.Any(a => a.Contains(n, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            if (device.OpenServices.Any(s => s.ServiceName.Contains(n, StringComparison.OrdinalIgnoreCase)))
                return true;

            return device.Details.Values.Any(v => v.Contains(n, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Address filter with wildcard. <c>192.0.2.*</c> matches the whole
        /// subnet, <c>2001:db8:*</c> everything in that prefix. Without an
        /// asterisk the pattern is matched as a substring.
        /// </summary>
        private static bool MatchesAddress(Device device, string pattern)
        {
            if (string.IsNullOrWhiteSpace(pattern)) return true;

            string p = pattern.Trim();

            if (!p.Contains('*'))
            {
                return device.Addresses.Any(a =>
                    a.Info.Canonical.Contains(p, StringComparison.OrdinalIgnoreCase));
            }

            string regex = "^" + Regex.Escape(p).Replace("\\*", ".*") + "$";
            Regex compiled = new(regex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

            return device.Addresses.Any(a => compiled.IsMatch(a.Info.Canonical));
        }

        /// <summary>
        /// Whether the device comes from one of the checked scopes. Without a
        /// selection every device matches; otherwise the table would stay empty
        /// until something is checked.
        /// </summary>
        private bool MatchesScope(Device device) =>
            Scopes.Count == 0 || Scopes.Contains(ScopeKeyOf(device));

        private bool MatchesPorts(Device device)
        {
            PortSpec spec = PortSpec.Parse(Ports);
            if (spec.IsEmpty) return true;

            return Candidates(device).Any(s => spec.ContainsAny(s.Ports));
        }

        private bool MatchesServices(Device device)
        {
            if (Services.Count == 0)
            {
                // Without a service selection "running only" still applies: at
                // least one running service must be present.
                return !OnlyRunningServices || device.Services.Any(s => s.IsRunning);
            }

            return Candidates(device).Any(s => Services.Contains(s.ServiceName));
        }

        /// <summary>
        /// The services that are filtered on: only those that answered. A
        /// closed port is the result of a probe, not a property of the device;
        /// filtering for "SSH" means devices with open SSH, not every device
        /// that was probed for it.
        /// </summary>
        private IEnumerable<DeviceServiceResult> Candidates(Device device) =>
            OnlyRunningServices
                ? device.Services.Where(s => s.IsRunning)
                : device.OpenServices;

        private bool MatchesFeatures(Device device)
        {
            if (IsCamera && !HasDetail(device, "Camera")) return false;
            if (HasSnmp && !HasDetail(device, "SNMP")) return false;
            if (HasSmb && !HasDetail(device, "SMB versions") && !HasService(device, "SMB")) return false;
            if (HasNetBios && string.IsNullOrWhiteSpace(device.NetBiosName)) return false;
            if (HasSsdp && !device.SeenBy.Contains("SSDP / UPnP")) return false;

            return true;
        }

        // ---------------------------------------------------------------- Helpers

        private static bool HasDetail(Device device, string key) =>
            device.Details.ContainsKey(key);

        private static bool HasService(Device device, string name) =>
            device.OpenServices.Any(s => s.ServiceName.Contains(name, StringComparison.OrdinalIgnoreCase));

        private static string MacText(Device device) =>
            device.Mac is null
                ? string.Empty
                : string.Join(":", device.Mac.GetAddressBytes().Select(b => b.ToString("x2")));

        private static bool Contains(string? haystack, string? needle) =>
            string.IsNullOrWhiteSpace(needle) ||
            (!string.IsNullOrEmpty(haystack) && haystack.Contains(needle.Trim(), StringComparison.OrdinalIgnoreCase));
    }
}
