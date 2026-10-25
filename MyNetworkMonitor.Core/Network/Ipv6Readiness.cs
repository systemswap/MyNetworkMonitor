// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace MyNetworkMonitor.Core.Network
{
    /// <summary>
    /// How far IPv6 is actually usable on an adapter.
    /// <para>
    /// On many networks IPv6 is switched off, only half configured, or there is
    /// simply no router announcing a prefix. The application must detect this
    /// <b>before</b> starting IPv6 methods - otherwise they run into their
    /// timeouts without a result and the display shows empty columns without
    /// explanation.
    /// </para>
    /// </summary>
    public enum Ipv6Availability
    {
        /// <summary>Not checked yet.</summary>
        Unknown,

        /// <summary>The operating system itself does not support IPv6.</summary>
        NotSupportedByOperatingSystem,

        /// <summary>The adapter has no IPv6 binding - switched off on the adapter.</summary>
        DisabledOnAdapter,

        /// <summary>
        /// IPv6 is bound, but there is not a single IPv6 address. Unusual;
        /// occurs on freshly started or faulty adapters.
        /// </summary>
        NoAddress,

        /// <summary>
        /// Only a link-local address is present. The adapter supports IPv6, but
        /// no router on the network announces a prefix. The segment itself can
        /// still be examined completely - neighbor discovery, multicast and MLD
        /// all work over link-local.
        /// </summary>
        LinkLocalOnly,

        /// <summary>
        /// Additionally a ULA, but no global address. Internal IPv6 without an
        /// outside connection.
        /// </summary>
        UniqueLocalOnly,

        /// <summary>Global address present - IPv6 fully usable.</summary>
        Global
    }

    /// <summary>
    /// Result of the availability check with its reason. The reason is meant
    /// for the user interface: it appears where the IPv6 results would
    /// otherwise be.
    /// </summary>
    public sealed class Ipv6Readiness
    {
        /// <summary>The determined availability.</summary>
        public required Ipv6Availability Availability { get; init; }

        /// <summary>Short sentence for the user interface explaining the state.</summary>
        public required string Reason { get; init; }

        /// <summary>
        /// IPv6 methods on the segment make sense: neighbor cache, multicast to
        /// ff02::1, router advertisements and MLD only need link-local.
        /// </summary>
        public bool CanScanLocalSegment =>
            Availability is Ipv6Availability.LinkLocalOnly
                         or Ipv6Availability.UniqueLocalOnly
                         or Ipv6Availability.Global;

        /// <summary>
        /// Targets outside the own segment are reachable via IPv6. Without a
        /// global or unique local address this is not the case.
        /// </summary>
        public bool CanScanRoutedTargets =>
            Availability is Ipv6Availability.UniqueLocalOnly or Ipv6Availability.Global;

        /// <summary>
        /// The check "is this port reachable globally" is only meaningful with a
        /// global address.
        /// </summary>
        public bool CanAssessGlobalExposure => Availability == Ipv6Availability.Global;

        /// <summary>
        /// Hide IPv6 columns and views instead of showing them empty. When IPv6
        /// is not available at all, an empty column is only noise.
        /// </summary>
        public bool ShouldHideIpv6Ui =>
            Availability is Ipv6Availability.NotSupportedByOperatingSystem
                         or Ipv6Availability.DisabledOnAdapter
                         or Ipv6Availability.NoAddress;

        public override string ToString() => $"{Availability}: {Reason}";

        // ------------------------------------------------------------ Check

        /// <summary>Does the operating system support IPv6 at all?</summary>
        public static bool OperatingSystemSupportsIpv6 => Socket.OSSupportsIPv6;

        /// <summary>
        /// Checks a single adapter. Does not throw - an adapter that disappears
        /// during the check yields <see cref="Ipv6Availability.Unknown"/>.
        /// </summary>
        /// <param name="nic">The adapter; null yields <see cref="Ipv6Availability.Unknown"/>.</param>
        /// <returns>The availability with a reason for display.</returns>
        public static Ipv6Readiness ForInterface(NetworkInterface? nic)
        {
            if (!Socket.OSSupportsIPv6)
            {
                return new Ipv6Readiness
                {
                    Availability = Ipv6Availability.NotSupportedByOperatingSystem,
                    Reason = "This operating system does not support IPv6."
                };
            }

            if (nic is null)
            {
                return new Ipv6Readiness
                {
                    Availability = Ipv6Availability.Unknown,
                    Reason = "No network adapter selected."
                };
            }

            try
            {
                if (!nic.Supports(NetworkInterfaceComponent.IPv6))
                {
                    return new Ipv6Readiness
                    {
                        Availability = Ipv6Availability.DisabledOnAdapter,
                        Reason = $"IPv6 is not bound on adapter \"{nic.Name}\" - switched off there."
                    };
                }

                bool hasLinkLocal = false;
                bool hasUniqueLocal = false;
                bool hasGlobal = false;

                foreach (UnicastIPAddressInformation unicast in nic.GetIPProperties().UnicastAddresses)
                {
                    if (unicast.Address.AddressFamily != AddressFamily.InterNetworkV6) continue;

                    IpAddressInfo info = IpAddressAnalyzer.Analyze(unicast.Address);
                    switch (info.Scope)
                    {
                        case IpAddressScope.LinkLocal: hasLinkLocal = true; break;
                        case IpAddressScope.UniqueLocal: hasUniqueLocal = true; break;
                        case IpAddressScope.Global: hasGlobal = true; break;
                    }
                }

                if (hasGlobal)
                {
                    return new Ipv6Readiness
                    {
                        Availability = Ipv6Availability.Global,
                        Reason = "IPv6 fully usable - a global address is present."
                    };
                }

                if (hasUniqueLocal)
                {
                    return new Ipv6Readiness
                    {
                        Availability = Ipv6Availability.UniqueLocalOnly,
                        Reason = "Only a unique local address (ULA) - no access to the global IPv6 internet."
                    };
                }

                if (hasLinkLocal)
                {
                    return new Ipv6Readiness
                    {
                        Availability = Ipv6Availability.LinkLocalOnly,
                        Reason = "Link-local only - no router announces a prefix on this network. " +
                                 "The local segment can still be examined in full."
                    };
                }

                return new Ipv6Readiness
                {
                    Availability = Ipv6Availability.NoAddress,
                    Reason = $"Adapter \"{nic.Name}\" has no IPv6 address at all."
                };
            }
            catch (NetworkInformationException ex)
            {
                return new Ipv6Readiness
                {
                    Availability = Ipv6Availability.Unknown,
                    Reason = $"IPv6 status could not be determined: {ex.Message}"
                };
            }
            catch (PlatformNotSupportedException ex)
            {
                return new Ipv6Readiness
                {
                    Availability = Ipv6Availability.Unknown,
                    Reason = $"IPv6 status could not be determined: {ex.Message}"
                };
            }
        }
    }
}
