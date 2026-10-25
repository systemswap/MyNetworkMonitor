// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net.NetworkInformation;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Model
{
    /// <summary>
    /// A single observation: what a scan method learned about a device at one
    /// point in time. Deliberately narrow - a method reports what it knows and
    /// leaves the rest empty.
    /// <para>
    /// The <see cref="DeviceStore"/> decides which device the observation
    /// belongs to. The scan methods need no knowledge of this, which allows
    /// passive sources such as the router advertisement capture and active
    /// scans to be treated the same way.
    /// </para>
    /// </summary>
    public sealed class DeviceObservation
    {
        /// <summary>The scan method that reported the observation.</summary>
        public required string Source { get; init; }

        /// <summary>When the observation was made.</summary>
        public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.Now;

        /// <summary>The observed address, if known.</summary>
        public IpAddressInfo? Address { get; init; }

        /// <summary>The MAC address of the responding interface; a hard identifier for matching.</summary>
        public PhysicalAddress? Mac { get; init; }

        /// <summary>
        /// A MAC address reported by the method that need not belong to the
        /// responding interface - currently the one from SNMP.
        /// <para>
        /// SNMP reports the MAC of the management interface or the base MAC of
        /// the device. On anything with several interfaces - switch, router,
        /// controller - that differs from the MAC that answered ARP for this
        /// address. Used as a hard identifier, it would split one device into
        /// two entries sharing the same address.
        /// </para>
        /// <para>
        /// It may therefore <em>establish</em> a match and fill an empty MAC,
        /// but never <em>prevent</em> a match - the same rule as for the MAC
        /// derived from an EUI-64 interface identifier.
        /// </para>
        /// </summary>
        public PhysicalAddress? SoftMac { get; init; }

        /// <summary>DHCPv6 DUID in hexadecimal notation.</summary>
        public string? Duid { get; init; }

        /// <summary>Host name without domain.</summary>
        public string? HostName { get; init; }
        /// <summary>DNS domain of the host.</summary>
        public string? Domain { get; init; }
        /// <summary>NetBIOS name of the host.</summary>
        public string? NetBiosName { get; init; }
        /// <summary>Hardware vendor, usually derived from the MAC address.</summary>
        public string? Vendor { get; init; }

        /// <summary>The IP range the observation comes from.</summary>
        public string? GroupDescription { get; init; }

        // --- Address details, as far as the method knows them ----------------

        /// <summary>How the address was assigned.</summary>
        public AddressOrigin Origin { get; init; } = AddressOrigin.Unknown;
        /// <summary>State of the address.</summary>
        public AddressState State { get; init; } = AddressState.Unknown;
        /// <summary>End of the valid lifetime, if known.</summary>
        public DateTimeOffset? ValidUntil { get; init; }
        /// <summary>End of the preferred lifetime, if known.</summary>
        public DateTimeOffset? PreferredUntil { get; init; }

        /// <summary>The target responded to the request behind this observation.</summary>
        public bool IsResponding { get; init; }

        /// <summary>Free-form details from the method, such as SNMP or mDNS information.</summary>
        public Dictionary<string, string>? Details { get; init; }

        /// <summary>
        /// The addresses the host name points to in DNS - the result of the
        /// forward lookup.
        /// <para>
        /// Without DNS, a duplicate assignment is invisible: two devices
        /// registering under the same name each respond inconspicuously. Only
        /// the forward lookup shows that a name has several addresses, and the
        /// reverse lookup that an address has several names. These are
        /// therefore separate properties rather than free text in
        /// <see cref="Details"/> - only then can they be used for coloring,
        /// filtering and sorting.
        /// </para>
        /// </summary>
        public List<string>? LookupAddresses { get; init; }

        /// <summary>Further names for the address, from the reverse lookup.</summary>
        public List<string>? Aliases { get; init; }

        /// <summary>
        /// Remaining TTL of the ping reply. 0 means "not measured" - only the
        /// ping fills this field, all other methods leave it empty.
        /// </summary>
        public int Ttl { get; init; }

        /// <summary>
        /// The switch the device is connected to, if a switch could be queried.
        /// Comes from the SNMP query, not from the device itself.
        /// </summary>
        public string? SwitchName { get; init; }
        /// <summary>The switch port the device is connected to.</summary>
        public string? SwitchPort { get; init; }
        /// <summary>The VLAN of the switch port.</summary>
        public string? Vlan { get; init; }

        /// <summary>Title of the web interface.</summary>
        public string? WebTitle { get; init; }
        /// <summary>Subject of the web interface certificate.</summary>
        public string? CertificateSubject { get; init; }
        /// <summary>Issuer of the web interface certificate.</summary>
        public string? CertificateIssuer { get; init; }
        /// <summary>Expiry date of the web interface certificate.</summary>
        public DateTimeOffset? CertificateExpires { get; init; }
        /// <summary>Whether the web interface certificate is self-signed.</summary>
        public bool? CertificateIsSelfSigned { get; init; }

        /// <summary>
        /// Detected services. The state is tracked per address family - the
        /// reporting method fills in only the side it checked and leaves the
        /// other <c>null</c>. Comparing both sides afterwards yields the finding
        /// "behind NAT on IPv4, open on IPv6".
        /// </summary>
        public List<DeviceServiceResult>? Services { get; init; }

        public override string ToString() =>
            $"{Source}: {Address?.Canonical ?? HostName ?? Mac?.ToString() ?? "?"}";
    }
}
