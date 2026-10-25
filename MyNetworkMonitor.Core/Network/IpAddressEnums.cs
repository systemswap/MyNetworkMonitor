// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
namespace MyNetworkMonitor.Core.Network
{
    /// <summary>
    /// Address family as used by the application. Deliberately not
    /// <see cref="System.Net.Sockets.AddressFamily"/>, so model and user interface
    /// do not depend on socket types.
    /// </summary>
    public enum IpFamily
    {
        /// <summary>IPv4.</summary>
        IPv4,
        /// <summary>IPv6.</summary>
        IPv6
    }

    /// <summary>
    /// Scope of an address. Determines what can be done with it at all: a
    /// link-local address cannot be addressed without a zone ID, a global
    /// address is directly reachable without NAT.
    /// </summary>
    public enum IpAddressScope
    {
        /// <summary>Not determinable, or a range that is neither routed nor local (for example documentation).</summary>
        Unknown,

        /// <summary>::1 or 127.0.0.0/8.</summary>
        Loopback,

        /// <summary>:: or 0.0.0.0 - no address.</summary>
        Unspecified,

        /// <summary>fe80::/10 or 169.254.0.0/16. Valid only on the same segment.</summary>
        LinkLocal,

        /// <summary>fc00::/7 (ULA) or the RFC 1918 and RFC 6598 ranges. Locally valid, not routed on the internet.</summary>
        UniqueLocal,

        /// <summary>2000::/3 or public IPv4. Routed worldwide.</summary>
        Global,

        /// <summary>ff00::/8 or 224.0.0.0/4.</summary>
        Multicast,

        /// <summary>255.255.255.255 - IPv4 only.</summary>
        Broadcast
    }

    /// <summary>
    /// Special forms recognizable in an address in addition to its
    /// <see cref="IpAddressScope"/>. Several of them carry an embedded IPv4
    /// address that can be extracted and matched against the IPv4 view.
    /// </summary>
    public enum IpAddressSpecial
    {
        /// <summary>No special form.</summary>
        None,

        /// <summary>::ffff:a.b.c.d - an IPv4 address in IPv6 notation.</summary>
        IPv4Mapped,

        /// <summary>::a.b.c.d - deprecated long ago, but still appears.</summary>
        IPv4Compatible,

        /// <summary>2001:0::/32 - tunnel through NAT.</summary>
        Teredo,

        /// <summary>2002::/16 - IPv6 tunneled over IPv4.</summary>
        SixToFour,

        /// <summary>Interface identifier 0000:5efe or 0200:5efe followed by an IPv4 address.</summary>
        Isatap,

        /// <summary>64:ff9b::/96 - well-known prefix for NAT64/DNS64.</summary>
        Nat64WellKnown,

        /// <summary>2001:db8::/32 - documentation only, must not occur in real networks.</summary>
        Documentation,

        /// <summary>2001:2::/48 - reserved for benchmarking.</summary>
        Benchmarking,

        /// <summary>ff02::1:ffXX:XXXX - reveals the lower 24 bits of an interface identifier.</summary>
        SolicitedNodeMulticast,

        /// <summary>fc00::/8 - intended for central assignment, never allocated. Indicates a misconfiguration.</summary>
        UnassignedUniqueLocal
    }

    /// <summary>
    /// Origin of the lower 64 bits of an IPv6 address, as far as it can be
    /// derived from the bits themselves.
    /// <para>
    /// Important: <see cref="Random"/> covers both privacy extensions
    /// (RFC 8981, changes regularly) and stable opaque identifiers (RFC 7217,
    /// stays the same per prefix). Both are pseudo-random and <b>cannot be
    /// distinguished from the address alone</b>. The distinction is only
    /// possible over time (does it change?) or via the operating system
    /// (SuffixOrigin). The analyzer deliberately claims no more than it can
    /// know.
    /// </para>
    /// </summary>
    public enum InterfaceIdKind
    {
        /// <summary>Cannot be classified, for example an all-zero identifier.</summary>
        Unknown,

        /// <summary>IPv4 only - no interface identifier present.</summary>
        NotApplicable,

        /// <summary>
        /// Formed from a MAC address (ff:fe in the middle, u/l bit flipped).
        /// The MAC can be recovered - see <see cref="IpAddressInfo.DerivedMac"/>.
        /// </summary>
        Eui64,

        /// <summary>Very small value such as ::1 or ::20. Usually assigned manually.</summary>
        LowByte,

        /// <summary>Pseudo-random. Privacy extension or stable opaque identifier - see the remarks on the enum.</summary>
        Random,

        /// <summary>Carries an embedded IPv4 address (6to4, ISATAP, NAT64, Teredo).</summary>
        Embedded
    }

    /// <summary>
    /// How an address came to the interface. Not derived from the bits but
    /// reported by the operating system (PrefixOrigin/SuffixOrigin on Windows,
    /// the flags from <c>ip -6 addr</c> on Linux).
    /// </summary>
    public enum AddressOrigin
    {
        /// <summary>Not reported.</summary>
        Unknown,

        /// <summary>Formed from a router advertisement.</summary>
        Slaac,

        /// <summary>Assigned by a DHCP or DHCPv6 server.</summary>
        Dhcp,

        /// <summary>Configured manually.</summary>
        Manual,

        /// <summary>Predefined, for example loopback.</summary>
        WellKnown,

        /// <summary>Formed from the layer 2 address.</summary>
        LinkLayer,

        /// <summary>Generated randomly.</summary>
        Random
    }

    /// <summary>
    /// State of an address in terms of duplicate address detection and
    /// lifetimes (RFC 4862). <see cref="Duplicate"/> is a finding and must be
    /// reported.
    /// </summary>
    public enum AddressState
    {
        /// <summary>Not reported.</summary>
        Unknown,

        /// <summary>Verification still in progress; the address must not be used.</summary>
        Tentative,

        /// <summary>Valid and preferred for new connections.</summary>
        Preferred,

        /// <summary>Still valid, but no longer to be used for new connections.</summary>
        Deprecated,

        /// <summary>Lifetime expired.</summary>
        Invalid,

        /// <summary>The address is already in use on the segment.</summary>
        Duplicate
    }
}
