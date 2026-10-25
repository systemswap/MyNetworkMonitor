// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net;
using System.Net.NetworkInformation;

namespace MyNetworkMonitor.Core.Network
{
    /// <summary>
    /// An analyzed IP address. Unlike under IPv4, an IPv6 address is itself
    /// already a record: prefix, scope, origin of the interface identifier and
    /// sometimes even the MAC or an embedded IPv4 address can be derived from
    /// the bits alone.
    /// <para>
    /// The record is created via <see cref="IpAddressAnalyzer.Analyze"/>.
    /// Everything that does <b>not</b> follow from the address itself -
    /// lifetimes, state, origin as reported by the operating system - is
    /// deliberately kept on the device, not here, because it depends on
    /// observation rather than on the address.
    /// </para>
    /// </summary>
    public sealed class IpAddressInfo
    {
        /// <summary>The parsed address.</summary>
        public required IPAddress Address { get; init; }

        /// <summary>The address family.</summary>
        public required IpFamily Family { get; init; }

        /// <summary>The scope of the address.</summary>
        public required IpAddressScope Scope { get; init; }

        /// <summary>The special form, if any.</summary>
        public IpAddressSpecial Special { get; init; } = IpAddressSpecial.None;

        /// <summary>The origin of the interface identifier; not applicable for IPv4.</summary>
        public InterfaceIdKind InterfaceIdKind { get; init; } = InterfaceIdKind.Unknown;

        /// <summary>
        /// Zone or scope ID of a link-local address (the part after the %).
        /// Without it, an fe80 address cannot be addressed, so it must be carried
        /// wherever addresses are passed on as text. <c>null</c> if none was
        /// given.
        /// </summary>
        public long? ZoneId { get; init; }

        /// <summary>
        /// The MAC recovered from an EUI-64 interface identifier. Set only if
        /// <see cref="InterfaceIdKind"/> is <see cref="InterfaceIdKind.Eui64"/>.
        /// This allows determining the vendor even if the device is not on the
        /// same segment.
        /// </summary>
        public PhysicalAddress? DerivedMac { get; init; }

        /// <summary>
        /// The IPv4 address contained in the address for 6to4, ISATAP, NAT64,
        /// Teredo or IPv4-mapped. Allows matching against the IPv4 view.
        /// </summary>
        public IPAddress? EmbeddedIPv4 { get; init; }

        /// <summary>
        /// Canonical notation per RFC 5952 (lower case, longest run of zeros
        /// compressed), with the zone appended if present. This form is the one
        /// to store and compare - not the text as entered, because the same
        /// address can be written in many ways.
        /// </summary>
        public required string Canonical { get; init; }

        /// <summary>
        /// 16 bytes in network byte order, for stable sorting. IPv4 is sorted as
        /// IPv4-mapped so that v4 and v6 can be sorted side by side in one column.
        /// </summary>
        public required byte[] SortKey { get; init; }

        /// <summary>
        /// Reachable worldwide - and therefore directly addressable from the
        /// internet without NAT. Basis for the finding "port open globally".
        /// </summary>
        public bool IsGloballyRoutable => Scope == IpAddressScope.Global;

        /// <summary>
        /// The address is not suitable as a permanent identifier of a device -
        /// either because it changes regularly or because it is valid only on
        /// the segment. Prevents a device with privacy extensions from being
        /// counted as several devices.
        /// </summary>
        public bool IsUnstableIdentity =>
            InterfaceIdKind == InterfaceIdKind.Random || Scope == IpAddressScope.LinkLocal;

        public override string ToString() => Canonical;
    }
}
