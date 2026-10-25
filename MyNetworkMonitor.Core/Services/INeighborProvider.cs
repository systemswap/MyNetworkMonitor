using System.Net;
using System.Net.NetworkInformation;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// State of a neighbor entry. Corresponds to the states of RFC 4861,
    /// section 7.3.2, and is the same on Windows and Linux - both run the same
    /// state machine, only under different names.
    /// <para>
    /// The state matters: <see cref="Incomplete"/> and <see cref="Failed"/> mean
    /// "this address was queried, but no answer ever came". Reporting such
    /// entries as discovered devices would be wrong - they only witness the
    /// local attempt.
    /// </para>
    /// </summary>
    public enum NeighborState
    {
        /// <summary>The state could not be determined.</summary>
        Unknown = 0,

        /// <summary>Queried, no answer yet. Not a device.</summary>
        Incomplete,

        /// <summary>Given up, nobody answers. Not a device.</summary>
        Failed,

        /// <summary>Entry present, but not confirmed for some time.</summary>
        Stale,

        /// <summary>Waiting before reachability is re-verified.</summary>
        Delay,

        /// <summary>Reachability probe in progress.</summary>
        Probe,

        /// <summary>Recently confirmed - the device is present.</summary>
        Reachable,

        /// <summary>Statically configured, never verified.</summary>
        Permanent
    }

    /// <summary>
    /// An entry from the operating system's neighbor table - the IPv6
    /// counterpart to <see cref="Models.ArpEntry"/>.
    /// <para>
    /// Richer than the ARP entry, deliberately: under IPv6 the table also
    /// carries the state and the router flag. Both can be evaluated -
    /// <see cref="IsRouter"/> identifies the router on the segment without
    /// sending a single packet.
    /// </para>
    /// </summary>
    public sealed class NeighborEntry
    {
        /// <summary>The neighbor's IP address.</summary>
        public required IPAddress Address { get; init; }

        /// <summary>Missing for entries that were never answered.</summary>
        public PhysicalAddress? Mac { get; init; }

        /// <summary>Index of the adapter through which the neighbor is reachable.</summary>
        public int InterfaceIndex { get; init; }

        /// <summary>Name of the adapter, if the platform provides it.</summary>
        public string? InterfaceName { get; init; }

        /// <summary>The neighbor cache state of the entry.</summary>
        public NeighborState State { get; init; } = NeighborState.Unknown;

        /// <summary>The neighbor has identified itself as a router.</summary>
        public bool IsRouter { get; init; }

        /// <summary>
        /// The entry witnesses a device that is actually present. A mere query
        /// attempt without an answer does not.
        /// </summary>
        public bool IsUsable =>
            State is not (NeighborState.Incomplete or NeighborState.Failed or NeighborState.Unknown) &&
            Mac is not null;

        public override string ToString() =>
            $"{Address} {Mac?.ToString() ?? "-"} [{State}]{(IsRouter ? " router" : "")}";
    }

    /// <summary>
    /// Reads the operating system's neighbor table (neighbor cache).
    /// <para>
    /// A separate interface instead of an extension of
    /// <see cref="IArpProvider"/>: the ARP provider returns strings and knows
    /// neither state nor adapter, and its Windows implementation parses the
    /// output of <c>arp -a</c>. That is not enough for IPv6 - there the state is
    /// needed to separate query attempts from real neighbors.
    /// </para>
    /// </summary>
    public interface INeighborProvider
    {
        /// <summary>
        /// All entries of both address families. Does not throw - if the table
        /// cannot be read, an empty list is returned.
        /// </summary>
        Task<IReadOnlyList<NeighborEntry>> GetNeighborsAsync(CancellationToken cancellationToken = default);
    }
}
