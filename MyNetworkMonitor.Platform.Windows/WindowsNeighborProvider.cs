using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Platform.Windows
{
    /// <summary>
    /// Reads the neighbor table with <c>GetIpNetTable2</c> from
    /// <c>iphlpapi.dll</c>, the same source that
    /// <c>netsh interface ipv6 show neighbors</c> uses.
    /// <para>
    /// Uses the API on purpose instead of the output of <c>netsh</c>: its
    /// column headers are localized, and on a German Windows the type column
    /// says "Erreichbar" instead of "Reachable". Text parsing would tie the
    /// result to the system language. The API returns numbers.
    /// </para>
    /// <para>
    /// The table is read byte by byte instead of with
    /// <see cref="Marshal.PtrToStructure(IntPtr, Type)"/>: <c>MIB_IPNET_ROW2</c>
    /// starts with <c>SOCKADDR_INET</c>, a union of an IPv4 and an IPv6
    /// address. As a C# struct this can only be modeled with overlapping
    /// fields, and explicit field offsets do not combine well with
    /// <c>ByValArray</c>. The offsets are therefore constants here, computed
    /// once and named instead of hidden in a struct.
    /// </para>
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class WindowsNeighborProvider : INeighborProvider
    {
        private const int AF_UNSPEC = 0;
        private const int AF_INET = 2;
        private const int AF_INET6 = 23;

        // --- Offsets in MIB_IPNET_ROW2 -------------------------------------
        //
        // SOCKADDR_INET  Address              0   (28 bytes, union)
        //   ADDRESS_FAMILY sin_family           0   (2)
        //   IPv4: sin_addr                      4   (4)
        //   IPv6: sin6_addr                     8   (16), sin6_scope_id 24 (4)
        // NET_IFINDEX    InterfaceIndex      28   (4)
        // NET_LUID       InterfaceLuid       32   (8, hence padding after offset 28)
        // UCHAR          PhysicalAddress[32] 40
        // ULONG          PhysicalAddressLength 72 (4)
        // NL_NEIGHBOR_STATE State            76   (4)
        // UCHAR          Flags               80   (1)
        // ULONG          ReachabilityTime    84   (4)
        //                                    88   total size (8-byte alignment)
        private const int OffsetFamily = 0;
        private const int OffsetV4Address = 4;
        private const int OffsetV6Address = 8;
        private const int OffsetV6ScopeId = 24;
        private const int OffsetInterfaceIndex = 28;
        private const int OffsetPhysicalAddress = 40;
        private const int OffsetPhysicalAddressLength = 72;
        private const int OffsetState = 76;
        private const int OffsetFlags = 80;
        private const int RowSize = 88;

        /// <summary>MIB_IPNET_TABLE2: ULONG NumEntries, followed by the rows from offset 8.</summary>
        private const int OffsetFirstRow = 8;

        /// <summary>Bit 0 of MIB_IPNET_ROW2.Flags: the neighbor is a router.</summary>
        private const byte FlagIsRouter = 0x01;

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int GetIpNetTable2(ushort family, out IntPtr table);

        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern void FreeMibTable(IntPtr memory);

        public Task<IReadOnlyList<NeighborEntry>> GetNeighborsAsync(CancellationToken cancellationToken = default)
        {
            return Task.Run<IReadOnlyList<NeighborEntry>>(() =>
            {
                cancellationToken.ThrowIfCancellationRequested();

                IntPtr table = IntPtr.Zero;
                var entries = new List<NeighborEntry>();

                try
                {
                    if (GetIpNetTable2(AF_UNSPEC, out table) != 0 || table == IntPtr.Zero)
                    {
                        return entries;
                    }

                    int count = Marshal.ReadInt32(table);

                    for (int i = 0; i < count; i++)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        NeighborEntry? entry = ReadRow(table + OffsetFirstRow + (i * RowSize));
                        if (entry is not null) entries.Add(entry);
                    }
                }
                catch (DllNotFoundException) { /* no Windows network stack: empty list */ }
                catch (EntryPointNotFoundException) { /* function missing (pre-Vista): empty list instead of a crash */ }
                finally
                {
                    if (table != IntPtr.Zero) FreeMibTable(table);
                }

                return entries;
            }, cancellationToken);
        }

        private static NeighborEntry? ReadRow(IntPtr row)
        {
            ushort family = (ushort)Marshal.ReadInt16(row, OffsetFamily);
            int interfaceIndex = Marshal.ReadInt32(row, OffsetInterfaceIndex);

            IPAddress address;
            switch (family)
            {
                case AF_INET:
                    byte[] v4 = new byte[4];
                    Marshal.Copy(row + OffsetV4Address, v4, 0, 4);
                    address = new IPAddress(v4);
                    break;

                case AF_INET6:
                    byte[] v6 = new byte[16];
                    Marshal.Copy(row + OffsetV6Address, v6, 0, 16);

                    // A link-local address cannot be reached without a zone:
                    // fe80::1 can exist once on every adapter. Windows leaves
                    // sin6_scope_id at 0 throughout this table and records the
                    // adapter in InterfaceIndex instead (measured on a machine
                    // with six adapters). The zone is therefore taken from
                    // there; otherwise the address comes out without %n and
                    // cannot be reached.
                    uint scopeId = (uint)Marshal.ReadInt32(row, OffsetV6ScopeId);
                    if (scopeId == 0 && interfaceIndex > 0) scopeId = (uint)interfaceIndex;

                    address = new IPAddress(v6, scopeId);
                    break;

                default:
                    return null;
            }

            int macLength = Marshal.ReadInt32(row, OffsetPhysicalAddressLength);
            PhysicalAddress? mac = null;

            if (macLength is > 0 and <= 32)
            {
                byte[] raw = new byte[macLength];
                Marshal.Copy(row + OffsetPhysicalAddress, raw, 0, macLength);
                mac = new PhysicalAddress(raw);
            }

            byte flags = Marshal.ReadByte(row, OffsetFlags);

            return new NeighborEntry
            {
                Address = address,
                Mac = mac,
                InterfaceIndex = interfaceIndex,
                State = ToState(Marshal.ReadInt32(row, OffsetState)),
                IsRouter = (flags & FlagIsRouter) != 0
            };
        }

        /// <summary>
        /// NL_NEIGHBOR_STATE from <c>nldef.h</c>. The order is part of the API
        /// and does not change.
        /// </summary>
        private static NeighborState ToState(int value) => value switch
        {
            0 => NeighborState.Failed,       // NlnsUnreachable
            1 => NeighborState.Incomplete,   // NlnsIncomplete
            2 => NeighborState.Probe,        // NlnsProbe
            3 => NeighborState.Delay,        // NlnsDelay
            4 => NeighborState.Stale,        // NlnsStale
            5 => NeighborState.Reachable,    // NlnsReachable
            6 => NeighborState.Permanent,    // NlnsPermanent
            _ => NeighborState.Unknown
        };
    }
}
