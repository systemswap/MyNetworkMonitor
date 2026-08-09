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
    /// Liest die Nachbarschaftstabelle ueber <c>GetIpNetTable2</c> aus
    /// <c>iphlpapi.dll</c> - dieselbe Quelle, aus der auch
    /// <c>netsh interface ipv6 show neighbors</c> schoepft.
    /// <para>
    /// Bewusst die API statt der Ausgabe von <c>netsh</c>: deren Spaltenkoepfe
    /// sind uebersetzt, und auf einem deutschen Windows steht in der
    /// Typ-Spalte "Erreichbar" statt "Reachable". Ein Auswerten nach Text
    /// waere damit an die Sprache des Systems gebunden. Die API liefert Zahlen.
    /// </para>
    /// <para>
    /// Die Tabelle wird byteweise gelesen statt ueber
    /// <see cref="Marshal.PtrToStructure(IntPtr, Type)"/>: <c>MIB_IPNET_ROW2</c>
    /// beginnt mit <c>SOCKADDR_INET</c>, und das ist eine Union aus IPv4- und
    /// IPv6-Adresse. Als C#-Struktur laesst sich das nur mit ueberlappenden
    /// Feldern nachbilden, und Feldversatz plus <c>ByValArray</c> vertragen
    /// sich schlecht. Die Versaetze stehen darum als Konstanten hier - einmal
    /// nachgerechnet und benannt, statt in einer Struktur versteckt.
    /// </para>
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class WindowsNeighborProvider : INeighborProvider
    {
        private const int AF_UNSPEC = 0;
        private const int AF_INET = 2;
        private const int AF_INET6 = 23;

        // --- Versaetze in MIB_IPNET_ROW2 -----------------------------------
        //
        // SOCKADDR_INET  Address              0   (28 Byte, Union)
        //   ADDRESS_FAMILY sin_family           0   (2)
        //   IPv4: sin_addr                      4   (4)
        //   IPv6: sin6_addr                     8   (16), sin6_scope_id 24 (4)
        // NET_IFINDEX    InterfaceIndex      28   (4)
        // NET_LUID       InterfaceLuid       32   (8, deshalb Auffuellung ab 28)
        // UCHAR          PhysicalAddress[32] 40
        // ULONG          PhysicalAddressLength 72 (4)
        // NL_NEIGHBOR_STATE State            76   (4)
        // UCHAR          Flags               80   (1)
        // ULONG          ReachabilityTime    84   (4)
        //                                    88   Gesamtgroesse (8er-Ausrichtung)
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

        /// <summary>MIB_IPNET_TABLE2: ULONG NumEntries, dann die Zeilen ab 8.</summary>
        private const int OffsetFirstRow = 8;

        /// <summary>Bit 0 von MIB_IPNET_ROW2.Flags - der Nachbar ist ein Router.</summary>
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
                catch (DllNotFoundException) { /* kein Windows-Netzwerkstapel - leere Liste */ }
                catch (EntryPointNotFoundException) { /* vor Vista, laengst irrelevant, aber kein Absturz */ }
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

                    // Ohne Zone ist eine Link-Local-Adresse nicht ansprechbar:
                    // fe80::1 gibt es auf jedem Adapter einmal. Windows laesst
                    // sin6_scope_id in dieser Tabelle durchweg auf 0 und fuehrt
                    // den Adapter stattdessen in InterfaceIndex - nachgemessen
                    // an einem Rechner mit sechs Adaptern. Also von dort
                    // nehmen, sonst kommt die Adresse ohne %n heraus und laesst
                    // sich nicht ansprechen.
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
        /// NL_NEIGHBOR_STATE aus <c>nldef.h</c>. Die Reihenfolge ist Teil der
        /// API und aendert sich nicht.
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
