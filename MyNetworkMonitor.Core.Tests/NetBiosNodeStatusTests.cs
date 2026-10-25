// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Text;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Tests;

/// <summary>
/// <see cref="NetBiosNodeStatus"/>: request and evaluation after RFC 1002, sections 4.2.17 and 4.2.18
/// (docs/FEHLERGEDAECHTNIS.md, No. 15). All responses are built here; names are invented.
/// </summary>
public class NetBiosNodeStatusTests
{
    private static readonly (string Name, byte Suffix, bool Group)[] HostAndGroup =
    [
        ("PC-EXAMPLE", 0x00, false), ("WORKGROUP", 0x00, true), ("PC-EXAMPLE", 0x20, false), ("WORKGROUP", 0x1E, true),
    ];

    /// <summary>Builds a node status response after RFC 1002, 4.2.18, with unit ID 02-00-00-00-00-01.</summary>
    private static byte[] Response(ushort id, (string Name, byte Suffix, bool Group)[] names, bool pointer = false, ushort flags = 0x8400)
    {
        var b = new List<byte> { (byte)(id >> 8), (byte)id, (byte)(flags >> 8), (byte)flags, 0, 0, 0, 1, 0, 0, 0, 0 };
        if (pointer) b.AddRange([0xC0, 0x0C]);
        else { b.Add(32); b.AddRange(Encoding.ASCII.GetBytes("CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")); b.Add(0); }
        var rdata = new List<byte> { (byte)names.Length };
        foreach (var n in names)
        {
            rdata.AddRange(Encoding.ASCII.GetBytes(n.Name.PadRight(15)));
            rdata.Add(n.Suffix);
            rdata.Add((byte)(n.Group ? 0x84 : 0x04));
            rdata.Add(0);
        }
        rdata.AddRange([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        rdata.AddRange(new byte[40]);
        b.AddRange([0, 0x21, 0, 1, 0, 0, 0, 0, (byte)(rdata.Count >> 8), (byte)rdata.Count]);
        b.AddRange(rdata);
        return [.. b];
    }

    [Fact]
    public void Request_IsTheWildcardNodeStatusQuery()
    {
        byte[] expected =
        [
            0x80, 0x94, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, .. Enumerable.Repeat((byte)0x41, 30),
            0x00, 0x00, 0x21, 0x00, 0x01,
        ];
        Assert.Equal(expected, NetBiosNodeStatus.BuildRequest(0x8094));
    }

    [Theory]
    [InlineData(0, "PC-EXAMPLE", "WORKGROUP")]
    [InlineData(1, "PC-EXAMPLE", "WORKGROUP")]
    [InlineData(2, "NAS-EXAMPLE", "DOMAIN")]
    [InlineData(3, "PRINTER", null)]
    [InlineData(4, null, null)]
    public void Parse_PicksHostAndWorkgroup(int caseIndex, string? host, string? group)
    {
        (string, byte, bool)[][] cases =
        [
            HostAndGroup,
            [("WORKGROUP", 0x00, true), ("PC-EXAMPLE", 0x00, false)],
            [("NAS-EXAMPLE", 0x20, false), ("DOMAIN", 0x1E, true)],
            [("PRINTER", 0x00, false)],
            [],
        ];
        NetBiosNodeStatusResult? result = NetBiosNodeStatus.Parse(Response(0x1234, cases[caseIndex]), 0x1234);
        Assert.NotNull(result);
        Assert.Equal(host, result.HostName);
        Assert.Equal(group, result.Workgroup);
        Assert.Equal("02-00-00-00-00-01", result.UnitId);
    }

    [Fact]
    public void Parse_AcceptsCompressedName()
    {
        NetBiosNodeStatusResult? result = NetBiosNodeStatus.Parse(Response(7, HostAndGroup, pointer: true), 7);
        Assert.Equal("PC-EXAMPLE", result?.HostName);
        Assert.Equal("WORKGROUP", result?.Workgroup);
    }

    [Fact]
    public void Parse_RejectsForeignOrFailedAnswers()
    {
        Assert.Null(NetBiosNodeStatus.Parse(Response(7, HostAndGroup), 8));                  // other transaction
        Assert.Null(NetBiosNodeStatus.Parse(Response(7, HostAndGroup, flags: 0x8403), 7));   // RCODE set
        Assert.Null(NetBiosNodeStatus.Parse(Response(7, HostAndGroup, flags: 0x0000), 7));   // a request, not a response
    }

    [Fact]
    public void Parse_SurvivesDamagedResponses()
    {
        var random = new Random(5);
        byte[] good = Response(9, HostAndGroup);
        for (int i = 0; i < 200_000; i++)
        {
            byte[] d = random.Next(3) == 0 ? new byte[random.Next(0, 120)] : (byte[])good.Clone();
            if (random.Next(3) == 0) random.NextBytes(d);
            else for (int k = random.Next(1, 8); k > 0 && d.Length > 0; k--) d[random.Next(d.Length)] = (byte)random.Next(256);
            if (random.Next(4) == 0 && d.Length > 0) Array.Resize(ref d, random.Next(d.Length));
            NetBiosNodeStatus.Parse(d, 9);   // must not throw
        }
    }
}
