// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net;

namespace MyNetworkMonitor.Core.Tests;

/// <summary>
/// An address of the scanning machine itself takes the MAC of its adapter: no neighbor table lists it
/// (docs/FEHLERGEDAECHTNIS.md, No. 46).
/// </summary>
public class OwnMacTests
{
    private static readonly (IPAddress, byte[])[] Own =
    [
        (IPAddress.Parse("127.0.0.1"), []),
        (IPAddress.Parse("203.0.113.10"), [0x02, 0x00, 0x5E, 0x10, 0x00, 0x0A]),
        (IPAddress.Parse("198.51.100.5"), [0, 0, 0, 0, 0, 0])
    ];

    [Fact]
    public void OwnAddressTakesTheMacOfItsAdapter()
    {
        Assert.Equal("02-00-5e-10-00-0a", ScanningMethod_ARP.OwnMacOf(IPAddress.Parse("203.0.113.10"), Own));
    }

    [Theory]
    [InlineData("203.0.113.11")]   // another device in the same network
    [InlineData("127.0.0.1")]      // adapter without MAC
    [InlineData("198.51.100.5")]   // adapter with a MAC of zeros
    public void OtherAddressesAreLeftToArp(string ip)
    {
        Assert.Null(ScanningMethod_ARP.OwnMacOf(IPAddress.Parse(ip), Own));
    }
}

/// <summary>
/// Reading the ARP table reports every entry before it returns: the caller unsubscribes right after
/// (docs/FEHLERGEDAECHTNIS.md, No. 47).
/// </summary>
public class ArpTableTests
{
    private sealed class FixedTable(int count) : MyNetworkMonitor.Core.Services.IArpProvider
    {
        public Task<string?> ResolveMacAsync(IPAddress ip, CancellationToken cancellationToken = default) =>
            Task.FromResult<string?>(null);

        public Task<IReadOnlyList<MyNetworkMonitor.Core.Models.ArpEntry>> GetArpTableAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<MyNetworkMonitor.Core.Models.ArpEntry>>(
                [.. Enumerable.Range(1, count).Select(i => new MyNetworkMonitor.Core.Models.ArpEntry
                    { IpAddress = $"192.0.2.{i}", MacAddress = $"02-00-5e-10-00-{i:x2}" })]);

        public bool FlushArpCache() => true;
    }

    [Fact]
    public async Task EveryEntryIsReportedBeforeReadingEnds()
    {
        ScanningMethod_ARP arp = new(new FixedTable(200));
        List<IPToScan> targets = [.. Enumerable.Range(1, 200).Select(i => new IPToScan { IPorHostname = $"192.0.2.{i}" })];
        int reported = 0;
        void OnFound(object? _, ScanTask_Finished_EventArgs e)
        {
            Thread.Sleep(5);   // a subscriber that takes a moment, like the merge into the inventory
            Interlocked.Increment(ref reported);
        }

        arp.ARP_A_newDevice += OnFound;
        await arp.ARP_A(targets);
        arp.ARP_A_newDevice -= OnFound;
        int whenDone = Volatile.Read(ref reported);
        await Task.Delay(200);

        Assert.Equal(200, whenDone);
        Assert.Equal(200, Volatile.Read(ref reported));
    }
}
