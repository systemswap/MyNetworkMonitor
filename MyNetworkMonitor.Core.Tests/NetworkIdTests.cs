// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;
using MyNetworkMonitor.Core.Persistence;
using MyNetworkMonitor.Core.Scanning.Engine;
using static MyNetworkMonitor.Core.Tests.DeviceStoreTests;

namespace MyNetworkMonitor.Core.Tests;

/// <summary>
/// Every address knows the network it was seen in (<see cref="NetworkIds"/>): from the range it was
/// scanned through, kept by the inventory, saved with it, and filled in for inventories without it.
/// </summary>
public class NetworkIdTests
{
    private static ScanScope Range(string group, string first, string last) =>
        new() { Kind = ScanScopeKind.IPv4Range, GroupDescription = group, FirstIP = first, LastIP = last };

    private static readonly (IPAddress, IPAddress)[] TwoSubnets =
    [
        (IPAddress.Parse("192.0.2.25"), IPAddress.Parse("255.255.255.224")),
        (IPAddress.Parse("198.51.100.5"), IPAddress.Parse("255.255.255.0"))
    ];

    [Fact]
    public void RangeKeyIsTheIdOfTheRange()
    {
        ScanScope range = Range("Office", "192.0.2.33", "192.0.2.62");

        Assert.Equal(range.Id.ToString("N"), NetworkIds.For(range, IPAddress.Parse("192.0.2.40"), null));
    }

    [Fact]
    public void TargetListHasNoKey()
    {
        ScanScope list = new() { Kind = ScanScopeKind.TargetList, GroupDescription = "Rescan" };

        Assert.Null(NetworkIds.For(list, IPAddress.Parse("192.0.2.40"), null));
    }

    [Theory]
    [InlineData("192.0.2.7", "192.0.2.0/27")]
    [InlineData("198.51.100.77", "198.51.100.0/24")]
    [InlineData("2001:db8::7", "192.0.2.0/27")]
    public void OwnInterfaceKeyCarriesTheSubnetOfTheAddress(string address, string subnet)
    {
        ScanScope local = new() { Kind = ScanScopeKind.NetworkInterface, GroupDescription = "Local network" };

        Assert.Equal($"{local.Id:N}@{subnet}", NetworkIds.For(local, IPAddress.Parse(address), TwoSubnets));
    }

    [Fact]
    public void AddressOutsideEveryInterfaceSubnetHasNoSubnet()
    {
        Assert.Null(NetworkIds.SubnetOf(IPAddress.Parse("203.0.113.1"), TwoSubnets));
    }

    [Fact]
    public void InventoryKeepsTheNetworkOfAnAddress()
    {
        DeviceStore store = new();
        DeviceObservation first = Seen("192.0.2.40", MacA, "Office");
        first.NetworkId = "office";
        store.Observe(first);

        // a target list (rescan) carries no network: the address keeps the one it had
        store.Observe(Seen("192.0.2.40", MacA, "Rescan"));

        Assert.Equal("office", Assert.Single(Assert.Single(store.Devices).Addresses).NetworkId);
    }

    [Fact]
    public void NetworkIsSavedAndLoaded()
    {
        DeviceStore store = new();
        DeviceObservation observation = Seen("192.0.2.40", MacA);
        observation.NetworkId = "office";
        store.Observe(observation);

        Device loaded = Assert.Single(DeviceStoreFile.FromJson(DeviceStoreFile.ToJson(store)));

        Assert.Equal("office", Assert.Single(loaded.Addresses).NetworkId);
    }

    [Fact]
    public void InventoryWithoutNetworksStillLoads()
    {
        const string old = """
            [{ "Mac": "02005E10000A", "HostName": "pc-example",
               "Addresses": [ { "Address": "192.0.2.40" } ] }]
            """;

        Device loaded = Assert.Single(DeviceStoreFile.FromJson(old));

        Assert.Null(Assert.Single(loaded.Addresses).NetworkId);
    }

    [Fact]
    public void MissingNetworksAreFilledFromTheRanges()
    {
        ScanScope server = Range("Server", "192.0.2.1", "192.0.2.30");
        ScanScope office = Range("Office", "192.0.2.33", "192.0.2.62");
        DeviceStore store = new();
        store.Observe(Seen("192.0.2.40", MacA));
        store.Observe(Seen("2001:db8::40", MacA));
        store.Observe(Seen("203.0.113.9", MacB));

        int filled = NetworkIds.FillMissing(store.Devices, [server, office]);

        Device pc = store.FindAllByAddress(Ip("192.0.2.40")).Single();
        Assert.All(pc.Addresses, a => Assert.Equal(office.Id.ToString("N"), a.NetworkId));
        Assert.Null(store.FindAllByAddress(Ip("203.0.113.9")).Single().Addresses.Single().NetworkId);
        Assert.Equal(2, filled);
    }

    [Fact]
    public void Ipv6StaysWithoutNetworkWhenTheIpv4AddressesDisagree()
    {
        DeviceStore store = new();
        store.Observe(Seen("192.0.2.5", MacA));
        store.Observe(Seen("192.0.2.40", MacA));
        store.Observe(Seen("2001:db8::40", MacA));

        NetworkIds.FillMissing(store.Devices, [Range("Server", "192.0.2.1", "192.0.2.30"), Range("Office", "192.0.2.33", "192.0.2.62")]);

        Assert.Null(Assert.Single(store.Devices).Ipv6Addresses.Single().NetworkId);
    }

    [Fact]
    public void FillingKeepsKnownNetworks()
    {
        DeviceStore store = new();
        DeviceObservation observation = Seen("192.0.2.40", MacA);
        observation.NetworkId = "seen-in-the-scan";
        store.Observe(observation);

        NetworkIds.FillMissing(store.Devices, [Range("Office", "192.0.2.33", "192.0.2.62")]);

        Assert.Equal("seen-in-the-scan", Assert.Single(store.Devices).Addresses.Single().NetworkId);
    }

    [Fact]
    public void EngineGivesEveryTargetTheNetworkOfItsFirstScope()
    {
        ScanScope office = Range("Office", "192.0.2.33", "192.0.2.62");
        ScanScope rescan = new() { Kind = ScanScopeKind.TargetList, GroupDescription = "Rescan" };
        Ipv6Readiness none = new() { Availability = Ipv6Availability.Unknown, Reason = "test" };
        ScopeRuntime officeRun = new() { Scope = office, Ipv6 = none };
        ScopeRuntime rescanRun = new() { Scope = rescan, Ipv6 = none };

        Dictionary<string, string> networks = ScanEngine.TargetNetworks(
        [
            new ScanTargetEntry { Address = Ip("192.0.2.40"), Scope = officeRun },
            new ScanTargetEntry { Address = Ip("192.0.2.40"), Scope = rescanRun },
            new ScanTargetEntry { Address = Ip("203.0.113.9"), Scope = rescanRun },
            new ScanTargetEntry { HostName = "pc-example", Scope = officeRun }
        ]);

        Assert.Equal(office.Id.ToString("N"), Assert.Single(networks).Value);
        Assert.Equal("192.0.2.40", networks.Keys.Single());
    }
}
