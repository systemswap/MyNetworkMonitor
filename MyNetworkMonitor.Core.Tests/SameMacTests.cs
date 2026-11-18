// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net.NetworkInformation;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Persistence;
using static MyNetworkMonitor.Core.Tests.DeviceStoreTests;

namespace MyNetworkMonitor.Core.Tests;

/// <summary>
/// A MAC identifies a device only within its network (docs/FEHLERGEDAECHTNIS.md, No. 36): the same MAC
/// in two networks is two devices, within one network it is one device with several addresses.
/// </summary>
public class SameMacTests
{
    private const string Office = "office", Plant = "plant";

    private static DeviceObservation In(string network, string ip, string? mac = null, string? group = null,
                                        string? host = null, string source = "Test")
    {
        DeviceObservation o = Seen(ip, mac, group, host, source);
        o.NetworkId = network;
        return o;
    }

    [Fact]
    public void SameMacInTwoNetworksIsTwoDevices()
    {
        DeviceStore store = new();
        store.Observe(In(Office, "192.0.2.53", MacA, "Office", "pc-example"));
        store.Observe(In(Plant, "198.51.100.21", MacA, "Plant", "vm-clone"));

        Assert.Equal(2, store.Devices.Count);
        Assert.Equal(["pc-example", "vm-clone"], store.Devices.Select(d => d.HostName).Order());
        Assert.Equal(["Office", "Plant"], store.Devices.Select(d => d.GroupDescription).Order());
    }

    [Fact]
    public void SameMacWithAnotherAddressInTheSameNetworkIsOneDevice()
    {
        DeviceStore store = new();
        store.Observe(In(Office, "192.0.2.53", MacA));
        store.Observe(In(Office, "192.0.2.54", MacA));

        Assert.Equal(2, Assert.Single(store.Devices).Ipv4Addresses.Count());
    }

    [Fact]
    public void Ipv6OfTheSameNetworkJoinsTheDevice()
    {
        DeviceStore store = new();
        store.Observe(In(Office, "192.0.2.53", MacA));
        store.Observe(In(Office, "2001:db8:10::53", MacA, source: "IPv6 neighbour table"));
        store.Observe(In(Office, "fe80::53", MacA, source: "IPv6 neighbour table"));

        Assert.Equal(3, Assert.Single(store.Devices).Addresses.Count);
    }

    [Fact]
    public void ObservationWithoutNetworkFindsTheDevice()
    {
        // a rescan runs over a target list, which carries no network
        DeviceStore store = new();
        store.Observe(In(Office, "192.0.2.53", MacA));
        store.Observe(In(Plant, "198.51.100.21", MacA));
        store.Observe(Seen("192.0.2.53", MacA, host: "pc-example"));

        Assert.Equal(2, store.Devices.Count);
        Assert.Equal("pc-example", store.FindAllByAddress(Ip("192.0.2.53")).Single().HostName);
        Assert.Equal(Office, store.FindAllByAddress(Ip("192.0.2.53")).Single().Addresses.Single().NetworkId);
    }

    [Fact]
    public void DerivedMacConnectsOnlyWithinTheNetwork()
    {
        // the interface identifier 0000:5eff:fe10:000a carries the MAC 02-00-5E-10-00-0A
        DeviceStore store = new();
        store.Observe(In(Office, "192.0.2.53", MacA));
        store.Observe(In(Office, "2001:db8:10::5eff:fe10:a", source: "IPv6 multicast ping"));
        store.Observe(In(Plant, "2001:db8:30::5eff:fe10:a", source: "IPv6 multicast ping"));

        Device office = store.FindAllByAddress(Ip("192.0.2.53")).Single();
        Assert.Equal(2, office.Addresses.Count);
        Assert.Equal(2, store.Devices.Count);
    }

    [Theory]
    [InlineData("00-00-5E-00-01-01")]   // VRRP IPv4
    [InlineData("00-00-5E-00-02-01")]   // VRRP IPv6
    [InlineData("00-00-0C-07-AC-01")]   // HSRP version 1
    [InlineData("00-00-0C-9F-F0-01")]   // HSRP version 2
    [InlineData("02-BF-C0-00-02-0A")]   // Windows NLB unicast
    public void VirtualRouterMacsIdentifyNobody(string mac)
    {
        Assert.False(DeviceStore.IsIdentifying(PhysicalAddress.Parse(mac)));

        DeviceStore store = new();
        store.Observe(In(Office, "192.0.2.1", mac));
        store.Observe(In(Office, "192.0.2.2", mac));

        Assert.Equal(2, store.Devices.Count);
    }

    [Fact]
    public void OrdinaryMacIdentifies()
    {
        Assert.True(DeviceStore.IsIdentifying(PhysicalAddress.Parse(MacA)));
        Assert.True(DeviceStore.IsIdentifying(PhysicalAddress.Parse("00-00-5E-00-53-01")));   // documentation MAC (RFC 7042)
    }

    [Fact]
    public void SameMacAtTwoSitesSurvivesSavingAndLoading()
    {
        DeviceStore store = new();
        store.Observe(In(Office, "192.0.2.53", MacA));
        store.Observe(In(Plant, "198.51.100.21", MacA));

        DeviceStore loaded = new();
        loaded.LoadFrom(DeviceStoreFile.FromJson(DeviceStoreFile.ToJson(store)));
        loaded.Observe(In(Plant, "198.51.100.21", MacA, host: "vm-clone"));

        Assert.Equal(2, loaded.Devices.Count);
        Assert.Equal("vm-clone", loaded.FindAllByAddress(Ip("198.51.100.21")).Single().HostName);
    }

    // ---------------------------------------------------------------- satellites

    private static ScanScope Range(string group, string first, string last, string? scannedBy = null) =>
        new() { Kind = ScanScopeKind.IPv4Range, GroupDescription = group, FirstIP = first, LastIP = last, ScannedBy = scannedBy ?? string.Empty };

    private static List<Device> SatelliteReport(params DeviceObservation[] observations)
    {
        DeviceStore satellite = new();
        foreach (DeviceObservation o in observations) satellite.Observe(o);
        return DeviceStoreFile.FromJson(DeviceStoreFile.ToJson(satellite));
    }

    [Fact]
    public void SatelliteResultTakesTheRangesOfTheMainScanner()
    {
        ScanScope plant = Range("Plant", "198.51.100.1", "198.51.100.30", "sat-1");
        List<Device> report = SatelliteReport(
            In("job-of-the-satellite", "198.51.100.21", MacA, "Satellite"),
            In("job-of-the-satellite", "2001:db8:30::21", MacA, "Satellite"),
            In("job-of-the-satellite", "203.0.113.9", MacB, "Satellite"));

        NetworkIds.AdoptSatelliteResult(report, [plant], "satellite-sat-1");

        Device inPlant = report.Single(d => d.Ipv4Addresses.Any(a => a.Info.Canonical == "198.51.100.21"));
        Assert.Equal("Plant", inPlant.GroupDescription);
        Assert.All(inPlant.Addresses, a => Assert.Equal(plant.Id.ToString("N"), a.NetworkId));

        Device outside = report.Single(d => d.Ipv4Addresses.Any(a => a.Info.Canonical == "203.0.113.9"));
        Assert.Equal("satellite-sat-1:job-of-the-satellite", outside.Addresses.Single().NetworkId);
    }

    [Fact]
    public void SatelliteDeviceWithAMacOfAnotherNetworkStaysApart()
    {
        ScanScope office = Range("Office", "192.0.2.33", "192.0.2.62");
        ScanScope plant = Range("Plant", "198.51.100.1", "198.51.100.30", "sat-1");
        DeviceStore store = new();
        store.Observe(In(office.Id.ToString("N"), "192.0.2.53", MacA, "Office", "pc-example"));

        List<Device> report = SatelliteReport(In("job", "198.51.100.21", MacA, "Satellite", "vm-clone"));
        NetworkIds.AdoptSatelliteResult(report, [plant, office], "satellite-sat-1");
        store.MergeFrom(report);

        Assert.Equal(2, store.Devices.Count);
        Assert.Equal("Plant", store.FindAllByAddress(Ip("198.51.100.21")).Single().GroupDescription);
    }

    [Fact]
    public void SatelliteDeviceAlreadyScannedFromHereIsTheSameDevice()
    {
        // the main scanner scanned the satellite's range itself earlier (satellite not connected)
        ScanScope plant = Range("Plant", "198.51.100.1", "198.51.100.30", "sat-1");
        DeviceStore store = new();
        store.Observe(In(plant.Id.ToString("N"), "198.51.100.21", MacA, "Plant"));

        List<Device> report = SatelliteReport(In("job", "198.51.100.21", MacA, "Satellite", "vm-clone"));
        NetworkIds.AdoptSatelliteResult(report, [plant], "satellite-sat-1");
        store.MergeFrom(report);

        Device device = Assert.Single(store.Devices);
        Assert.Equal("vm-clone", device.HostName);
    }
}
