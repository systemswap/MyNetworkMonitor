// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net.NetworkInformation;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;
using MyNetworkMonitor.Core.Persistence;

namespace MyNetworkMonitor.Core.Tests;

/// <summary>
/// How observations become devices: the identity cascade of <see cref="DeviceStore"/> (DUID, MAC,
/// derived and soft MAC, address, host name), loading and the merging of satellite results.
/// Addresses and names are invented (RFC 5737, RFC 3849, locally administered MACs).
/// </summary>
public class DeviceStoreTests
{
    internal const string MacA = "02-00-5E-10-00-0A";
    internal const string MacB = "02-00-5E-10-00-0B";

    internal static IpAddressInfo Ip(string text)
    {
        Assert.True(IpAddressAnalyzer.TryAnalyze(text, out IpAddressInfo? info));
        return info!;
    }

    internal static DeviceObservation Seen(string ip, string? mac = null, string? group = null, string? host = null,
                                           string source = "Test", string? softMac = null) => new()
    {
        Source = source,
        Address = Ip(ip),
        Mac = mac is null ? null : PhysicalAddress.Parse(mac),
        SoftMac = softMac is null ? null : PhysicalAddress.Parse(softMac),
        GroupDescription = group,
        HostName = host,
        IsResponding = true
    };

    [Fact]
    public void SameAddressAndMacIsOneDevice()
    {
        DeviceStore store = new();
        store.Observe(Seen("192.0.2.10", MacA, "Office"));
        store.Observe(Seen("192.0.2.10", MacA, "Office", host: "pc-example"));

        Device device = Assert.Single(store.Devices);
        Assert.Equal("pc-example", device.HostName);
    }

    [Fact]
    public void SameAddressWithDifferentMacsStaysTwoDevices()
    {
        DeviceStore store = new();
        store.Observe(Seen("192.0.2.10", MacA));
        store.Observe(Seen("192.0.2.10", MacB));

        Assert.Equal(2, store.Devices.Count);
        Assert.Equal(2, store.FindAllByAddress(Ip("192.0.2.10")).Count);
    }

    [Fact]
    public void ObservationWithoutMacJoinsTheDeviceAtItsAddress()
    {
        DeviceStore store = new();
        store.Observe(Seen("192.0.2.10", MacA));
        store.Observe(Seen("192.0.2.10", host: "pc-example"));

        Device device = Assert.Single(store.Devices);
        Assert.Equal("pc-example", device.HostName);
        Assert.Equal(PhysicalAddress.Parse(MacA), device.Mac);
    }

    [Fact]
    public void Ipv6AddressWithTheSameMacJoinsTheDevice()
    {
        DeviceStore store = new();
        store.Observe(Seen("192.0.2.10", MacA, "Office"));
        store.Observe(Seen("2001:db8::10", MacA, "Office", source: "IPv6 neighbour table"));
        store.Observe(Seen("fe80::10", MacA, "Office", source: "IPv6 neighbour table"));

        Device device = Assert.Single(store.Devices);
        Assert.Single(device.Ipv4Addresses);
        Assert.Equal(2, device.Ipv6Addresses.Count());
    }

    [Fact]
    public void Eui64AddressJoinsTheDeviceWithItsMac()
    {
        // Interface identifier 0000:5eff:fe10:000a: with the universal/local bit flipped back it is the
        // MAC 02-00-5E-10-00-0A (RFC 4291, appendix A)
        DeviceStore store = new();
        store.Observe(Seen("192.0.2.10", MacA));
        store.Observe(Seen("2001:db8::5eff:fe10:a", source: "IPv6 multicast ping"));

        Device device = Assert.Single(store.Devices);
        Assert.Equal(2, device.Addresses.Count);
    }

    [Fact]
    public void SoftMacFromSnmpConnectsButNeverSeparates()
    {
        DeviceStore store = new();
        store.Observe(Seen("192.0.2.10", MacA));
        store.Observe(Seen("192.0.2.20", softMac: MacA, source: "SNMP"));

        Device device = Assert.Single(store.Devices);
        Assert.Equal(2, device.Ipv4Addresses.Count());
    }

    [Fact]
    public void HostNameAloneJoinsOnlyWhenNothingElseMatches()
    {
        DeviceStore store = new();
        store.Observe(Seen("192.0.2.10", MacA, host: "pc-example"));
        store.Observe(new DeviceObservation { Source = "Test", HostName = "pc-example", Vendor = "Example Vendor" });

        Device device = Assert.Single(store.Devices);
        Assert.Equal("Example Vendor", device.Vendor);
    }

    /// <summary>
    /// Without a known network the MAC connects across ranges, as for inventories saved before addresses
    /// knew their network; with networks see <see cref="SameMacTests"/>.
    /// </summary>
    [Fact]
    public void SameMacWithoutKnownNetworkIsOneDevice()
    {
        DeviceStore store = new();
        store.Observe(Seen("192.0.2.10", MacA, "Office", host: "pc-example"));
        store.Observe(Seen("198.51.100.10", MacA, "Plant", host: "vm-example"));

        Device device = Assert.Single(store.Devices);
        Assert.Equal(2, device.Ipv4Addresses.Count());
    }

    /// <summary>Within one device the range name is the one of its last observation.</summary>
    [Fact]
    public void GroupIsTheOneOfTheLastObservation()
    {
        DeviceStore store = new();
        store.Observe(Seen("192.0.2.10", MacA, "Office"));
        store.Observe(Seen("198.51.100.10", MacA, "Plant"));

        Assert.Equal("Plant", Assert.Single(store.Devices).GroupDescription);
    }

    [Fact]
    public void LoadingKeepsDuplicateAssignmentsApart()
    {
        DeviceStore source = new();
        source.Observe(Seen("192.0.2.10", MacA));
        source.Observe(Seen("192.0.2.10", MacB));

        DeviceStore loaded = new();
        loaded.LoadFrom(DeviceStoreFile.FromJson(DeviceStoreFile.ToJson(source)));

        Assert.Equal(2, loaded.Devices.Count);
    }

    [Fact]
    public void SavedInventoryComesBackWithAddressesMacAndGroup()
    {
        DeviceStore source = new();
        source.Observe(Seen("192.0.2.10", MacA, "Office", host: "pc-example"));
        source.Observe(Seen("2001:db8::10", MacA, "Office"));

        Device device = Assert.Single(DeviceStoreFile.FromJson(DeviceStoreFile.ToJson(source)));

        Assert.Equal("pc-example", device.HostName);
        Assert.Equal("Office", device.GroupDescription);
        Assert.Equal(PhysicalAddress.Parse(MacA), device.Mac);
        Assert.Equal(["192.0.2.10", "2001:db8::10"], device.Addresses.Select(a => a.Info.Canonical).Order());
    }

    [Fact]
    public void SatelliteResultWithAKnownMacSupplementsTheDevice()
    {
        DeviceStore store = new();
        store.Observe(Seen("192.0.2.10", MacA, "Office", host: "pc-example"));

        DeviceStore satellite = new();
        satellite.Observe(Seen("198.51.100.10", MacA, "Plant", host: "vm-example"));
        store.MergeFrom(satellite.Devices.ToList());

        Device device = Assert.Single(store.Devices);
        Assert.Equal(2, device.Ipv4Addresses.Count());
    }

    [Fact]
    public void SatelliteResultWithAnUnknownDeviceIsAdded()
    {
        DeviceStore store = new();
        store.Observe(Seen("192.0.2.10", MacA, "Office"));

        DeviceStore satellite = new();
        satellite.Observe(Seen("198.51.100.10", MacB, "Plant"));
        store.MergeFrom(satellite.Devices.ToList());

        Assert.Equal(2, store.Devices.Count);
    }
}
