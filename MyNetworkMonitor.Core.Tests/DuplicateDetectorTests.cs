// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.ViewModels;
using static MyNetworkMonitor.Core.Tests.DeviceStoreTests;

namespace MyNetworkMonitor.Core.Tests;

/// <summary>
/// What <see cref="DuplicateDetector"/> marks as assigned more than once, and which findings follow from it.
/// </summary>
public class DuplicateDetectorTests
{
    private static Device Only(DeviceStore store, string ip) => store.FindAllByAddress(Ip(ip)).Single();

    [Fact]
    public void SameAddressOnTwoDevicesIsMarkedOnBoth()
    {
        DeviceStore store = new();
        store.Observe(Seen("192.0.2.10", MacA));
        store.Observe(Seen("192.0.2.10", MacB));

        DuplicateDetector.Analyze(store.Devices);

        Assert.All(store.Devices, d => Assert.True(d.Conflicts.HasFlag(DeviceConflict.Address)));
    }

    [Fact]
    public void LinkLocalAddressesAreNeverDuplicates()
    {
        DeviceStore store = new();
        store.Observe(Seen("fe80::1", MacA));
        store.Observe(Seen("fe80::1", MacB));

        DuplicateDetector.Analyze(store.Devices);

        Assert.All(store.Devices, d => Assert.False(d.Conflicts.HasFlag(DeviceConflict.Address)));
    }

    [Fact]
    public void SameHostNameOnTwoDevicesIsMarked()
    {
        DeviceStore store = new();
        store.Observe(Seen("192.0.2.10", MacA, "Office", host: "drk-example"));
        store.Observe(Seen("198.51.100.10", MacB, "Plant", host: "drk-example"));

        DuplicateDetector.Analyze(store.Devices);

        Assert.All(store.Devices, d => Assert.True(d.Conflicts.HasFlag(DeviceConflict.HostName)));
    }

    [Fact]
    public void SeveralIpv4AddressesOnOneDeviceAreMarked()
    {
        DeviceStore store = new();
        store.Observe(Seen("192.0.2.10", MacA));
        store.Observe(Seen("192.0.2.11", MacA));

        DuplicateDetector.Analyze(store.Devices);

        Device device = Assert.Single(store.Devices);
        Assert.True(device.Conflicts.HasFlag(DeviceConflict.MultipleIpv4));
        Assert.Contains("192.0.2.10", device.ConflictDetails);
        Assert.Contains("192.0.2.11", device.ConflictDetails);
    }

    [Fact]
    public void Ipv4AndIpv6AddressesAreNoConflict()
    {
        DeviceStore store = new();
        store.Observe(Seen("192.0.2.10", MacA));
        store.Observe(Seen("2001:db8::10", MacA));
        store.Observe(Seen("2001:db8::11", MacA));

        DuplicateDetector.Analyze(store.Devices);

        Assert.Equal(DeviceConflict.None, Assert.Single(store.Devices).Conflicts);
    }

    [Fact]
    public void NamePointingToAnotherDeviceIsADnsMismatch()
    {
        DeviceStore store = new();
        store.Observe(Seen("192.0.2.10", MacA, host: "cam-example"));
        store.Observe(Seen("192.0.2.20", MacB, host: "cam-other"));
        store.Observe(new DeviceObservation
        {
            Source = "Reverse lookup", Address = Ip("192.0.2.10"), LookupAddresses = ["192.0.2.20"]
        });

        DuplicateDetector.Analyze(store.Devices);

        Assert.True(Only(store, "192.0.2.10").Conflicts.HasFlag(DeviceConflict.DnsMismatch));
        Assert.False(Only(store, "192.0.2.20").Conflicts.HasFlag(DeviceConflict.DnsMismatch));
    }

    [Fact]
    public void ResetClearsEveryMark()
    {
        DeviceStore store = new();
        store.Observe(Seen("192.0.2.10", MacA));
        store.Observe(Seen("192.0.2.10", MacB));
        DuplicateDetector.Analyze(store.Devices);

        DuplicateDetector.Reset(store.Devices);

        Assert.All(store.Devices, d => Assert.Equal(DeviceConflict.None, d.Conflicts));
    }

    [Theory]
    [InlineData("address", "Duplicate address", FindingSeverity.Critical)]
    [InlineData("name", "Duplicate host name", FindingSeverity.Warning)]
    [InlineData("several", "Several IPv4 addresses", FindingSeverity.Warning)]
    public void EachKindOfDuplicateBecomesAFinding(string kind, string title, FindingSeverity severity)
    {
        DeviceStore store = new();
        switch (kind)
        {
            case "address":
                store.Observe(Seen("192.0.2.10", MacA));
                store.Observe(Seen("192.0.2.10", MacB));
                break;
            case "name":
                store.Observe(Seen("192.0.2.10", MacA, host: "drk-example"));
                store.Observe(Seen("192.0.2.20", MacB, host: "drk-example"));
                break;
            default:
                store.Observe(Seen("192.0.2.10", MacA));
                store.Observe(Seen("192.0.2.11", MacA));
                break;
        }
        DuplicateDetector.Analyze(store.Devices);

        FindingsViewModel findings = new(store);
        findings.Refresh();
        List<Finding> addressing = [.. findings.Findings.Where(f => f.Category == FindingCategory.Addressing)];

        Assert.NotEmpty(addressing);
        Assert.All(addressing, f =>
        {
            Assert.Equal(title, f.Title);
            Assert.Equal(severity, f.Severity);
        });
    }
}
