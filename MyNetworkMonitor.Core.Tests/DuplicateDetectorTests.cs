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

    // ------------------------------------------------- same MAC, spoofing, per line

    private static DeviceObservation In(string network, string ip, string mac, bool responding = true, string? host = null)
    {
        DeviceObservation o = new()
        {
            Source = "Test", Address = Ip(ip), Mac = System.Net.NetworkInformation.PhysicalAddress.Parse(mac),
            HostName = host, IsResponding = responding, NetworkId = network
        };
        return o;
    }

    private static List<Finding> Addressing(DeviceStore store, IReadOnlySet<string>? gateways = null)
    {
        DuplicateDetector.Analyze(store.Devices, gateways);
        FindingsViewModel findings = new(store);
        findings.Refresh();
        return [.. findings.Findings.Where(f => f.Category == FindingCategory.Addressing)];
    }

    /// <summary>Every line keeps its own title and severity (docs/FEHLERGEDAECHTNIS.md, No. 39).</summary>
    [Fact]
    public void EachLineOfADeviceKeepsItsOwnTitle()
    {
        DeviceStore store = new();
        store.Observe(Seen("192.0.2.10", MacA, host: "drk-example"));
        store.Observe(Seen("192.0.2.10", MacB, host: "drk-example"));

        List<Finding> found = Addressing(store);

        Assert.Equal(2, found.Count(f => f.Title == "Duplicate address" && f.Severity == FindingSeverity.Critical));
        Assert.Equal(2, found.Count(f => f.Title == "Duplicate host name" && f.Severity == FindingSeverity.Warning));
    }

    [Fact]
    public void SameMacAnsweringInTwoNetworksIsAWarning()
    {
        DeviceStore store = new();
        store.Observe(In("office", "192.0.2.53", MacA, host: "pc-example"));
        store.Observe(In("plant", "198.51.100.21", MacA, host: "vm-clone"));

        List<Finding> found = Addressing(store);

        Assert.All(store.Devices, d => Assert.True(d.Conflicts.HasFlag(DeviceConflict.SameMacInOtherNetwork)));
        Assert.Equal(2, found.Count(f => f.Title == "Same MAC in another network" && f.Severity == FindingSeverity.Warning));
        Assert.Contains(found, f => f.Detail.Contains("vm-clone") && f.Subject == "pc-example");
    }

    [Fact]
    public void SameMacOfADeviceThatMovedIsANote()
    {
        DeviceStore store = new();
        store.Observe(In("office", "192.0.2.53", MacA, responding: false, host: "nb-example"));
        store.Observe(In("wifi", "198.51.100.21", MacA, host: "nb-example"));

        List<Finding> found = Addressing(store);

        Assert.Contains(found, f => f.Title == "MAC seen in another network" && f.Severity == FindingSeverity.Note);
        Assert.DoesNotContain(found, f => f.Title == "Same MAC in another network");
    }

    [Fact]
    public void ForeignMacOnAnAddressWithItsOwnDeviceIsSuspectedSpoofing()
    {
        DeviceStore store = new();
        store.Observe(In("office", "192.0.2.1", MacB, host: "gw-example"));      // the real gateway
        store.Observe(In("office", "192.0.2.66", MacA, host: "pc-attacker"));
        store.Observe(In("office", "192.0.2.1", MacA));                          // pc-attacker answers for the gateway

        List<Finding> found = Addressing(store);

        Device attacker = store.Devices.Single(d => d.HostName == "pc-attacker");
        Assert.True(attacker.Conflicts.HasFlag(DeviceConflict.SuspectedArpSpoofing));
        Assert.Contains(found, f => f.Title == "Suspected ARP spoofing" && f.Severity == FindingSeverity.Critical && f.Subject == "pc-attacker");
        Assert.Contains(found, f => f.Title == "Duplicate address" && f.Subject == "gw-example");
    }

    [Fact]
    public void SeveralAddressesIncludingTheGatewayAreNamedButNotCritical()
    {
        // a router with a second address on the same interface looks the same - without a second
        // device holding the gateway address it stays a warning
        DeviceStore store = new();
        store.Observe(In("office", "192.0.2.1", MacA));
        store.Observe(In("office", "192.0.2.5", MacA));

        List<Finding> found = Addressing(store, new HashSet<string> { "192.0.2.1" });

        Finding finding = Assert.Single(found);
        Assert.Equal("Several IPv4 addresses", finding.Title);
        Assert.Equal(FindingSeverity.Warning, finding.Severity);
        Assert.Contains("including the gateway 192.0.2.1", finding.Detail);
        Assert.Contains("ARP spoofing", finding.Detail);
    }

    [Fact]
    public void VirtualRouterMacInTwoNetworksIsNoMacFinding()
    {
        DeviceStore store = new();
        store.Observe(In("office", "192.0.2.1", "00-00-5E-00-01-01"));
        store.Observe(In("plant", "198.51.100.1", "00-00-5E-00-01-01"));

        List<Finding> found = Addressing(store);

        Assert.DoesNotContain(found, f => f.Title.Contains("MAC"));
    }
}
