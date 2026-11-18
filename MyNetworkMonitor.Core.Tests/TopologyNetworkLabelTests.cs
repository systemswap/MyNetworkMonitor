// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;
using MyNetworkMonitor.Core.Services;
using Newtonsoft.Json.Linq;

namespace MyNetworkMonitor.Core.Tests;

/// <summary>The 3D network view and the configured ranges: network labels (docs/FEHLERGEDAECHTNIS.md, No. 35) and the same MAC in two networks (No. 36).</summary>
public class TopologyNetworkLabelTests
{
    [Theory]
    [InlineData("192.0.2.1", "192.0.2.30", "192.0.2.0/27")]
    [InlineData("192.0.2.33", "192.0.2.62", "192.0.2.32/27")]
    [InlineData("192.0.2.0", "192.0.2.255", "192.0.2.0/24")]
    [InlineData("198.51.100.1", "198.51.101.254", "198.51.100.0/23")]
    [InlineData("203.0.113.129", "203.0.113.254", "203.0.113.128/25")]
    [InlineData("192.0.2.10", "192.0.2.20", "192.0.2.10 - 192.0.2.20")]
    [InlineData("192.0.2.7", "192.0.2.7", "192.0.2.7")]
    [InlineData("192.0.2.20", "192.0.2.10", "")]
    [InlineData("2001:db8::1", "2001:db8::ff", "")]
    [InlineData("", "192.0.2.1", "")]
    public void RangeIsNamedAsItsNetwork(string first, string last, string expected)
    {
        Assert.Equal(expected, TopologyGraph.DescribeRange(first, last));
    }

    [Fact]
    public void ConfiguredNetworkGoesIntoTheGraph()
    {
        Device device = Make("pc-example", "Office", null, "192.0.2.40");

        string json = TopologyGraph.BuildGraphJson([device], [new TopologyRange("Office", "192.0.2.33", "192.0.2.62")]);

        Assert.Contains("\"network\": \"192.0.2.32/27\"", json);
    }

    /// <summary>
    /// The inventory merges the same MAC into one device; the graph must still show the second network
    /// it turned up in, joined by a "same MAC" edge (docs/FEHLERGEDAECHTNIS.md, No. 36).
    /// </summary>
    [Fact]
    public void SameMacInTwoNetworksConnectsThem()
    {
        Device clone = Make("pc-example", "Office", "02-00-5E-10-00-01", "192.0.2.40", "192.0.2.10");
        Device other = Make("srv-example", "Server", "02-00-5E-10-00-02", "192.0.2.5");

        JObject graph = JObject.Parse(TopologyGraph.BuildGraphJson([clone, other],
        [
            new TopologyRange("Server", "192.0.2.1", "192.0.2.30"),
            new TopologyRange("Office", "192.0.2.33", "192.0.2.62")
        ]));

        var nodes = graph["nodes"]!.ToDictionary(n => (string)n["id"]!, n => (Group: (string)n["group"]!, Ip: (string)n["ip"]!));
        Assert.Equal(3, nodes.Count);
        string inServer = nodes.Single(n => n.Value.Ip == "192.0.2.10").Key;
        string inOffice = nodes.Single(n => n.Value.Ip == "192.0.2.40").Key;
        Assert.Equal("Server", nodes[inServer].Group);
        Assert.Equal("Office", nodes[inOffice].Group);

        var macLinks = graph["links"]!.Where(l => (bool)l["isDuplicatedMac"]!)
                                      .Select(l => ((string)l["source"]!, (string)l["target"]!)).ToList();
        Assert.Contains((inServer, inOffice), macLinks);
        Assert.Contains((inOffice, inServer), macLinks);
        Assert.Equal(2, macLinks.Count);
    }

    /// <summary>Two devices of different networks with the same MAC are joined by "same MAC" edges.</summary>
    [Fact]
    public void SameMacOnDevicesOfTwoNetworksConnectsThem()
    {
        Device pc = Make("pc-example", "Office", "02-00-5E-10-00-01", "192.0.2.40");
        Device clone = Make("vm-clone", "Server", "02-00-5E-10-00-01", "192.0.2.10");

        JObject graph = JObject.Parse(TopologyGraph.BuildGraphJson([pc, clone],
        [
            new TopologyRange("Server", "192.0.2.1", "192.0.2.30"),
            new TopologyRange("Office", "192.0.2.33", "192.0.2.62")
        ]));

        Assert.Equal(2, graph["nodes"]!.Count());
        Assert.Equal(2, graph["links"]!.Count(l => (bool)l["isDuplicatedMac"]!));
    }

    [Fact]
    public void VirtualRouterMacDrawsNoMacEdge()
    {
        Device first = Make("gw-a", "Office", "00-00-5E-00-01-01", "192.0.2.33");
        Device second = Make("gw-b", "Server", "00-00-5E-00-01-01", "192.0.2.1");

        JObject graph = JObject.Parse(TopologyGraph.BuildGraphJson([first, second], (IReadOnlyList<TopologyRange>?)null));

        Assert.DoesNotContain(graph["links"]!, l => (bool)l["isDuplicatedMac"]!);
    }

    [Fact]
    public void DeviceWithOneAddressHasOneNode()
    {
        JObject graph = JObject.Parse(TopologyGraph.BuildGraphJson([Make("pc-example", "Office", "02-00-5E-10-00-01", "192.0.2.40")],
                                                                    [new TopologyRange("Office", "192.0.2.33", "192.0.2.62")]));

        Assert.Single(graph["nodes"]!);
        Assert.DoesNotContain(graph["links"]!, l => (bool)l["isDuplicatedMac"]!);
    }

    private static Device Make(string name, string group, string? mac, params string[] addresses)
    {
        Device device = new() { HostName = name, GroupDescription = group };
        if (mac is not null) device.Mac = System.Net.NetworkInformation.PhysicalAddress.Parse(mac);
        foreach (string text in addresses)
        {
            IpAddressAnalyzer.TryAnalyze(text, out IpAddressInfo? info);
            device.Addresses.Add(new DeviceAddress { Info = info! });
        }
        return device;
    }
}
