// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Network;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Core.Tests;

/// <summary>The network label of a group in the 3D view comes from the configured range (docs/FEHLERGEDAECHTNIS.md, No. 35).</summary>
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
        Device device = new() { HostName = "pc-example", GroupDescription = "Office" };
        IpAddressAnalyzer.TryAnalyze("192.0.2.40", out IpAddressInfo? info);
        device.Addresses.Add(new DeviceAddress { Info = info! });

        string json = TopologyGraph.BuildGraphJson([device], new Dictionary<string, string> { ["Office"] = "192.0.2.32/27" });

        Assert.Contains("\"network\": \"192.0.2.32/27\"", json);
    }
}
