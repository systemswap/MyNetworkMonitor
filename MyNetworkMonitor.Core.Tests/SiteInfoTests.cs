// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Tests;

/// <summary><see cref="SiteInfo.SuggestedRange"/>: the range a new scope starts with.</summary>
public class SiteInfoTests
{
    [Theory]
    [InlineData("192.0.2.77", 24, "192.0.2.1", "192.0.2.254")]
    [InlineData("198.51.100.200", 25, "198.51.100.129", "198.51.100.254")]
    [InlineData("203.0.113.9", 30, "203.0.113.9", "203.0.113.10")]
    [InlineData("10.20.30.40", 16, "10.20.30.1", "10.20.30.254")]   // narrowed to the /24 around the address
    [InlineData("10.20.30.40", 8, "10.20.30.1", "10.20.30.254")]
    public void SuggestedRange_IsTheHostsOfTheOwnNetwork(string address, int prefix, string first, string last)
    {
        Assert.Equal((first, last), SiteInfo.SuggestedRange(address, prefix));
    }

    [Theory]
    [InlineData("192.0.2.1", 31)]
    [InlineData("192.0.2.1", 32)]
    [InlineData("2001:db8::1", 64)]
    [InlineData("not an address", 24)]
    public void SuggestedRange_IsNullWithoutUsableHosts(string address, int prefix)
    {
        Assert.Null(SiteInfo.SuggestedRange(address, prefix));
    }
}
