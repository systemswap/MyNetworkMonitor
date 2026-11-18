// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using MyNetworkMonitor.Core.Network;
using Xunit;

namespace MyNetworkMonitor.Core.Tests;

/// <summary>
/// Which addresses count as globally reachable - IPv4 and IPv6 alike, after the IANA special-purpose
/// registries (docs/FEHLERGEDAECHTNIS.md, No. 34).
/// </summary>
public class IpAddressScopeTests
{
    [Theory]
    [InlineData("192.0.2.10", IpAddressSpecial.Documentation)]
    [InlineData("198.51.100.200", IpAddressSpecial.Documentation)]
    [InlineData("203.0.113.1", IpAddressSpecial.Documentation)]
    [InlineData("198.18.0.1", IpAddressSpecial.Benchmarking)]
    [InlineData("198.19.255.254", IpAddressSpecial.Benchmarking)]
    [InlineData("2001:db8::1", IpAddressSpecial.Documentation)]
    public void DocumentationAndBenchmarkingRangesAreNotGlobal(string text, IpAddressSpecial expected)
    {
        Assert.True(IpAddressAnalyzer.TryAnalyze(text, out IpAddressInfo? info));

        Assert.Equal(expected, info!.Special);
        Assert.False(info.IsGloballyRoutable);
    }

    [Theory]
    [InlineData("192.0.3.1")]
    [InlineData("198.51.101.1")]
    [InlineData("198.20.0.1")]
    [InlineData("203.0.114.1")]
    [InlineData("8.8.8.8")]
    public void NeighbouringPublicAddressesStayGlobal(string text)
    {
        Assert.True(IpAddressAnalyzer.TryAnalyze(text, out IpAddressInfo? info));

        Assert.Equal(IpAddressSpecial.None, info!.Special);
        Assert.True(info.IsGloballyRoutable);
    }

    [Theory]
    [InlineData("10.1.2.3")]
    [InlineData("192.168.1.1")]
    public void PrivateAddressesAreNotGlobal(string text)
    {
        Assert.True(IpAddressAnalyzer.TryAnalyze(text, out IpAddressInfo? info));

        Assert.False(info!.IsGloballyRoutable);
    }
}
