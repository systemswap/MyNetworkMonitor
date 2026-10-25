// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using MyNetworkMonitor.Core.Models;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Tests;

/// <summary>Wi-Fi signal conversion and nmcli parsing (docs/FEHLERGEDAECHTNIS.md, No. 24).</summary>
public class WifiTests
{
    [Theory]
    [InlineData(0, -100)]
    [InlineData(50, -75)]
    [InlineData(100, -50)]
    [InlineData(130, -50)]
    [InlineData(-5, -100)]
    public void WindowsQuality_FollowsWlanSignalQuality(int quality, int dbm)
    {
        Assert.Equal(dbm, WiFiSignalResult.WindowsQualityToDbm(quality));
    }

    [Theory]
    [InlineData(0, -100)]
    [InlineData(50, -70)]
    [InlineData(100, -40)]
    [InlineData(65, -61)]
    public void NetworkManagerSignal_IsTheInverseOfItsScale(int signal, int dbm)
    {
        Assert.Equal(dbm, WiFiSignalResult.NetworkManagerSignalToDbm(signal));
    }

    [Fact]
    public void NmcliTerse_KeepsEscapedSeparatorsInsideAValue()
    {
        Assert.Equal(["yes", "Cafe:Guest", "72"], NmcliTerse.SplitFields(@"yes:Cafe\:Guest:72"));
        Assert.Equal(["no", @"back\slash", "10"], NmcliTerse.SplitFields(@"no:back\\slash:10"));
        Assert.Equal(["yes", "", "40"], NmcliTerse.SplitFields("yes::40"));
        Assert.Equal([""], NmcliTerse.SplitFields(""));
    }
}
