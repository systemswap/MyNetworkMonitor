// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net;

namespace MyNetworkMonitor.Core.Tests;

/// <summary>
/// An address of the scanning machine itself takes the MAC of its adapter: no neighbor table lists it
/// (docs/FEHLERGEDAECHTNIS.md, No. 46).
/// </summary>
public class OwnMacTests
{
    private static readonly (IPAddress, byte[])[] Own =
    [
        (IPAddress.Parse("127.0.0.1"), []),
        (IPAddress.Parse("203.0.113.10"), [0x02, 0x00, 0x5E, 0x10, 0x00, 0x0A]),
        (IPAddress.Parse("198.51.100.5"), [0, 0, 0, 0, 0, 0])
    ];

    [Fact]
    public void OwnAddressTakesTheMacOfItsAdapter()
    {
        Assert.Equal("02-00-5e-10-00-0a", ScanningMethod_ARP.OwnMacOf(IPAddress.Parse("203.0.113.10"), Own));
    }

    [Theory]
    [InlineData("203.0.113.11")]   // another device in the same network
    [InlineData("127.0.0.1")]      // adapter without MAC
    [InlineData("198.51.100.5")]   // adapter with a MAC of zeros
    public void OtherAddressesAreLeftToArp(string ip)
    {
        Assert.Null(ScanningMethod_ARP.OwnMacOf(IPAddress.Parse(ip), Own));
    }
}
