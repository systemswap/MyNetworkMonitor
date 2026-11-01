// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using MyNetworkMonitor.Core.Scanning.ServiceScans;

namespace MyNetworkMonitor.Core.Tests;

/// <summary><see cref="DhcpProbe.GetDhcpServerIp"/>: the server of an offer (docs/FEHLERGEDAECHTNIS.md, No. 30).</summary>
public class DhcpProbeTests
{
    /// <summary>A BOOTP reply of 300 bytes with magic cookie and the given options.</summary>
    private static byte[] Offer(params byte[] options)
    {
        byte[] offer = new byte[300];
        offer[0] = 2;                                   // BOOTREPLY
        offer[236] = 0x63; offer[237] = 0x82; offer[238] = 0x53; offer[239] = 0x63;
        options.CopyTo(offer, 240);
        return offer;
    }

    [Fact]
    public void ServerIdentifier_IsReadFromTheOptionList()
    {
        // A byte 54 in the transaction ID and in the subnet mask option must
        // not be taken for the server identifier.
        byte[] offer = Offer(53, 1, 2, 0, 1, 4, 255, 255, 54, 0, 54, 4, 192, 0, 2, 1, 255);
        offer[4] = 54;

        Assert.Equal("192.0.2.1", DhcpProbe.GetDhcpServerIp(offer));
    }

    [Fact]
    public void WithoutServerIdentifier_TheRelayThenTheNextServerIsNamed()
    {
        byte[] offer = Offer(53, 1, 2, 255);
        offer[16] = 192; offer[17] = 0; offer[18] = 2; offer[19] = 9;        // siaddr
        Assert.Equal("192.0.2.9", DhcpProbe.GetDhcpServerIp(offer));

        offer[24] = 198; offer[25] = 51; offer[26] = 100; offer[27] = 7;     // giaddr
        Assert.Equal("198.51.100.7", DhcpProbe.GetDhcpServerIp(offer));
    }

    [Fact]
    public void RequestsAndDamagedAnswers_NameNoServer()
    {
        byte[] request = Offer(54, 4, 192, 0, 2, 1, 255);
        request[0] = 1;                                 // BOOTREQUEST
        Assert.Null(DhcpProbe.GetDhcpServerIp(request));

        // An option longer than the datagram, and every cut-off length.
        byte[] offer = Offer(12, 200, 0x61);
        for (int length = 0; length <= offer.Length; length++)
            DhcpProbe.GetDhcpServerIp(offer.AsSpan(0, length));
        Assert.Null(DhcpProbe.GetDhcpServerIp(offer));
    }
}
