// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
namespace MyNetworkMonitor.Core.Tests;

/// <summary>The SMB 3.1.1 negotiate request carries its negotiate context (docs/FEHLERGEDAECHTNIS.md, No. 31).</summary>
public class SmbNegotiationTests
{
    private static readonly byte[] Request = ScanningMethod_SMBVersionCheck.GetSMB311NegotiationRequest();

    private static int U16(int at) => Request[at] | (Request[at + 1] << 8);

    [Fact]
    public void TransportLength_MatchesThePacket()
    {
        Assert.Equal(0, Request[0]);
        Assert.Equal(Request.Length - 4, (Request[1] << 16) | (Request[2] << 8) | Request[3]);
    }

    [Fact]
    public void OffersOnly311()
    {
        const int body = 4 + 64;
        Assert.Equal(0x24, U16(body));          // StructureSize
        Assert.Equal(1, U16(body + 2));         // DialectCount
        Assert.Equal(0x0311, U16(body + 36));   // the dialect behind the fixed part
    }

    [Fact]
    public void PreauthIntegrityContext_IsWhereTheHeaderSaysAndFillsThePacket()
    {
        const int header = 4;                   // the SMB2 header starts behind the transport header
        int offset = Request[header + 64 + 28] | (Request[header + 64 + 29] << 8);
        int count = U16(header + 64 + 32);

        Assert.Equal(1, count);
        Assert.Equal(0, offset % 8);            // 8-byte aligned (MS-SMB2 2.2.3)

        int context = header + offset;
        Assert.Equal(1, U16(context));          // SMB2_PREAUTH_INTEGRITY_CAPABILITIES
        int dataLength = U16(context + 2);
        Assert.Equal(Request.Length, context + 8 + dataLength);
        Assert.Equal(1, U16(context + 8));      // one hash algorithm
        Assert.Equal(32, U16(context + 10));    // salt length
        Assert.Equal(1, U16(context + 12));     // SHA-512
    }
}
