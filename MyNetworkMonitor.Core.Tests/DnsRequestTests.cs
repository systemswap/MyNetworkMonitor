// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Text;
using MyNetworkMonitor.Core.Scanning.ServiceScans;

namespace MyNetworkMonitor.Core.Tests;

/// <summary><see cref="DnsRequest"/>: the query of the DNS probes (docs/FEHLERGEDAECHTNIS.md, No. 21).</summary>
public class DnsRequestTests
{
    [Fact]
    public void ProbeName_IsUnderTheReservedTopLevelDomainInvalid()
    {
        Assert.EndsWith(".invalid", DnsRequest.NonexistentName);
    }

    [Fact]
    public void Query_EncodesTheNameAsLabels()
    {
        byte[] query = DnsRequest.Build(DnsRequest.NonexistentName);
        var expected = new List<byte>();
        foreach (string label in DnsRequest.NonexistentName.Split('.'))
        {
            expected.Add((byte)label.Length);
            expected.AddRange(Encoding.ASCII.GetBytes(label));
        }
        expected.AddRange([0, 0, 1, 0, 1]);   // root, type A, class IN

        Assert.Equal(12 + expected.Count, query.Length);
        Assert.Equal(expected, query[12..]);
        Assert.Equal(1, query[5]);            // one question
    }

    [Fact]
    public void Answer_MustCarryTheIdAndTheResponseBit()
    {
        byte[] query = DnsRequest.Build(DnsRequest.NonexistentName);
        byte[] nxdomain = [query[0], query[1], 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0];
        Assert.True(DnsRequest.IsAnswerTo(query, nxdomain));
        Assert.False(DnsRequest.IsAnswerTo(query, [query[0], (byte)(query[1] ^ 1), 0x81, 0x83]));
        Assert.False(DnsRequest.IsAnswerTo(query, [query[0], query[1], 0x01, 0x00]));
    }
}
