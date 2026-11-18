// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using MyNetworkMonitor;
using Xunit;

namespace MyNetworkMonitor.Core.Tests;

/// <summary>Reading the lines of the MAC vendor list (docs/FEHLERGEDAECHTNIS.md, No. 33).</summary>
public class MacVendorCsvTests
{
    [Fact]
    public void VendorWithCommaLosesTheQuotesOfTheFileFormat()
    {
        string[] fields = SupportMethods.SplitCsvLine("00:00:0C,\"Cisco Systems, Inc\",false,MA-L,2026/10/25");

        Assert.Equal(["00:00:0C", "Cisco Systems, Inc", "false", "MA-L", "2026/10/25"], fields);
    }

    [Fact]
    public void PlainVendorStaysAsItIs()
    {
        string[] fields = SupportMethods.SplitCsvLine("00:01:E3,Siemens AG,false,MA-L,2026/10/25");

        Assert.Equal("Siemens AG", fields[1]);
        Assert.Equal(5, fields.Length);
    }

    [Fact]
    public void DoubledQuoteInsideAFieldBecomesOne()
    {
        string[] fields = SupportMethods.SplitCsvLine("00:00:00,\"Officially Xerox, but \"\"0:0:0\"\" is common\",false");

        Assert.Equal("Officially Xerox, but \"0:0:0\" is common", fields[1]);
    }
}
