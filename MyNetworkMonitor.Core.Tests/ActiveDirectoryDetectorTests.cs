// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Net;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Core.Tests;

/// <summary><see cref="ActiveDirectoryDetector"/>: which servers and domains are asked (docs/FEHLERGEDAECHTNIS.md, No. 26).</summary>
public class ActiveDirectoryDetectorTests
{
    [Theory]
    [InlineData("127.0.0.53", true)]
    [InlineData("192.168.178.1", true)]
    [InlineData("fd00::1", true)]
    [InlineData("192.0.2.53", true)]        // a company's own server on a public range is still asked
    [InlineData("8.8.8.8", false)]
    [InlineData("1.1.1.1", false)]
    [InlineData("9.9.9.9", false)]
    [InlineData("208.67.222.222", false)]
    [InlineData("2001:4860:4860::8888", false)]
    [InlineData("::ffff:1.0.0.1", false)]
    public void AllNameServersButThePublicResolversAreAsked(string server, bool asked)
    {
        Assert.Equal(asked, !ActiveDirectoryDetector.IsPublicResolver(IPAddress.Parse(server)));
    }

    [Theory]
    [InlineData("fritz.box", true)]
    [InlineData("speedport.ip", true)]
    [InlineData("lan", true)]
    [InlineData("home", true)]
    [InlineData("localdomain", true)]
    [InlineData("local", true)]
    [InlineData("lab.test", true)]
    [InlineData("home.arpa", true)]
    [InlineData("site.home.arpa", true)]
    [InlineData("", true)]
    [InlineData("corp.example.com", false)]
    [InlineData("ad.example.org.", false)]
    [InlineData("example.de", false)]
    [InlineData("company.local", false)]   // a common Active Directory domain
    [InlineData("company.lan", false)]
    [InlineData("office.box", false)]
    public void HomeAndReservedSuffixesAreNotAsked(string suffix, bool skipped)
    {
        Assert.Equal(skipped, ActiveDirectoryDetector.IsLocalSuffix(suffix));
    }
}
