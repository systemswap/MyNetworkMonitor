// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Core.Tests;

/// <summary><see cref="RawSocketRights"/>: reading the capability and the command that grants it (docs/FEHLERGEDAECHTNIS.md, No. 27).</summary>
public class RawSocketRightsTests
{
    [Theory]
    [InlineData("CapEff:\t0000000000000000", false)]
    [InlineData("CapEff:\t0000000000002000", true)]    // bit 13 alone
    [InlineData("CapEff:\t000001ffffffffff", true)]    // root
    [InlineData("CapEff:\t0000000000001000", false)]   // bit 12 (CAP_NET_ADMIN) is not enough
    [InlineData("CapPrm:\t0000000000002000", false)]   // permitted, but not effective
    public void EffectiveCapabilityIsRead(string line, bool present)
    {
        string[] status = ["Name:\tExample", "CapInh:\t0000000000000000", line, "Seccomp:\t0"];
        Assert.Equal(present, RawSocketRights.HasEffectiveCapability(status, 13));
    }

    [Fact]
    public void PlainProgram_GetsSetcapOnItself()
    {
        Assert.Equal("sudo setcap cap_net_raw+ep '/opt/My Tools/MyNetworkMonitor.Avalonia'",
            RawSocketRights.GrantCommand("/opt/My Tools/MyNetworkMonitor.Avalonia", null));
    }

    [Fact]
    public void AppImage_GetsNoCommand()
    {
        // setcap on an unpacked copy would not reach what the menu starts (docs/FEHLERGEDAECHTNIS.md, No. 29).
        Assert.Null(RawSocketRights.GrantCommand("/tmp/.mount_X/usr/bin/MyNetworkMonitor.Avalonia", "/home/user/Apps/MyNetworkMonitor-x86_64.AppImage"));
        Assert.Contains("sudo", RawSocketRights.GrantHint("/home/user/Apps/MyNetworkMonitor-x86_64.AppImage"));
    }

    [Fact]
    public void QuotesInPathsAreEscaped()
    {
        Assert.Equal(@"sudo setcap cap_net_raw+ep '/opt/it'\''s/app'", RawSocketRights.GrantCommand("/opt/it's/app", null));
    }
}
