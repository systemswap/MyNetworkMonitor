// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using MyNetworkMonitor.Core.Scanning.Engine.Methods;
using MyNetworkMonitor.Core.Scanning.ServiceScans;

namespace MyNetworkMonitor.Core.Tests;

/// <summary>The details view hides the bare confirmation of a probe, in the current and in the earlier German wording.</summary>
public class PortLogTests
{
    [Theory]
    [InlineData(ServiceProbeBase.ProtocolMatched, false)]
    [InlineData(ServiceProbeBase.ProtocolMatchedGerman, false)]
    [InlineData("  " + ServiceProbeBase.ProtocolMatchedGerman + "\n", false)]
    [InlineData("", false)]
    [InlineData("Version: 7.0 (wire protocol 21)", true)]
    public void OnlyRealInformationCountsAsDeviceInfo(string log, bool isInfo)
    {
        Assert.Equal(isInfo, LegacyScanMethod.IsDeviceInfo(log));
    }
}
