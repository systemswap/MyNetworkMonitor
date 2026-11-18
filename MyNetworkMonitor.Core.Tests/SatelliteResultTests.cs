// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Persistence;
using MyNetworkMonitor.Core.SatelliteLink;
using static MyNetworkMonitor.Core.Tests.DeviceStoreTests;

namespace MyNetworkMonitor.Core.Tests;

/// <summary>
/// What the main scanner shows of a satellite run: the status note (docs/FEHLERGEDAECHTNIS.md, No. 42)
/// and the reachability of the devices a satellite reports (No. 43).
/// </summary>
public class SatelliteResultTests
{
    [Fact]
    public void NoteFollowsTheSatellitesUntilTheLastOneHasReported()
    {
        SatelliteRunTracker run = new();
        run.Start(["sat-halle3", "sat-lager"], []);
        Assert.Equal("2 satellites are scanning (sat-halle3, sat-lager)", run.Note);

        run.Finished("sat-halle3", 16, partial: false);
        Assert.Equal("Satellite \"sat-lager\" is scanning · \"sat-halle3\" reported 16 device(s)", run.Note);

        run.Finished("sat-lager", 12, partial: false);
        Assert.DoesNotContain("scanning", run.Note);
        Assert.Contains("\"sat-lager\" reported 12 device(s)", run.Note);
    }

    [Fact]
    public void SatelliteEndingWithAnErrorIsNoLongerScanning()
    {
        SatelliteRunTracker run = new();
        run.Start(["sat-halle3"], ["sat-werkstatt"]);

        run.Failed("sat-halle3", "A job is already running (job-1).");

        Assert.DoesNotContain("is scanning", run.Note);
        Assert.Contains("\"sat-halle3\": A job is already running (job-1).", run.Note);
        Assert.Contains("\"sat-werkstatt\" is not connected", run.Note);
    }

    [Fact]
    public void StoppedJobIsMarkedAsPartial()
    {
        SatelliteRunTracker run = new();
        run.Start(["sat-halle3"], []);

        run.Finished("SAT-HALLE3", 3, partial: true);

        Assert.Empty(run.Scanning);
        Assert.Contains("was stopped - 3 device(s) found so far", run.Note);
    }

    [Fact]
    public void ClearForgetsThePreviousRun()
    {
        SatelliteRunTracker run = new();
        run.Start(["sat-halle3"], ["sat-lager"]);

        run.Clear();

        Assert.Equal(string.Empty, run.Note);
    }

    // ------------------------------------------------------------- reachability

    private static string SatelliteReportJson()
    {
        DeviceStore satellite = new();
        satellite.Observe(Seen("198.51.100.21", MacA, "Satellite"));                            // answered
        satellite.Observe(new DeviceObservation { Source = "Test", Address = Ip("198.51.100.22"),
                                                  Mac = System.Net.NetworkInformation.PhysicalAddress.Parse(MacB) });   // did not
        return DeviceStoreFile.ToJson(satellite);
    }

    [Fact]
    public void SatelliteResultKeepsWhichDevicesAnswered()
    {
        List<Device> devices = DeviceStoreFile.FromJson(SatelliteReportJson(), keepResponding: true);

        Assert.True(devices.Single(d => d.Ipv4Text == "198.51.100.21").IsOnline);
        Assert.False(devices.Single(d => d.Ipv4Text == "198.51.100.22").IsOnline);
    }

    [Fact]
    public void SavedInventoryNeverComesBackAsAnswering()
    {
        Assert.All(DeviceStoreFile.FromJson(SatelliteReportJson()), d => Assert.False(d.IsOnline));
    }

    [Fact]
    public void MergedSatelliteDeviceIsReachableInTheMainInventory()
    {
        DeviceStore main = new();
        main.Observe(new DeviceObservation { Source = "Test", Address = Ip("198.51.100.21"),
                                             Mac = System.Net.NetworkInformation.PhysicalAddress.Parse(MacA) });

        main.MergeFrom(DeviceStoreFile.FromJson(SatelliteReportJson(), keepResponding: true));

        Assert.True(main.FindAllByAddress(Ip("198.51.100.21")).Single().IsOnline);
    }
}

/// <summary>How the main scanner shows where a satellite connected from (docs/FEHLERGEDAECHTNIS.md, No. 45).</summary>
public class SatelliteEndpointTests
{
    [Theory]
    [InlineData("::ffff:198.51.100.20", 41604, "198.51.100.20:41604")]
    [InlineData("198.51.100.20", 41604, "198.51.100.20:41604")]
    [InlineData("2001:db8::20", 41604, "[2001:db8::20]:41604")]
    public void PeerAddressIsShownAsAnAdministratorReadsIt(string address, int port, string expected)
    {
        Assert.Equal(expected, SatelliteListener.Describe(new System.Net.IPEndPoint(System.Net.IPAddress.Parse(address), port)));
    }

    [Fact]
    public void MissingEndPointIsUnknown()
    {
        Assert.Equal("unknown", SatelliteListener.Describe(null));
    }
}
