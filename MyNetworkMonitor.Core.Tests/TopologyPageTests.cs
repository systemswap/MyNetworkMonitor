// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Services;

namespace MyNetworkMonitor.Core.Tests;

/// <summary>The generated pages of the 3D view: complete, in English, offline by default.</summary>
public class TopologyPageTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "mnm-tests-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_folder)) Directory.Delete(_folder, recursive: true);
    }

    public static TheoryData<string> Pages => ["network", "services"];

    [Theory]
    [MemberData(nameof(Pages))]
    public void Page_IsEnglishAndUsesTheBundledLibrary(string page)
    {
        IReadOnlyList<Device> devices = [];
        string path = page == "network"
            ? TopologyGraph.WriteHtmlFile(_folder, devices, useOnlineVersion: false)
            : ServiceTopologyGraph.WriteHtmlFile(_folder, devices, useOnlineVersion: false);
        string html = File.ReadAllText(path);

        Assert.Contains("<html lang=\"en\">", html);
        Assert.Contains("</html>", html);
        Assert.DoesNotContain("cdn.jsdelivr.net", html);
        foreach (string german in new[] { "Unbekannt", " und ", " der ", " die ", " nicht ", "ueber", "Knoten" })
            Assert.DoesNotContain(german, html);
    }
}
