using System.Collections.Generic;
using System.IO;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using MyNetworkMonitor.Avalonia.Platform;
using MyNetworkMonitor.Avalonia.Views;
using MyNetworkMonitor.Core.Models;
using MyNetworkMonitor.Core.Persistence;
using MyNetworkMonitor.Core.ViewModels;

namespace MyNetworkMonitor.Avalonia;

public partial class App : Application
{
    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            // Demonstration der Kette Core-ViewModel <-> Avalonia-View:
            // dasselbe ManageIPGroupsViewModel wie in WPF, hier mit dem
            // Avalonia-Dialogdienst und ein paar Demo-Daten.
            var table = IpGroupTable.CreateTable();
            IpGroupTable.WriteRows(table, new List<IpGroup>
            {
                new IpGroup { IsActive = true, IpGroupDescription = "Office", DeviceDescription = "Printers",
                    FirstIP = "192.168.1.10", LastIP = "192.168.1.20", Domain = "corp.local",
                    DnsServers = "192.168.1.1", NmGatewayIP = "192.168.1.1", NmGatewayPort = "8443",
                    AutomaticScan = false, ScanIntervalMinutes = "60" },
                new IpGroup { IsActive = false, IpGroupDescription = "Lab", DeviceDescription = "Switches",
                    FirstIP = "10.0.0.1", LastIP = "10.0.0.50", Domain = "lab.local",
                    DnsServers = "10.0.0.1", NmGatewayIP = "10.0.0.1", NmGatewayPort = "8443",
                    AutomaticScan = true, ScanIntervalMinutes = "15" },
            });

            string xmlPath = Path.Combine(Path.GetTempPath(), "MyNetworkMonitor_ipgroups_demo.xml");
            var viewModel = new ManageIPGroupsViewModel(table, xmlPath, new AvaloniaDialogService());

            desktop.MainWindow = new ManageIPGroupsView(viewModel);
        }

        base.OnFrameworkInitializationCompleted();
    }
}
