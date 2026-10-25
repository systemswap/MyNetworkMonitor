using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Markup.Xaml;
using Avalonia.Media;
using MyNetworkMonitor.Avalonia.Platform;
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Models;
using MyNetworkMonitor.Core.Services;
using MyNetworkMonitor.Core.Persistence;
using MyNetworkMonitor.Core.Scanning.Engine;
using MyNetworkMonitor.Core.Scanning.Engine.Methods;
using MyNetworkMonitor.Core.ViewModels;

namespace MyNetworkMonitor.Avalonia.Views;

/// <summary>
/// The main window. Deliberately holds little logic: everything domain-related
/// lives in <see cref="ShellViewModel"/> in Core; this class contains only what
/// is tied to Avalonia.
/// <para>
/// Two things are built in code instead of XAML because they cannot be
/// declared sensibly: the method drawer, whose four columns come from a list
/// filtered by stage, and the service selection in the filter, which grows
/// from the actual findings.
/// </para>
/// </summary>
public partial class ShellView : Window
{
    private readonly ShellViewModel _shell;
    private readonly ScanEngine _engine;
    private readonly DeviceStore _store;

    /// <summary>
    /// True only once the constructor has finished.
    /// <para>
    /// Required because Avalonia already raises events while loading the XAML:
    /// <c>SelectionChanged</c> of the scope selection and
    /// <c>IsCheckedChanged</c> of the preselected rail entry fire before
    /// <see cref="_shell"/> exists. Without this guard the window dies with a
    /// NullReferenceException when it opens.
    /// </para>
    /// </summary>
    private bool _ready;

    /// <summary>Creates the window, loads settings and lists, and starts the satellite link.</summary>
    public ShellView()
    {
        InitializeComponent();

        _store = new DeviceStore();
        _engine = new ScanEngine();
        RegisterMethods(_engine);

        _shell = new ShellViewModel(_engine, _store)
        {
            // For questions during a run, for example when the satellite of a
            // range is not connected.
            Dialogs = new AvaloniaDialogService()
        };

        DataContext = _shell;

        // System check once the window is open: in the background, and only shown when something needs attention.
        Opened += async (_, _) => await ShowSystemCheckIfNeededAsync();

        // The stored settings first: timeout and port switches feed into the
        // availability check of the methods.
        _shell.AttachSettings(SettingsFolder());

        LoadScopes();

        _shell.PortEditor.Load(System.IO.Path.Combine(SettingsFolder(), "portsToScan.xml"));
        _shell.ServiceEditor.Load(ServiceXmlPath());

        // Only now are the service definitions available that make up the
        // selection "which services are grouped".
        _shell.BuildGroupableServices();

        BuildMethodDrawer();

        _shell.Devices.AvailableServices.CollectionChanged += (_, _) => BuildServiceFacets();
        _shell.Devices.AvailableScopes.CollectionChanged += (_, _) => BuildScopeFacets();
        _shell.Devices.Filter.Changed += UpdateServiceFilterLabel;

        // The custom input changes the target count just like a checkmark;
        // the footer of the selection must reflect both.
        _shell.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ShellViewModel.CustomTargets)) UpdateScopeFooter();
        };

        // The selection sizes itself to its content when opened; the ranges
        // may have changed between two clicks.
        if (bt_Scopes.Flyout is FlyoutBase scopeFlyout)
        {
            scopeFlyout.Opened += (_, _) =>
            {
                BuildScopeRows();

                // The adapter list too: a VPN adapter or a dock comes and goes,
                // and a list from program start would then be wrong.
                _shell.RefreshCustomTargetAdapters();
            };
        }

        // The version belongs in the title: the last component is incremented
        // with every release, and it is the first thing asked for in a support
        // request. Four components, as in the csproj.
        Title = $"My Network Monitor  v{OwnVersion()}";

        // When trying things out with two instances they must be told apart;
        // the name of the state folder is shown in the title for that.
        if (AppPaths.HasOwnState)
        {
            string root = System.IO.Path.GetDirectoryName(SettingsFolder()) ?? string.Empty;
            Title += $" - {System.IO.Path.GetFileName(root)}";
        }

        // The adapter list for the custom input. Read again whenever the
        // selection opens, because a VPN or a dock comes and goes.
        _shell.RefreshCustomTargetAdapters();

        BuildServiceFacets();
        BuildScopeFacets();
        BuildFindServicePortMenu();
        UpdateServiceFilterLabel();
        UpdateScopeFooter();
        UpdateIpv6Hint();

        _ready = true;
    }

    // No custom InitializeComponent: the version generated by the XAML compiler
    // also assigns the named controls. A handwritten variant with
    // AvaloniaXamlLoader.Load loads the XAML but leaves the fields null, and
    // accessing them then fails when the window opens.

    /// <summary>
    /// All available methods. The list itself lives in Core
    /// (<see cref="ScanEngineFactory"/>) because the satellite service runs
    /// without a window and needs the same methods.
    /// </summary>
    private static void RegisterMethods(ScanEngine engine) =>
        ScanEngineFactory.RegisterAllMethods(engine, ServiceXmlPath());

    /// <summary>
    /// The service definitions file in the settings folder. The file need not
    /// exist; the module creates every service with its default ports and reads
    /// the file only as an overlay.
    /// </summary>
    private static string ServiceXmlPath() =>
        System.IO.Path.Combine(SettingsFolder(), "services.xml");

    /// <summary>
    /// The settings folder: <c>Documents/MyNetworkMonitor/Settings</c>, or the
    /// instance's own folder given with <c>--state</c>.
    /// </summary>
    private static string SettingsFolder()
    {
        // A second instance for trying things out gets its own folder through
        // --state; otherwise both would write to the same files and delete each
        // other's ranges and last run.
        if (AppPaths.OwnSettingsFolder is { } own) return own;

        string documents = System.Runtime.InteropServices.RuntimeInformation
            .IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows)
            ? System.IO.Path.Combine(Environment.ExpandEnvironmentVariables("%userprofile%"), "Documents")
            : System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents");

        return System.IO.Path.Combine(documents, "MyNetworkMonitor", "Settings");
    }

    // ------------------------------------------------------- Satellite mode

    /// <summary>The own version, as the peer should see it.</summary>
    private static string OwnVersion() =>
        System.Reflection.Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? string.Empty;

    /// <summary>
    /// Attaches listener and connector. Both depend on a setting; with
    /// satellite mode unused, nothing of it is noticeable.
    /// </summary>
    private void StartSatelliteLink()
    {
        // The events arrive on background threads, but the list is bound to
        // the display.
        _shell.SatelliteEditor.Post = action => global::Avalonia.Threading.Dispatcher.UIThread.Post(action);

        _shell.SatelliteEditor.SetAppVersion(OwnVersion());
        _shell.SatelliteEditor.RefreshFirewall();

        // Queries the service first: if it runs, the outgoing connection
        // belongs to it, and this window does not connect itself.
        _shell.SatelliteEditor.RefreshService();

        if (_shell.Settings.SatelliteListenEnabled)
        {
            _shell.SatelliteEditor.StartListening(_shell.Settings.SatelliteListenPort, OwnVersion());
        }

        if (_shell.Settings.SatelliteModeEnabled && _shell.SatelliteEditor.CanConnectFromWindow)
        {
            _shell.SatelliteEditor.ConnectAllHosts();
        }
    }

    private void bt_FirewallRefresh_Click(object? sender, RoutedEventArgs e) =>
        _shell.SatelliteEditor.RefreshFirewall();

    private void bt_FirewallAllow_Click(object? sender, RoutedEventArgs e) =>
        _shell.SatelliteEditor.CreateFirewallRule(_shell.Settings.SatelliteListenPort);

    private void bt_FirewallRemove_Click(object? sender, RoutedEventArgs e) =>
        _shell.SatelliteEditor.RemoveFirewallRule();

    /// <summary>Reads name, domain and addresses of this machine again.</summary>
    private void bt_HostInfoRefresh_Click(object? sender, RoutedEventArgs e) =>
        _shell.SatelliteEditor.RefreshHostInfo();

    /// <summary>
    /// Takes a port from the firewall selection as the listening port. The list
    /// is thus a selection and not just information: without the right to
    /// create a rule, a port that is already open can be picked here.
    /// </summary>
    private void cb_AllowedPorts_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (!_ready || sender is not ComboBox list || list.SelectedItem is not string entry) return;

        // The line looks like "TCP 5900-5904  (only for ...)". The first number
        // is taken; for a range that is its start, because one of them has to
        // be chosen and the first is the obvious one.
        string digits = new([.. entry.SkipWhile(c => !char.IsDigit(c)).TakeWhile(char.IsDigit)]);

        if (int.TryParse(digits, out int port) && port is > 0 and <= 65535)
        {
            _shell.Settings.SatelliteListenPort = port;
        }
    }

    // ---------------------------------------------------- Receivers (hosts)

    private void bt_SatelliteConnect_Click(object? sender, RoutedEventArgs e)
    {
        // The button also sets the switch: connecting here means connecting on
        // the next start as well.
        _shell.Settings.SatelliteModeEnabled = true;

        _shell.SatelliteEditor.ConnectAllHosts();
    }

    private void bt_SatelliteDisconnect_Click(object? sender, RoutedEventArgs e)
    {
        _shell.Settings.SatelliteModeEnabled = false;
        _shell.SatelliteEditor.DisconnectAllHosts();
    }

    // ---------------------------------------------------------------- Ranges

    /// <summary>
    /// Loads the satellites and the stored ranges, then starts the satellite
    /// link. Loading and saving of the ranges live in
    /// <see cref="ScopeEditorViewModel"/> so that they do not drift apart.
    /// </summary>
    private void LoadScopes()
    {
        // The satellites first: the range form offers their names for
        // selection, and a selection that is still empty when the range loads
        // discards its stored value.
        _shell.SatelliteEditor.Load(SettingsFolder());

        // Settings without a host list store exactly one main scanner. If it is
        // set, it becomes the first entry instead of having to be typed in again.
        if (_shell.SatelliteEditor.Hosts.Count == 0 &&
            !string.IsNullOrWhiteSpace(_shell.Settings.MainScannerHost))
        {
            _shell.SatelliteEditor.Hosts.Add(new MainScanner
            {
                Host = _shell.Settings.MainScannerHost,
                Port = _shell.Settings.MainScannerPort,
                Note = "taken over from the previous setting"
            });

            _shell.SatelliteEditor.SelectedHost = _shell.SatelliteEditor.Hosts[0];
        }

        _shell.ScopeEditor.Load(System.IO.Path.Combine(SettingsFolder(), "ipGroups.xml"));

        // Ranges in older settings refer to the satellite by name. They are
        // rewritten once to the identifier; afterwards the assignment survives
        // every renaming. What cannot be matched stays as it is and is reported
        // as "not connected" during the run.
        _shell.MigrateScannedByToIds();

        _shell.RefreshAvailability();

        // Only now: the listener approves only satellites in the loaded list;
        // before loading, every satellite would be "unknown".
        StartSatelliteLink();
    }

    private void Scope_IsCheckedChanged(object? sender, RoutedEventArgs e)
    {
        if (!_ready) return;

        _shell.RefreshAvailability();
        UpdateScopeFooter();
        UpdateIpv6Hint();
    }

    /// <summary>
    /// Builds the rows of the range selection.
    /// <para>
    /// By hand instead of with a DataGrid, which is the core of the matter: a
    /// Grid with Auto columns sizes itself to its content, a DataGrid does not.
    /// The latter takes the space offered and scrolls internally when it is not
    /// enough, so the surrounding menu never learns that it is too narrow, and
    /// the result is a truncated table with scroll bars. With the Grid, the
    /// border grows along by itself.
    /// </para>
    /// <para>
    /// Rebuilt on every opening: the ranges may have changed in the meantime,
    /// and there are only a handful of rows.
    /// </para>
    /// </summary>
    private void BuildScopeRows()
    {
        // Not beyond the window. A binding cannot do this: the popup has its
        // own name scope in which #ShellRoot does not resolve.
        bd_ScopeFlyout.MaxWidth = Math.Max(620, Bounds.Width - 120);

        grd_Scopes.Children.Clear();
        grd_Scopes.RowDefinitions.Clear();
        grd_Scopes.ColumnDefinitions.Clear();

        foreach (string _ in new[] { "check", "name", "range", "description" })
        {
            grd_Scopes.ColumnDefinitions.Add(new ColumnDefinition(GridLength.Auto));
        }

        grd_Scopes.RowDefinitions.Add(new RowDefinition(GridLength.Auto));

        AddHeader(0, "ACTIVE");
        AddHeader(1, "RANGE");
        AddHeader(2, "FROM - TO");
        AddHeader(3, "DESCRIPTION");

        int row = 1;

        foreach (ScanScope scope in _shell.Scopes)
        {
            grd_Scopes.RowDefinitions.Add(new RowDefinition(GridLength.Auto));

            CheckBox box = new()
            {
                VerticalAlignment = VerticalAlignment.Center,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new global::Avalonia.Thickness(11, 5, 6, 5),
                Padding = new global::Avalonia.Thickness(0)
            };

            box.Bind(ToggleButton.IsCheckedProperty,
                new global::Avalonia.Data.Binding(nameof(ScanScope.IsSelected))
                {
                    Source = scope,
                    Mode = global::Avalonia.Data.BindingMode.TwoWay
                });

            box.IsCheckedChanged += Scope_IsCheckedChanged;
            ToolTip.SetTip(box, "Include this range in the next scan");

            Place(box, row, 0);

            Place(Cell(scope, nameof(ScanScope.GroupDescription), 11.5, FontWeight.SemiBold,
                       ShellPalette.Ink, mono: false), row, 1);

            Place(Cell(scope, nameof(ScanScope.RangeText), 11, FontWeight.Normal,
                       ShellPalette.Teal, mono: true), row, 2);

            Place(Cell(scope, nameof(ScanScope.DeviceDescription), 10.5, FontWeight.Normal,
                       ShellPalette.Dimmer, mono: false), row, 3);

            row++;
        }

        void AddHeader(int column, string text)
        {
            TextBlock header = new()
            {
                Text = text,
                FontSize = 8.5,
                Foreground = ShellPalette.Dimmer,
                Margin = new global::Avalonia.Thickness(11, 4, 12, 4),
                VerticalAlignment = VerticalAlignment.Center
            };

            Place(header, 0, column);
        }

        void Place(Control control, int r, int c)
        {
            control[Grid.RowProperty] = r;
            control[Grid.ColumnProperty] = c;
            grd_Scopes.Children.Add(control);
        }

        // A cell binds to the range instead of copying the text, so a renaming
        // in the range management shows immediately.
        static TextBlock Cell(ScanScope scope, string property, double size,
                              FontWeight weight, IBrush brush, bool mono)
        {
            TextBlock cell = new()
            {
                FontSize = size,
                FontWeight = weight,
                Foreground = brush,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new global::Avalonia.Thickness(0, 5, 12, 5)
            };

            if (mono) cell.FontFamily = new FontFamily("Cascadia Mono,Consolas,monospace");

            cell.Bind(TextBlock.TextProperty,
                new global::Avalonia.Data.Binding(property) { Source = scope });

            return cell;
        }
    }

    private void bt_ScopesAll_Click(object? sender, RoutedEventArgs e) => SetAllScopes(true);

    private void bt_ScopesNone_Click(object? sender, RoutedEventArgs e) => SetAllScopes(false);

    private void SetAllScopes(bool selected)
    {
        foreach (ScanScope scope in _shell.Scopes) scope.IsSelected = selected;

        _shell.RefreshAvailability();
        UpdateScopeFooter();
        UpdateIpv6Hint();
    }

    private void bt_ManageScopes_Click(object? sender, RoutedEventArgs e)
    {
        nav_Scopes.IsChecked = true;
    }

    /// <summary>
    /// Updates the footer of the range selection: targets and estimated
    /// duration, so that the size of the run is visible before starting.
    /// </summary>
    private void UpdateScopeFooter()
    {
        long targets = _shell.TargetCount;
        string prefix = _shell.TargetCountIsEstimate ? "~" : string.Empty;
        TimeSpan estimate = _shell.EstimatedDuration;

        string duration = estimate.TotalSeconds < 90
            ? $"{estimate.TotalSeconds:F0} s"
            : $"{estimate.TotalMinutes:F0} min";

        tb_ScopeFooter.Text =
            $"{_shell.SelectedScopeCount} ranges · {prefix}{targets} targets · est. {duration}";
    }

    // -------------------------------------------------------- Method drawer

    /// <summary>
    /// Builds the four columns. The IPv6 column lists the IPv6-only methods;
    /// while there are none, it shows a hint (<see cref="UpdateIpv6Hint"/>)
    /// instead of an empty area.
    /// </summary>
    private void BuildMethodDrawer()
    {
        Fill(ic_Discovery, _shell.Methods.Where(m => m.Phase == ScanPhase.Discovery));

        // The cross-check sits in the middle of the list, right after the
        // reverse lookup: thematically it belongs between the two DNS methods,
        // not below all methods of the column.
        Fill(ic_Identification, _shell.Methods.Where(m => m.Phase == ScanPhase.Identification),
             after: "dns.reverse", extra: BuildDnsCrossCheckBox());

        Fill(ic_Services, _shell.Methods.Where(m => m.Phase == ScanPhase.Services));
        Fill(ic_Ipv6, _shell.Methods.Where(m => m.IsIpv6Only));

        static void Fill(ItemsControl target, IEnumerable<ScanMethodChoice> methods,
                         string? after = null, Control? extra = null)
        {
            List<Control> boxes = [];

            foreach (ScanMethodChoice choice in methods)
            {
                // Indented methods are variants of the method above, with the
                // same indent as the DNS cross-check.
                double left = choice.Indented ? 14 : 0;

                CheckBox box = new()
                {
                    Content = choice.DisplayName,
                    FontSize = 10.5,
                    Margin = new global::Avalonia.Thickness(left, 0, 0, 2)
                };

                box.Bind(ToggleButton.IsCheckedProperty,
                    new global::Avalonia.Data.Binding(nameof(ScanMethodChoice.IsSelected))
                    {
                        Source = choice,
                        Mode = global::Avalonia.Data.BindingMode.TwoWay
                    });

                box.Bind(IsEnabledProperty,
                    new global::Avalonia.Data.Binding(nameof(ScanMethodChoice.IsEnabled)) { Source = choice });

                // The tooltip explains the method in full sentences. As plain
                // text it would end up as one line wider than the screen, hence
                // a wrapping TextBlock with a fixed maximum width instead of the
                // string itself.
                TextBlock hint = new()
                {
                    FontSize = 11,
                    TextWrapping = global::Avalonia.Media.TextWrapping.Wrap,
                    MaxWidth = 320
                };

                hint.Bind(TextBlock.TextProperty,
                    new global::Avalonia.Data.Binding(nameof(ScanMethodChoice.Hint)) { Source = choice });

                ToolTip.SetTip(box, hint);

                // Otherwise disabled methods show nothing at all, although that
                // is exactly where the reason matters.
                ToolTip.SetShowOnDisabled(box, true);

                // Sent / answered / total, per method and persistent. After the
                // run these numbers show how much each method yielded; the
                // command bar alone only ever shows the running one.
                TextBlock counts = new()
                {
                    FontSize = 9.5,
                    FontFamily = new global::Avalonia.Media.FontFamily("Consolas, monospace"),
                    Foreground = global::Avalonia.Media.Brushes.Gray,
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new global::Avalonia.Thickness(8, 0, 0, 0)
                };

                counts.Bind(TextBlock.TextProperty,
                    new global::Avalonia.Data.Binding(nameof(ScanMethodChoice.ProgressText)) { Source = choice });

                counts.Bind(ToolTip.TipProperty,
                    new global::Avalonia.Data.Binding(nameof(ScanMethodChoice.ProgressText))
                    {
                        Source = choice,
                        StringFormat = "sent / answered / total: {0}"
                    });

                DockPanel row = new() { LastChildFill = false };
                DockPanel.SetDock(counts, Dock.Right);
                row.Children.Add(counts);
                row.Children.Add(box);

                boxes.Add(row);

                if (extra is not null && choice.Id == after) boxes.Add(extra);
            }

            target.ItemsSource = boxes;
        }
    }

    /// <summary>
    /// The checkbox of the DNS cross-check. Not a method of its own but a
    /// sub-function of the name scan: indented to make that visible, and
    /// disabled while neither of the two DNS methods is checked.
    /// </summary>
    private CheckBox BuildDnsCrossCheckBox()
    {
        CheckBox box = new()
        {
            Content = "cross-check DNS servers",
            FontSize = 10.5,
            Margin = new global::Avalonia.Thickness(14, 0, 0, 2)
        };

        box.Bind(ToggleButton.IsCheckedProperty,
            new global::Avalonia.Data.Binding(nameof(ScanSettings.CrossCheckDnsServers))
            {
                Source = _shell.Settings,
                Mode = global::Avalonia.Data.BindingMode.TwoWay
            });

        box.Bind(IsEnabledProperty,
            new global::Avalonia.Data.Binding(nameof(ShellViewModel.CanCrossCheckDns)) { Source = _shell });

        ToolTip.SetTip(box, new TextBlock
        {
            FontSize = 11,
            TextWrapping = global::Avalonia.Media.TextWrapping.Wrap,
            MaxWidth = 320,
            Text = "Asks every known DNS server about each address separately - forwards and " +
                   "backwards. As long as they all say the same thing there is nothing to do; " +
                   "where they differ, that is the finding, and it names the server that does " +
                   "not resolve cleanly. Needs the reverse lookup or the hostname lookup to be " +
                   "ticked. A thorough check that costs noticeable time on a large network, so " +
                   "no preset turns it on - tick it yourself when you want it."
        });

        ToolTip.SetShowOnDisabled(box, true);

        return box;
    }

    private void UpdateIpv6Hint()
    {
        bool anyIpv6Method = _shell.Methods.Any(m => m.IsIpv6Only);

        if (anyIpv6Method)
        {
            tb_Ipv6Hint.Text = string.Empty;
            return;
        }

        tb_Ipv6Hint.Text =
            "The IPv6 methods - neighbor cache, ff02::1, RA capture and MLD - " +
            "follow in a later step.";
    }

    private void cb_Profile_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (!_ready) return;

        if (cb_Profile.SelectedItem is ScanProfile profile) _shell.ApplyProfile(profile);
    }

    /// <summary>
    /// Mirrors the multiple selection of the device table into the view model.
    /// <c>SelectedItem</c> knows only the last clicked row, but rescanning
    /// must cover all selected rows.
    /// </summary>
    private void dg_Devices_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        _shell.Devices.SelectedDevices.Clear();

        foreach (Device device in dg_Devices.SelectedItems.OfType<Device>())
        {
            _shell.Devices.SelectedDevices.Add(device);
        }
    }

    // ---------------------------------------------------- Service selection

    /// <summary>
    /// The service selection in the filter is built from the services actually
    /// found, with hit counts, so that it is visible whether filtering pays off.
    /// </summary>
    private void BuildServiceFacets()
    {
        List<Control> rows = [];

        // The list arrives sorted by category. Where the category changes, it
        // appears as a subheading and the services below are indented;
        // otherwise the order looks random, because the category appears
        // nowhere else.
        string? lastCategory = null;

        foreach (ServiceFacet facet in _shell.Devices.AvailableServices)
        {
            string category = string.IsNullOrWhiteSpace(facet.Category) ? "Other" : facet.Category;

            if (!string.Equals(category, lastCategory, StringComparison.CurrentCultureIgnoreCase))
            {
                rows.Add(new TextBlock
                {
                    Text = category,
                    FontSize = 9.5,
                    FontWeight = FontWeight.SemiBold,
                    Foreground = new SolidColorBrush(Color.Parse("#7E979C")),
                    // Less space above the first heading than above the
                    // following ones: the menu edge already closes it off.
                    Margin = new global::Avalonia.Thickness(10, lastCategory is null ? 4 : 8, 10, 2)
                });

                lastCategory = category;
            }

            // One number per row instead of two side by side:
            //   all detected  -> "32 running"
            //   none detected -> "32 open"     (open ports without a protocol)
            //   mixed         -> "32, 8 running"
            // Not "32  (32 running)", which would show the same number twice.
            string zahlen =
                facet.RunningCount == 0 ? $"{facet.DeviceCount} open"
                : facet.RunningCount == facet.DeviceCount ? $"{facet.DeviceCount} running"
                : $"{facet.DeviceCount}, {facet.RunningCount} running";

            CheckBox box = new()
            {
                IsChecked = _shell.Devices.Filter.Services.Contains(facet.Name),
                FontSize = 10.5,
                // Indented below its heading.
                Margin = new global::Avalonia.Thickness(22, 2, 10, 2),
                // Across the whole menu width, so that the numbers on the right
                // line up instead of sticking to the name.
                HorizontalAlignment = HorizontalAlignment.Stretch,
                HorizontalContentAlignment = HorizontalAlignment.Stretch,
                Content = new Grid
                {
                    ColumnDefinitions = new ColumnDefinitions("*,Auto"),
                    HorizontalAlignment = HorizontalAlignment.Stretch,
                    Children =
                    {
                        new TextBlock
                        {
                            Text = facet.Name,
                            VerticalAlignment = VerticalAlignment.Center
                        },
                        new TextBlock
                        {
                            Text = zahlen,
                            FontSize = 9.5,
                            Foreground = new SolidColorBrush(Color.Parse("#93A5A9")),
                            VerticalAlignment = VerticalAlignment.Center,
                            TextAlignment = global::Avalonia.Media.TextAlignment.Right,
                            Margin = new global::Avalonia.Thickness(12, 0, 0, 0),
                            [Grid.ColumnProperty] = 1
                        }
                    }
                }
            };

            string name = facet.Name;
            box.IsCheckedChanged += (_, _) =>
            {
                bool wanted = box.IsChecked == true;
                bool present = _shell.Devices.Filter.Services.Contains(name);

                if (wanted != present) _shell.Devices.ToggleService(name);
            };

            rows.Add(box);
        }

        if (rows.Count == 0)
        {
            rows.Add(new TextBlock
            {
                Text = "No services found yet.",
                FontSize = 10.5,
                Foreground = new SolidColorBrush(Color.Parse("#93A5A9")),
                Margin = new global::Avalonia.Thickness(10, 6, 10, 6)
            });
        }

        ic_ServiceFacets.ItemsSource = rows;
    }

    private void bt_ServicesNone_Click(object? sender, RoutedEventArgs e)
    {
        _shell.Devices.Filter.Services.Clear();
        _shell.Devices.Filter.NotifyServicesChanged();
        BuildServiceFacets();
    }

    /// <summary>
    /// The range selection, built like the service selection. Each range shows
    /// how many devices come from it and how many of them currently answer,
    /// which tells whether filtering pays off at all.
    /// </summary>
    private void BuildScopeFacets()
    {
        List<Control> rows = [];

        foreach (ScopeFacet facet in _shell.Devices.AvailableScopes)
        {
            CheckBox box = new()
            {
                IsChecked = _shell.Devices.Filter.Scopes.Contains(facet.Name),
                FontSize = 10.5,
                Margin = new global::Avalonia.Thickness(10, 2, 10, 2),
                Content = new Grid
                {
                    ColumnDefinitions = new ColumnDefinitions("*,Auto"),
                    Children =
                    {
                        new TextBlock
                        {
                            Text = facet.Name,
                            TextTrimming = global::Avalonia.Media.TextTrimming.CharacterEllipsis,
                            VerticalAlignment = VerticalAlignment.Center,
                            [ToolTip.TipProperty] = facet.Name
                        },
                        new TextBlock
                        {
                            Text = facet.OnlineCount > 0
                                ? $"{facet.DeviceCount}  ({facet.OnlineCount} up)"
                                : $"{facet.DeviceCount}",
                            FontSize = 9.5,
                            Foreground = new SolidColorBrush(Color.Parse("#93A5A9")),
                            VerticalAlignment = VerticalAlignment.Center,
                            [Grid.ColumnProperty] = 1
                        }
                    }
                }
            };

            string name = facet.Name;
            box.IsCheckedChanged += (_, _) =>
            {
                bool wanted = box.IsChecked == true;
                bool present = _shell.Devices.Filter.Scopes.Contains(name);

                if (wanted != present) _shell.Devices.ToggleScope(name);
            };

            rows.Add(box);
        }

        if (rows.Count == 0)
        {
            rows.Add(new TextBlock
            {
                Text = "Nothing scanned yet.",
                FontSize = 10.5,
                Foreground = new SolidColorBrush(Color.Parse("#93A5A9")),
                Margin = new global::Avalonia.Thickness(10, 6, 10, 6)
            });
        }

        ic_ScopeFacets.ItemsSource = rows;
    }

    /// <summary>
    /// Fills the submenu of the port search with the services. One service per
    /// entry: the search runs over 65,536 ports and takes time; offering it for
    /// all services at once would be a click followed by a quarter of an hour
    /// of waiting.
    /// </summary>
    private void BuildFindServicePortMenu()
    {
        List<MenuItem> entries = [];

        foreach (ServiceType service in ShellViewModel.AllServiceTypes)
        {
            ServiceType captured = service;

            MenuItem entry = new()
            {
                Header = service.ToString(),
                Command = _shell.FindServicePortCommand,
                CommandParameter = captured
            };

            entries.Add(entry);
        }

        mi_FindServicePort.ItemsSource = entries;
    }

    // Not "ScopesNone": that name already belongs to resetting the scope
    // selection in the command bar. Two different things (what is scanned and
    // what is filtered by) must not share a name.
    private void bt_RangeFilterNone_Click(object? sender, RoutedEventArgs e)
    {
        _shell.Devices.Filter.Scopes.Clear();
        _shell.Devices.Filter.NotifyScopesChanged();
        BuildScopeFacets();
    }

    private void UpdateServiceFilterLabel()
    {
        int count = _shell.Devices.Filter.Services.Count;
        tb_ServiceFilterLabel.Text = count == 0 ? "Service  ▾" : $"Service ({count})  ▾";

        int scopes = _shell.Devices.Filter.Scopes.Count;
        tb_ScopeFilterLabel.Text = scopes == 0 ? "Range  ▾" : $"Range ({scopes})  ▾";
    }

    private void bt_ResetFilter_Click(object? sender, RoutedEventArgs e)
    {
        _shell.Devices.Filter.Reset();
        BuildServiceFacets();
        BuildScopeFacets();
    }

    // ------------------------------------------------------------ Rail

    /// <summary>
    /// Switches the view. A view that is not available yet says so openly
    /// instead of showing an empty area that looks like an error.
    /// </summary>
    private void Nav_Checked(object? sender, RoutedEventArgs e)
    {
        if (!_ready) return;

        // Avalonia has no Checked event, only IsCheckedChanged, which also
        // reports the deselection of the previous entry.
        if (sender is not RadioButton button || button.IsChecked != true) return;
        if (button.Tag is not string tag) return;
        if (!Enum.TryParse(tag, out ShellSection section)) return;

        _shell.Section = section;

        // Every available view has its line here; the placeholder catches
        // whatever is still missing and says so.
        view_Devices.IsVisible = section == ShellSection.Devices;
        view_Scopes.IsVisible = section == ShellSection.Scopes;
        view_Ports.IsVisible = section == ShellSection.Ports;
        view_Services.IsVisible = section == ShellSection.Services;
        view_Satellites.IsVisible = section == ShellSection.Satellites;
        view_Settings.IsVisible = section == ShellSection.Settings;
        view_Network.IsVisible = section == ShellSection.Network;
        view_Findings.IsVisible = section == ShellSection.Findings;

        // The web view is attached only here, and only the first time. Before
        // making the view visible so that it is ready when shown, but only if
        // the topology is opened at all.
        if (section == ShellSection.Topology) PrepareTopologyView();

        view_Topology.IsVisible = section == ShellSection.Topology;

        // Re-evaluated when shown: the adapter rule reads the state of the
        // machine, which changes even without a scan.
        if (section == ShellSection.Findings) _shell.FindingsView.Refresh();

        // Adapters come and go: a VPN client, a dock, a USB adapter. Reading
        // them again when the view is shown is cheaper than trying to track
        // the changes.
        if (section == ShellSection.Network) _shell.NetworkView.Refresh();

        // Brings the satellite list in line with the selection held in the view
        // model when the view is shown.
        //
        // Required because a selection set before the DataGrid has its rows
        // arrives only halfway. The first satellite is selected when the list
        // loads, long before this view is first shown. Measured, the state
        // then is:
        //
        //     SelectedItem = TestSat-A      SelectedIndex = -1
        //
        // The binding has carried the value in, but no row existed for it at
        // that time: nothing is highlighted on the left while its data already
        // shows on the right. Assigning the same value again does not help,
        // because the property system discards an assignment without a change;
        // the same applies to the index, which leads back to the same item.
        // Only clearing and setting again makes the table look for the row,
        // now that it exists.
        //
        // Only at index -1, i.e. only in the inconsistent state: a selection
        // made by hand stays untouched.
        //
        // With priority "Loaded" and not simply through the dispatcher: the
        // view has just been made visible, and its rows are created in the
        // next layout pass.
        if (section == ShellSection.Satellites)
        {
            global::Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                if (dg_Satellites.SelectedIndex < 0
                    && _shell.SatelliteEditor.Selected is Satellite chosen)
                {
                    dg_Satellites.SelectedItem = null;
                    dg_Satellites.SelectedItem = chosen;
                }

                // Focus as well, so that the list can be operated with the
                // arrow keys right away without clicking into it first.
                dg_Satellites.Focus();
            },
            global::Avalonia.Threading.DispatcherPriority.Loaded);
        }

        bool built = section is ShellSection.Devices or ShellSection.Scopes
                             or ShellSection.Ports or ShellSection.Services
                             or ShellSection.Settings or ShellSection.Network
                             or ShellSection.Topology or ShellSection.Findings
                             or ShellSection.Satellites;

        view_Placeholder.IsVisible = !built;

        if (built) return;

        (tb_PlaceholderTitle.Text, tb_PlaceholderText.Text) = section switch
        {
            ShellSection.Names => ("Names",
                "Mapping your own device names."),

            _ => ("Not built yet", string.Empty)
        };
    }

    /// <summary>
    /// Which engine for the embedded web view is available on this system.
    /// </summary>
    private enum WebEngine
    {
        /// <summary>No engine available; only the browser remains.</summary>
        None,

        /// <summary>The normal case: WebView2 on Windows, or WPE WebKit on Linux.</summary>
        Native,

        /// <summary>Linux without WPE but with WebKitGTK, embedded through the fallback path.</summary>
        WebKitGtk
    }

    /// <summary>
    /// The native libraries the embedded view needs on Linux.
    /// <para>
    /// The Linux engine of <c>NativeWebView</c> is not WebKitGTK but
    /// <b>WPE WebKit</b>; the names appear as P/Invoke targets in
    /// <c>Avalonia.Controls.WebView.dll</c>. Debian 13 has the packages but
    /// does not install them by default; if they are missing, loading fails in
    /// the native part and takes down the process instead of throwing a
    /// catchable exception. Hence the check beforehand instead of catching
    /// afterwards.
    /// </para>
    /// </summary>
    private static readonly string[] WpeLibraries =
    [
        "libWPEWebKit-2.0.so.1",
        "libwpe-1.0.so.1",
        "libWPEBackend-fdo-1.0.so.1"
    ];

    /// <summary>The GTK web engine, the documented fallback on Linux.</summary>
    private static readonly string[] WebKitGtkLibraries =
    [
        "libwebkit2gtk-4.1.so.0",
        "libwebkit2gtk-4.0.so.37"
    ];

    /// <summary>
    /// Maps every library of <see cref="WpeLibraries"/> to the apt package that
    /// provides it; only then can the hint be limited to what is actually
    /// missing.
    /// </summary>
    private static readonly IReadOnlyDictionary<string, string> WpePackageBySoName =
        new Dictionary<string, string>
        {
            ["libWPEWebKit-2.0.so.1"] = "libwpewebkit-2.0-1",
            ["libwpe-1.0.so.1"] = "libwpe-1.0-1",
            ["libWPEBackend-fdo-1.0.so.1"] = "libwpebackend-fdo-1.0-1"
        };

    /// <summary>
    /// The apt packages for the WPE libraries missing on this system.
    /// Empty if WPE is complete.
    /// </summary>
    private static IEnumerable<string> MissingWpePackages() =>
        WpeLibraries.Where(lib => !IsLibraryPresent(lib)).Select(lib => WpePackageBySoName[lib]);

    /// <summary>
    /// The status line text when the graph has been opened in the browser.
    /// Names cause and remedy, because "does not work" alone helps nobody.
    /// Lists only the packages actually missing on this system instead of all
    /// three, and names the real reason when WPE is present but embedding is
    /// deliberately disabled.
    /// </summary>
    private static string NoEmbeddedViewHint()
    {
        if (OperatingSystem.IsLinux() && !EmbeddedWebViewEnabledOnLinux && WpeLibraries.All(IsLibraryPresent))
        {
            return "Opened in your browser: the embedded view is disabled on Linux for now - " +
                   "it loads the page but never paints it (Avalonia.Controls.WebView issue, not a missing package).";
        }

        // Fedora does not package WPE WebKit (see packages.fedoraproject.org): no command to offer there.
        return "Opened in your browser: this system has no embedded web engine. " +
               "To get the view back inside the window, install WPE WebKit - on Debian and " +
               "Ubuntu that is: sudo apt install " + string.Join(' ', MissingWpePackages()) +
               " (Fedora does not package WPE WebKit; there the view keeps opening in the browser).";
    }

    /// <summary>
    /// Disabled on Linux although detection and control are in place. Tested
    /// with WPE fully installed (all three libraries present, processes start,
    /// the page loads successfully according to <c>NavigationCompleted</c>,
    /// JavaScript and WebGL run), the window still stays empty. So it is not
    /// detection or loading but the bridge between the WPE offscreen buffer
    /// and the Avalonia compositor in <c>Avalonia.Controls.WebView</c> 12.0.1
    /// that paints nothing on this path. A broken embedding that reports
    /// success is worse than none, so Linux stays at
    /// <see cref="WebEngine.None"/> and thus with the system browser until a
    /// newer package version actually paints.
    /// </summary>
    private const bool EmbeddedWebViewEnabledOnLinux = false;

    /// <summary>
    /// Determines which engine the embedded view can use.
    /// <para>
    /// Checked by loading the library, not by trying to create the control:
    /// the failed attempt ends the process, and a <c>try</c> around it does
    /// not help.
    /// </para>
    /// </summary>
    private static WebEngine AvailableWebEngine()
    {
        // Windows and macOS ship their engine.
        if (!OperatingSystem.IsLinux()) return WebEngine.Native;

        if (!EmbeddedWebViewEnabledOnLinux) return WebEngine.None;

        if (WpeLibraries.All(IsLibraryPresent)) return WebEngine.Native;
        if (WebKitGtkLibraries.Any(IsLibraryPresent)) return WebEngine.WebKitGtk;

        return WebEngine.None;
    }

    /// <summary>
    /// The engine the web view uses on this system. Determined once, in
    /// <see cref="PrepareTopologyView"/>.
    /// </summary>
    private WebEngine _webEngine = WebEngine.Native;

    /// <summary>The embedded web view; exists only once it is needed.</summary>
    private NativeWebView? _webTopology;

    private bool _topologyPrepared;

    /// <summary>
    /// Attaches the web view when the topology is first shown, not earlier,
    /// and <b>before</b> it becomes visible.
    /// <para>
    /// <c>NativeWebView</c> creates its native engine as soon as the control
    /// enters the visual tree, i.e. already when switching to the section, not
    /// only when drawing. If that fails on Linux for lack of WPE, the switch
    /// aborts halfway and the previous view stays on screen. The control is
    /// therefore either set to the GTK fallback here or not added to the tree
    /// at all; what is not there cannot initialize.
    /// </para>
    /// <para>
    /// <b>Why so late:</b> the application must not depend at start on a web
    /// engine being present and intact. A failure on Linux is a native crash,
    /// not a catchable error. If it happened while creating the main window,
    /// the whole application would disappear, and nobody would suspect the
    /// topology view that was never opened. Happening here, "Topology" has
    /// just been clicked, and the connection is obvious.
    /// </para>
    /// </summary>
    private void PrepareTopologyView()
    {
        if (_topologyPrepared) return;
        _topologyPrepared = true;

        _webEngine = AvailableWebEngine();

        if (_webEngine == WebEngine.None)
        {
            // No engine: the control is not created at all. In its place comes
            // what is missing and how to fix it, or, if WPE is present but
            // deliberately disabled, that the cause is Avalonia and not a
            // missing library.
            bool linuxEmbeddingDisabled = OperatingSystem.IsLinux() && !EmbeddedWebViewEnabledOnLinux
                                          && WpeLibraries.All(IsLibraryPresent);

            host_Topology.Children.Add(new TextBlock
            {
                Margin = new global::Avalonia.Thickness(24),
                Text = linuxEmbeddingDisabled
                    ? "WPE WebKit is installed, but the graph opens in your browser when you press " +
                      "Draw anyway: the embedded view loads the page successfully without ever " +
                      "painting it, a known issue in Avalonia.Controls.WebView on Linux - not " +
                      "something a missing package would fix."
                    : "No embedded web engine on this system, so the graph opens in your browser " +
                      "when you press Draw.\n\n" +
                      "To get it back inside this window, install WPE WebKit - on Debian and Ubuntu:\n" +
                      "sudo apt install " + string.Join(' ', MissingWpePackages()) + "\n\n" +
                      "Fedora does not package WPE WebKit; there the graph keeps opening in your browser.",
                FontSize = 11.5,
                TextWrapping = global::Avalonia.Media.TextWrapping.Wrap,
                Foreground = new SolidColorBrush(Color.Parse("#5C6F73")),
                VerticalAlignment = VerticalAlignment.Top
            });

            return;
        }

        _webTopology = new NativeWebView();

        // Without WPE but with GTK: the documented fallback. The handler must
        // be in place before the control creates its engine, i.e. now.
        if (_webEngine == WebEngine.WebKitGtk) PreferWebKitGtk(_webTopology);

        host_Topology.Children.Add(_webTopology);
    }

    /// <summary>
    /// Whether a native library is present on this system.
    /// <para>
    /// <b>Deliberately without loading it.</b> The obvious approach,
    /// <c>NativeLibrary.TryLoad</c> followed by <c>Free</c>, is dangerous
    /// exactly here: <c>Free</c> is a <c>dlclose</c>, and WebKit, GTK and WPE
    /// do not tolerate that. They register GObject types, hold thread-local
    /// state and hook into <c>atexit</c>; once unloaded, pointers to code that
    /// no longer exists remain, and the process dies without a catchable
    /// exception.
    /// </para>
    /// <para>
    /// The search therefore looks at the file system, as the dynamic linker
    /// does: first the <c>ldconfig</c> cache, then the usual paths as a
    /// fallback.
    /// </para>
    /// </summary>
    private static bool IsLibraryPresent(string soname)
    {
        if (LdConfigCache.Value.Contains(soname)) return true;

        string[] directories =
        [
            "/usr/lib/x86_64-linux-gnu",
            "/usr/lib/aarch64-linux-gnu",
            "/usr/lib64",
            "/usr/lib",
            "/lib/x86_64-linux-gnu",
            "/lib64",
            "/lib"
        ];

        return directories.Any(d => System.IO.File.Exists(System.IO.Path.Combine(d, soname)));
    }

    /// <summary>
    /// The names of all libraries known to the linker. Read once, because it
    /// takes an external process.
    /// </summary>
    private static readonly Lazy<HashSet<string>> LdConfigCache = new(() =>
    {
        HashSet<string> names = new(StringComparer.Ordinal);

        if (!OperatingSystem.IsLinux()) return names;

        try
        {
            using System.Diagnostics.Process? process = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("/sbin/ldconfig", "-p")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            });

            if (process is null) return names;

            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(3000);

            // Line format: "\tlibfoo.so.1 (libc6,x86-64) => /usr/lib/libfoo.so.1"
            foreach (string line in output.Split('\n'))
            {
                string trimmed = line.Trim();
                int space = trimmed.IndexOf(' ');

                if (space > 0) names.Add(trimmed[..space]);
            }
        }
        catch (Exception)
        {
            // No ldconfig available: the directory search alone decides.
        }

        return names;
    });

    /// <summary>
    /// Switches the view to the GTK engine.
    /// <para>
    /// The switch is set through <c>EnvironmentRequested</c>: the event is
    /// raised while the view builds its engine, and the event data differ per
    /// platform. On Linux they are
    /// <c>LinuxWpeWebViewEnvironmentRequestedEventArgs</c>; only there does
    /// <c>PreferWebKitGtkInstead</c> exist, hence the check for the type rather
    /// than the operating system.
    /// </para>
    /// </summary>
    private static void PreferWebKitGtk(NativeWebView view)
    {
        view.EnvironmentRequested += (_, args) =>
        {
            if (args is global::Avalonia.Platform.LinuxWpeWebViewEnvironmentRequestedEventArgs linux)
            {
                linux.PreferWebKitGtkInstead = true;
            }
        };
    }

    /// <summary>
    /// Draws the topology from the current devices.
    /// <para>
    /// Deliberately on button press and not when the view is shown: the graph
    /// is written as a file and loaded through a local web server, and doing
    /// that on every click in the rail would be wasteful.
    /// </para>
    /// </summary>
    private async void bt_DrawTopology_Click(object? sender, RoutedEventArgs e)
    {
        List<Device> devices;

        // Only copies under the lock. Writing the page takes time, and no scan
        // may change the devices for that long.
        lock (_store.SyncRoot)
        {
            devices = [.. _store.Devices];
        }

        if (devices.Count == 0)
        {
            tb_TopologyHint.Text = "Nothing to draw yet - run a scan first.";
            return;
        }

        // The switch alone decides which view is drawn; from here on the paths
        // differ, so that the network view is not affected by the service view.
        bool services = rb_TopologyService.IsChecked == true;

        try
        {
            tb_TopologyHint.Text = $"Drawing {devices.Count} devices...";

            // The engine was determined in PrepareTopologyView and is only used
            // here. Determining it now would be too late: the view was built
            // when switching to the section.
            bool embedded = _webTopology is not null;

            IWebViewHost host = embedded
                ? new NativeWebViewHost(_webTopology!)
                : new SystemBrowserWebViewHost();

            bool online = _shell.Settings.UseOnlineTopologyLibrary;

            if (services)
            {
                await TopologyLauncher.ShowServicesAsync(host, devices, online);

                tb_TopologyHint.Text = "One cloud per service, with the devices running it around it. " +
                                      "Only devices with a service are drawn.";
            }
            else
            {
                await TopologyLauncher.ShowAsync(host, devices, online);

                tb_TopologyHint.Text = "Duplicate addresses and names are drawn as coloured edges.";
            }

            if (!embedded) tb_TopologyHint.Text += " " + NoEmbeddedViewHint();
        }
        catch (Exception ex)
        {
            // The web view behaves differently depending on the system; an
            // error must not take the user interface down with it.
            tb_TopologyHint.Text = $"Could not draw: {ex.Message}";
        }
    }

    /// <summary>
    /// The donation window, if open.
    /// </summary>
    private PayPalDonationView? _donationWindow;

    private void bt_Donate_Click(object? sender, RoutedEventArgs e)
    {
        // An already open window is only brought to the front, not created
        // twice.
        if (_donationWindow is not null)
        {
            _donationWindow.Activate();
            return;
        }

        _donationWindow = new PayPalDonationView();
        _donationWindow.Closed += (_, _) => _donationWindow = null;
        _donationWindow.Show(this);
    }

    /// <summary>
    /// Writes pending changes of the ranges immediately on closing; the timer
    /// of the delayed save would otherwise never fire again, and the last
    /// change would be lost.
    /// </summary>
    protected override void OnClosing(global::Avalonia.Controls.WindowClosingEventArgs e)
    {
        _shell.ScopeEditor.SaveNow();
        _shell.PortEditor.SaveNow();
        _shell.ServiceEditor.SaveNow();

        // The satellites are written immediately on every change, without a
        // timer or delay, because the list is short. The call here is a safety
        // net in case something is still pending.
        _shell.SatelliteEditor.Save();
        _shell.SatelliteEditor.SaveHosts();

        // Closes connections cleanly so that the peers notice right away
        // instead of running into a timeout. The service is not affected: it
        // keeps running, which is exactly what it exists for.
        _shell.SatelliteEditor.StopListening();
        _shell.SatelliteEditor.DisconnectAllHosts();

        // The devices last: they are the largest part, and if something goes
        // wrong there, the settings are at least already safe.
        _shell.SaveLastScanResultNow();

        base.OnClosing(e);
    }

    // ------------------------------------------------------------ Settings

    private void bt_OpenSettingsFolder_Click(object? sender, RoutedEventArgs e) =>
        OpenFolder(_shell.SettingsFolder);

    private void bt_SystemCheck_Click(object? sender, RoutedEventArgs e) =>
        new SystemCheckWindow(_shell).ShowDialog(this);

    /// <summary>
    /// Runs the system check (<see cref="SystemRequirements"/>) after start and opens <see cref="SystemCheckWindow"/> if a
    /// required program is missing or an optional one has not been dismissed. A failing check never blocks the start.
    /// </summary>
    private async Task ShowSystemCheckIfNeededAsync()
    {
        try
        {
            IReadOnlyList<SystemCheckResult> results = await Task.Run(SystemRequirements.Check);
            if (SystemCheckWindow.NeedsAttention(_shell, results)) await new SystemCheckWindow(_shell).ShowDialog(this);
        }
        catch (Exception)
        {
            // The check is a help, not a condition for using the program.
        }
    }

    private void bt_OpenAppFolder_Click(object? sender, RoutedEventArgs e) =>
        OpenFolder(_shell.ApplicationFolder);

    private void bt_ShowLicense_Click(object? sender, RoutedEventArgs e) =>
        new LicenseWindow().ShowDialog(this);

    /// <summary>
    /// Opens a folder in the file manager of the system.
    /// <para>
    /// <c>UseShellExecute</c> is the platform-neutral way: Windows uses
    /// Explorer, Linux the configured file manager through xdg-open, macOS the
    /// Finder. A hard-wired <c>explorer.exe</c> would not work on Linux.
    /// </para>
    /// </summary>
    private void OpenFolder(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                _shell.StatusText = "No folder to open.";
                return;
            }

            // The settings folder is created only on the first save; creating it
            // here is friendlier than a message that it does not exist.
            System.IO.Directory.CreateDirectory(path);

            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = path,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            _shell.StatusText = $"Could not open {path}: {ex.Message}";
        }
    }

    // ---------------------------------------------------------- Export

    private async void bt_Export_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            global::Avalonia.Platform.Storage.IStorageFile? file =
                await StorageProvider.SaveFilePickerAsync(new global::Avalonia.Platform.Storage.FilePickerSaveOptions
                {
                    Title = "Export result table",
                    SuggestedFileName = $"network-{DateTime.Now:yyyy-MM-dd-HHmm}.csv",
                    DefaultExtension = "csv"
                });

            if (file is null) return;

            await using System.IO.Stream stream = await file.OpenWriteAsync();
            await using System.IO.StreamWriter writer = new(stream, System.Text.Encoding.UTF8);

            await writer.WriteLineAsync("Device;IPv4;IPv6;More v6;MAC;Vendor;Services;Open ports;Last seen;Range");

            foreach (Device device in _shell.Devices.Visible)
            {
                await writer.WriteLineAsync(string.Join(';',
                [
                    Csv(device.DisplayName), Csv(device.Ipv4Text), Csv(device.Ipv6Text),
                    device.Ipv6ExtraCount.ToString(), Csv(device.MacText), Csv(device.Vendor),
                    Csv(device.RunningServicesText), device.OpenPortCount.ToString(),
                    Csv(device.LastSeenText), Csv(device.GroupDescription)
                ]));
            }

            _shell.StatusText = $"{_shell.Devices.VisibleCount} rows exported to {file.Name}.";
        }
        catch (Exception ex)
        {
            _shell.StatusText = $"Export failed: {ex.Message}";
        }

        // Semicolons and line breaks would break the columns apart.
        static string Csv(string? value) =>
            (value ?? string.Empty).Replace(';', ',').Replace('\r', ' ').Replace('\n', ' ');
    }
}
