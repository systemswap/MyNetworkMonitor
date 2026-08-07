using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
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
/// Die neue Oberflaeche. Haelt bewusst wenig Logik: alles Fachliche sitzt im
/// <see cref="ShellViewModel"/> in Core, hier steht nur, was an Avalonia
/// gebunden ist.
/// <para>
/// Zwei Dinge werden im Code aufgebaut statt im XAML, weil sie sich nicht
/// sinnvoll deklarieren lassen: die Verfahren-Schublade, deren vier Spalten
/// aus einer nach Stufe gefilterten Liste entstehen, und die Dienstauswahl im
/// Filter, die aus den tatsaechlichen Funden waechst.
/// </para>
/// </summary>
public partial class ShellView : Window
{
    private readonly ShellViewModel _shell;
    private readonly ScanEngine _engine;
    private readonly DeviceStore _store;

    /// <summary>
    /// Erst wahr, wenn der Konstruktor durch ist.
    /// <para>
    /// Notwendig, weil Avalonia beim Laden des XAML bereits Ereignisse
    /// ausloest: <c>SelectionChanged</c> der Umfangsauswahl und
    /// <c>IsCheckedChanged</c> des vorausgewaehlten Rail-Eintrags feuern,
    /// bevor <see cref="_shell"/> existiert. Ohne diese Sperre stirbt das
    /// Fenster beim Oeffnen an einer NullReferenceException.
    /// </para>
    /// </summary>
    private bool _ready;

    public ShellView()
    {
        InitializeComponent();

        _store = new DeviceStore();
        _engine = new ScanEngine();
        RegisterMethods(_engine);

        _shell = new ShellViewModel(_engine, _store);
        DataContext = _shell;

        // Die gespeicherten Einstellungen zuerst - Zeitlimit und Portschalter
        // gehen in die Verfuegbarkeitspruefung der Verfahren ein.
        _shell.AttachSettings(SettingsFolder());

        LoadScopes();

        _shell.PortEditor.Load(System.IO.Path.Combine(SettingsFolder(), "portsToScan.xml"));
        _shell.ServiceEditor.Load(ServiceXmlPath());

        BuildMethodDrawer();

        _shell.Devices.AvailableServices.CollectionChanged += (_, _) => BuildServiceFacets();
        _shell.Devices.Filter.Changed += UpdateServiceFilterLabel;

        // Die eigene Eingabe aendert die Zielzahl genauso wie ein Haken -
        // die Fusszeile der Auswahl muss beides mitbekommen.
        _shell.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(ShellViewModel.CustomTargets)) UpdateScopeFooter();
        };

        // Die Auswahl misst sich beim Oeffnen an ihrem Inhalt - die Bereiche
        // koennen sich zwischen zwei Klicks geaendert haben.
        if (bt_Scopes.Flyout is FlyoutBase scopeFlyout)
        {
            scopeFlyout.Opened += (_, _) => BuildScopeRows();
        }

        BuildServiceFacets();
        UpdateServiceFilterLabel();
        UpdateScopeFooter();
        UpdateIpv6Hint();

        _ready = true;
    }

    // Kein eigenes InitializeComponent: die vom XAML-Compiler erzeugte Fassung
    // weist zugleich die benannten Steuerelemente zu. Eine handgeschriebene
    // Variante mit AvaloniaXamlLoader.Load laedt zwar das XAML, laesst die
    // Felder aber null - der Zugriff darauf scheitert dann beim Oeffnen.

    /// <summary>
    /// Alle heute vorhandenen Verfahren. Ein neues hinzuzufuegen heisst: eine
    /// Zeile hier - die Schublade und die Verfuegbarkeitspruefung ergeben sich
    /// daraus von selbst.
    /// </summary>
    private static void RegisterMethods(ScanEngine engine)
    {
        engine.Register(new PingScanMethod());
        engine.Register(new ArpRequestScanMethod());
        engine.Register(new ArpCacheScanMethod());
        engine.Register(new SsdpScanMethod());
        engine.Register(new MdnsScanMethod());
        // Reihenfolge innerhalb der Phase = Reihenfolge hier. Die
        // Rueckwaertsaufloesung muss vor der Vorwaertsaufloesung stehen: erst
        // liefert sie zur Adresse den Namen, dann fragt die Vorwaerts-
        // aufloesung, welche Adressen dieser Name im DNS hat. Andersherum
        // fragt die zweite ins Leere, weil der Name noch fehlt.
        engine.Register(new ReverseLookupScanMethod());
        engine.Register(new HostnameLookupScanMethod());
        engine.Register(new NetBiosScanMethod());
        engine.Register(new SnmpScanMethod());
        engine.Register(new OnvifScanMethod());
        engine.Register(new TcpPortScanMethod());
        engine.Register(new UdpPortScanMethod());
        engine.Register(new SmbVersionScanMethod());
        engine.Register(new ServiceDetectionScanMethod(ServiceXmlPath()));
    }

    /// <summary>
    /// Dieselbe Datei, die das bisherige Fenster benutzt - eigene Portlisten
    /// und Dienstauswahl gelten damit in beiden Oberflaechen. Die Datei muss
    /// nicht vorhanden sein; das Modul legt jeden Dienst mit Standardports an
    /// und liest sie nur als Ueberlagerung darueber.
    /// </summary>
    private static string ServiceXmlPath() =>
        System.IO.Path.Combine(SettingsFolder(), "services.xml");

    /// <summary>
    /// Derselbe Ordner, den das bisherige Fenster benutzt - damit beide
    /// Oberflaechen waehrend des Umbaus denselben Bestand sehen.
    /// </summary>
    private static string SettingsFolder()
    {
        string documents = System.Runtime.InteropServices.RuntimeInformation
            .IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows)
            ? System.IO.Path.Combine(Environment.ExpandEnvironmentVariables("%userprofile%"), "Documents")
            : System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents");

        return System.IO.Path.Combine(documents, "MyNetworkMonitor", "Settings");
    }

    // ------------------------------------------------------------- Bereiche

    /// <summary>
    /// Uebernimmt die gespeicherten Bereiche. Dieselbe Datei, die das bisherige
    /// Fenster liest - beide Oberflaechen arbeiten waehrend des Umbaus auf
    /// demselben Bestand. Laden und Speichern liegen im
    /// <see cref="ScopeEditorViewModel"/>, damit sie sich nicht auseinander
    /// entwickeln.
    /// </summary>
    private void LoadScopes()
    {
        _shell.ScopeEditor.Load(System.IO.Path.Combine(SettingsFolder(), "ipGroups.xml"));
        _shell.RefreshAvailability();
    }

    private void Scope_IsCheckedChanged(object? sender, RoutedEventArgs e)
    {
        if (!_ready) return;

        _shell.RefreshAvailability();
        UpdateScopeFooter();
        UpdateIpv6Hint();
    }

    /// <summary>
    /// Baut die Zeilen der Bereichsauswahl auf.
    /// <para>
    /// Von Hand statt ueber ein DataGrid, und das ist hier der Kern der Sache:
    /// ein Grid mit Auto-Spalten misst sich an seinem Inhalt, ein DataGrid
    /// nicht. Letzteres nimmt den angebotenen Platz und scrollt intern, wenn
    /// er nicht reicht - das umgebende Menue erfaehrt dadurch nie, dass es zu
    /// schmal ist, und man sieht eine abgeschnittene Tabelle mit
    /// Bildlaufbalken. Mit dem Grid waechst der Rahmen von selbst mit.
    /// </para>
    /// <para>
    /// Wird bei jedem Oeffnen neu gebaut: die Bereiche koennen sich
    /// zwischendurch geaendert haben, und es sind eine Handvoll Zeilen.
    /// </para>
    /// </summary>
    private void BuildScopeRows()
    {
        // Nicht ueber das Fenster hinaus. Als Bindung ginge das nicht - das
        // Popup hat einen eigenen Namensraum, in dem #ShellRoot nicht auflöst.
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

        // Eine Zelle bindet gegen den Bereich, statt den Text zu kopieren -
        // eine Umbenennung in der Verwaltung schlaegt so sofort durch.
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
    /// Rechnet die Fusszeile der Bereichsauswahl mit: Ziele und geschaetzte
    /// Dauer, damit vor dem Start sichtbar ist, worauf man sich einlaesst.
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

    // -------------------------------------------------- Verfahren-Schublade

    /// <summary>
    /// Baut die vier Spalten auf. Die IPv6-Spalte bleibt vorerst leer - dort
    /// erscheinen die Verfahren, sobald sie gebaut sind; bis dahin steht ein
    /// Hinweis statt einer leeren Flaeche.
    /// </summary>
    private void BuildMethodDrawer()
    {
        Fill(ic_Discovery, _shell.Methods.Where(m => m.Phase == ScanPhase.Discovery));
        Fill(ic_Identification, _shell.Methods.Where(m => m.Phase == ScanPhase.Identification));
        Fill(ic_Services, _shell.Methods.Where(m => m.Phase == ScanPhase.Services));
        Fill(ic_Ipv6, _shell.Methods.Where(m => m.IsIpv6Only));

        static void Fill(ItemsControl target, IEnumerable<ScanMethodChoice> methods)
        {
            List<Control> boxes = [];

            foreach (ScanMethodChoice choice in methods)
            {
                CheckBox box = new()
                {
                    Content = choice.DisplayName,
                    FontSize = 10.5,
                    Margin = new global::Avalonia.Thickness(0, 0, 0, 2)
                };

                box.Bind(ToggleButton.IsCheckedProperty,
                    new global::Avalonia.Data.Binding(nameof(ScanMethodChoice.IsSelected))
                    {
                        Source = choice,
                        Mode = global::Avalonia.Data.BindingMode.TwoWay
                    });

                box.Bind(IsEnabledProperty,
                    new global::Avalonia.Data.Binding(nameof(ScanMethodChoice.IsEnabled)) { Source = choice });

                box.Bind(ToolTip.TipProperty,
                    new global::Avalonia.Data.Binding(nameof(ScanMethodChoice.BlockReason)) { Source = choice });

                // Gesendet / geantwortet / gesamt, je Verfahren und stehend.
                // Die bisherige Anwendung hat diese drei Zahlen fuer alle
                // Verfahren nebeneinander gezeigt; daran ist nach dem Lauf
                // abzulesen, welches wie viel gebracht hat - der Kommandobalken
                // allein zeigt immer nur das gerade laufende.
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
            }

            target.ItemsSource = boxes;
        }
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

    // ----------------------------------------------------- Dienstauswahl

    /// <summary>
    /// Die Dienstauswahl im Filter entsteht aus den tatsaechlich gefundenen
    /// Diensten - mit Trefferzahl, damit man sieht, ob sich das Filtern lohnt.
    /// </summary>
    private void BuildServiceFacets()
    {
        List<Control> rows = [];

        foreach (ServiceFacet facet in _shell.Devices.AvailableServices)
        {
            CheckBox box = new()
            {
                IsChecked = _shell.Devices.Filter.Services.Contains(facet.Name),
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
                            VerticalAlignment = VerticalAlignment.Center
                        },
                        new TextBlock
                        {
                            Text = facet.RunningCount > 0
                                ? $"{facet.DeviceCount}  ({facet.RunningCount} running)"
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

    private void UpdateServiceFilterLabel()
    {
        int count = _shell.Devices.Filter.Services.Count;
        tb_ServiceFilterLabel.Text = count == 0 ? "Service  ▾" : $"Service ({count})  ▾";
    }

    private void bt_ResetFilter_Click(object? sender, RoutedEventArgs e)
    {
        _shell.Devices.Filter.Reset();
        BuildServiceFacets();
    }

    // ------------------------------------------------------------ Rail

    /// <summary>
    /// Wechselt die Ansicht. Was noch nicht gebaut ist, sagt das offen -
    /// statt eine leere Flaeche zu zeigen, die wie ein Fehler aussieht.
    /// </summary>
    private void Nav_Checked(object? sender, RoutedEventArgs e)
    {
        if (!_ready) return;

        // Avalonia kennt kein Checked-Ereignis, nur IsCheckedChanged - das
        // meldet auch das Abwaehlen des vorherigen Eintrags.
        if (sender is not RadioButton button || button.IsChecked != true) return;
        if (button.Tag is not string tag) return;
        if (!Enum.TryParse(tag, out ShellSection section)) return;

        _shell.Section = section;

        // Jede gebaute Ansicht bekommt hier ihre Zeile; der Platzhalter faengt
        // auf, was noch fehlt, und sagt das auch.
        view_Devices.IsVisible = section == ShellSection.Devices;
        view_Scopes.IsVisible = section == ShellSection.Scopes;
        view_Ports.IsVisible = section == ShellSection.Ports;
        view_Services.IsVisible = section == ShellSection.Services;
        view_Settings.IsVisible = section == ShellSection.Settings;
        view_Network.IsVisible = section == ShellSection.Network;
        view_Topology.IsVisible = section == ShellSection.Topology;

        // Adapter kommen und gehen - ein VPN-Client, ein Dock, ein Stick.
        // Beim Aufschlagen der Ansicht neu lesen ist billiger als der
        // Versuch, das mitzubekommen.
        if (section == ShellSection.Network) _shell.NetworkView.Refresh();

        bool built = section is ShellSection.Devices or ShellSection.Scopes
                             or ShellSection.Ports or ShellSection.Services
                             or ShellSection.Settings or ShellSection.Network
                             or ShellSection.Topology;

        view_Placeholder.IsVisible = !built;

        if (built) return;

        (tb_PlaceholderTitle.Text, tb_PlaceholderText.Text) = section switch
        {
            ShellSection.Findings => ("Findings",
                "Rogue router advertisements, globally open ports, protocol divergence. " +
                "The rule set needs data from every earlier step and comes last."),

            ShellSection.Names => ("Names",
                "Mapping your own device names."),

            _ => ("Not built yet", string.Empty)
        };
    }

    /// <summary>
    /// Zeichnet die Topologie aus dem aktuellen Bestand.
    /// <para>
    /// Bewusst auf Knopfdruck und nicht beim Aufschlagen der Ansicht: der
    /// Graph wird als Datei geschrieben und ueber einen lokalen Webserver
    /// geladen, und das bei jedem Klick in der Leiste zu tun waere
    /// verschwenderisch.
    /// </para>
    /// </summary>
    private async void bt_DrawTopology_Click(object? sender, RoutedEventArgs e)
    {
        List<Device> devices;

        // Unter der Sperre nur kopieren. Das Schreiben der Seite dauert, und
        // solange duerfte kein Scan den Bestand veraendern.
        lock (_store.SyncRoot)
        {
            devices = [.. _store.Devices];
        }

        if (devices.Count == 0)
        {
            tb_TopologyHint.Text = "Nothing to draw yet - run a scan first.";
            return;
        }

        try
        {
            tb_TopologyHint.Text = $"Drawing {devices.Count} devices...";

            await TopologyLauncher.ShowAsync(
                new NativeWebViewHost(webTopology), devices, _shell.Settings.UseOnlineTopologyLibrary);

            tb_TopologyHint.Text = "Duplicate addresses and names are drawn as coloured edges.";
        }
        catch (Exception ex)
        {
            // Die Webansicht faellt je nach System unterschiedlich aus - ein
            // Fehler darf die Oberflaeche nicht mitnehmen.
            tb_TopologyHint.Text = $"Could not draw: {ex.Message}";
        }
    }

    /// <summary>
    /// Oeffnet die bisherige Oberflaeche als zweites Fenster. Sie haelt noch
    /// die Ansichten, die hier erst Platzhalter sind - bis sie umgezogen sind,
    /// ist ein Klick besser als ein Neustart mit --classic.
    /// </summary>
    private MainWindowView? _classicWindow;

    private void bt_OpenClassic_Click(object? sender, RoutedEventArgs e)
    {
        // Ein bereits offenes Fenster nur nach vorn holen, nicht doppelt
        // erzeugen - zwei Instanzen wuerden auf denselben Dateien arbeiten.
        if (_classicWindow is not null)
        {
            _classicWindow.Activate();
            return;
        }

        _classicWindow = new MainWindowView();
        _classicWindow.Closed += (_, _) => _classicWindow = null;
        _classicWindow.Show();
    }

    /// <summary>
    /// Beim Schliessen den vorgemerkten Stand der Bereiche sofort schreiben -
    /// der Zeitgeber der verzoegerten Speicherung wuerde sonst nie mehr feuern
    /// und die letzte Aenderung waere verloren.
    /// </summary>
    protected override void OnClosing(global::Avalonia.Controls.WindowClosingEventArgs e)
    {
        _shell.ScopeEditor.SaveNow();
        _shell.PortEditor.SaveNow();
        _shell.ServiceEditor.SaveNow();

        // Der Bestand zuletzt: er ist der groesste Brocken, und wenn dabei
        // etwas schiefgeht, sind die Einstellungen wenigstens schon sicher.
        _shell.SaveLastScanResultNow();

        base.OnClosing(e);
    }

    // ------------------------------------------------------ Einstellungen

    private void bt_OpenSettingsFolder_Click(object? sender, RoutedEventArgs e) =>
        OpenFolder(_shell.SettingsFolder);

    private void bt_OpenAppFolder_Click(object? sender, RoutedEventArgs e) =>
        OpenFolder(_shell.ApplicationFolder);

    /// <summary>
    /// Oeffnet einen Ordner im Dateimanager des Systems.
    /// <para>
    /// <c>UseShellExecute</c> ist der plattformneutrale Weg: Windows nimmt den
    /// Explorer, Linux den eingestellten Dateimanager ueber xdg-open, macOS den
    /// Finder. Ein fest verdrahtetes <c>explorer.exe</c> waere unter Linux tot.
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

            // Der Einstellungsordner entsteht erst beim ersten Speichern - ihn
            // hier anzulegen ist freundlicher als die Meldung, dass es ihn nicht gibt.
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

        // Semikolon und Zeilenumbrueche wuerden die Spalten zerreissen.
        static string Csv(string? value) =>
            (value ?? string.Empty).Replace(';', ',').Replace('\r', ' ').Replace('\n', ' ');
    }
}
