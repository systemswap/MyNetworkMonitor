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
using MyNetworkMonitor.Core.Model;
using MyNetworkMonitor.Core.Models;
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

        LoadScopes();
        BuildMethodDrawer();

        _shell.Devices.AvailableServices.CollectionChanged += (_, _) => BuildServiceFacets();
        _shell.Devices.Filter.Changed += UpdateServiceFilterLabel;

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
        engine.Register(new HostnameLookupScanMethod());
        engine.Register(new ReverseLookupScanMethod());
        engine.Register(new NetBiosScanMethod());
        engine.Register(new SnmpScanMethod());
        engine.Register(new OnvifScanMethod());
        engine.Register(new TcpPortScanMethod());
        engine.Register(new UdpPortScanMethod());
        engine.Register(new SmbVersionScanMethod());
        engine.Register(new ServiceDetectionScanMethod(ServiceXmlPath()));
    }

    private static string ServiceXmlPath() =>
        System.IO.Path.Combine(AppContext.BaseDirectory, "Services.xml");

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
    /// Uebernimmt die gespeicherten IP-Gruppen und stellt den lokalen Adapter
    /// als eigenen Bereich voran, damit ohne jede Einrichtung sofort etwas da
    /// ist.
    /// </summary>
    private void LoadScopes()
    {
        _shell.Scopes.Add(new ScanScope
        {
            Index = 0,
            Kind = ScanScopeKind.NetworkInterface,
            GroupDescription = "Lokales Netz",
            DeviceDescription = "vom aktiven Adapter",
            IsSelected = true
        });

        // Dieselbe Datei, die das bisherige Fenster liest - beide Oberflaechen
        // arbeiten waehrend des Umbaus auf demselben Bestand.
        string xml = System.IO.Path.Combine(SettingsFolder(), "ipGroups.xml");

        if (!System.IO.File.Exists(xml)) return;

        try
        {
            IPGroupData data = new();
            data.IPGroupsDT.ReadXml(xml);

            foreach (IpGroup group in IpGroupTable.ReadRows(data.IPGroupsDT))
            {
                _shell.Scopes.Add(ScanScope.FromIpGroup(group));
            }
        }
        catch (Exception ex)
        {
            // Eine fehlende oder beschaedigte Gruppendatei darf den Start nicht
            // verhindern - der lokale Adapter genuegt zum Arbeiten.
            _shell.StatusText = $"IP-Gruppen konnten nicht geladen werden: {ex.Message}";
        }

        _shell.RefreshAvailability();
    }

    private void Scope_IsCheckedChanged(object? sender, RoutedEventArgs e)
    {
        if (!_ready) return;

        _shell.RefreshAvailability();
        UpdateScopeFooter();
        UpdateIpv6Hint();
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
        string prefix = _shell.TargetCountIsEstimate ? "ca. " : string.Empty;
        TimeSpan estimate = _shell.EstimatedDuration;

        string duration = estimate.TotalSeconds < 90
            ? $"{estimate.TotalSeconds:F0} s"
            : $"{estimate.TotalMinutes:F0} min";

        tb_ScopeFooter.Text =
            $"{_shell.SelectedScopeCount} Bereiche · {prefix}{targets} Ziele · geschaetzt {duration}";
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

                boxes.Add(box);
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
            "Die IPv6-Verfahren - Neighbor Cache, ff02::1, RA-Mitschnitt und MLD - " +
            "folgen in einem spaeteren Schritt.";
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
                                ? $"{facet.DeviceCount}  ({facet.RunningCount} laufend)"
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
                Text = "Noch keine Dienste gefunden.",
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
        tb_ServiceFilterLabel.Text = count == 0 ? "Dienst  ▾" : $"Dienst ({count})  ▾";
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

        bool isDevices = section == ShellSection.Devices;
        view_Devices.IsVisible = isDevices;
        view_Placeholder.IsVisible = !isDevices;

        if (isDevices) return;

        (tb_PlaceholderTitle.Text, tb_PlaceholderText.Text) = section switch
        {
            ShellSection.Network => ("Netz",
                "Praefixe, Router und Multicast-Gruppen. Entsteht mit den passiven " +
                "IPv6-Verfahren - vorher gibt es hier nichts zu zeigen."),

            ShellSection.Findings => ("Befunde",
                "Fremde Router-Advertisements, global offene Ports, Protokolldivergenz. " +
                "Das Regelwerk braucht Daten aus allen vorherigen Schritten und kommt zuletzt."),

            ShellSection.Topology => ("Topologie",
                "Die 3D-Ansicht wird aus dem bisherigen Fenster uebernommen."),

            ShellSection.Scopes => ("Bereiche",
                "Die Verwaltung bleibt wie bisher - Liste links, Maske rechts. " +
                "Sie wird als Naechstes hier eingehaengt."),

            ShellSection.Ports => ("Ports",
                "Die Portsammlungen aus dem bisherigen Fenster."),

            ShellSection.Services => ("Dienste",
                "Welcher Dienst auf welchen Ports gesucht wird. " +
                "Die Erkennungspakete bleiben unangetastet."),

            ShellSection.Names => ("Namen",
                "Die Zuordnung eigener Geraetenamen."),

            ShellSection.Settings => ("Einstellungen",
                "Zeitlimits, Speicherorte und die Anzeige."),

            _ => ("Noch nicht gebaut", string.Empty)
        };
    }

    // ---------------------------------------------------------- Export

    private async void bt_Export_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            global::Avalonia.Platform.Storage.IStorageFile? file =
                await StorageProvider.SaveFilePickerAsync(new global::Avalonia.Platform.Storage.FilePickerSaveOptions
                {
                    Title = "Ergebnistabelle exportieren",
                    SuggestedFileName = $"netzwerk-{DateTime.Now:yyyy-MM-dd-HHmm}.csv",
                    DefaultExtension = "csv"
                });

            if (file is null) return;

            await using System.IO.Stream stream = await file.OpenWriteAsync();
            await using System.IO.StreamWriter writer = new(stream, System.Text.Encoding.UTF8);

            await writer.WriteLineAsync("Geraet;IPv4;IPv6;Weitere v6;MAC;Hersteller;Dienste;Offene Ports;Zuletzt;Bereich");

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

            _shell.StatusText = $"{_shell.Devices.VisibleCount} Zeilen exportiert nach {file.Name}.";
        }
        catch (Exception ex)
        {
            _shell.StatusText = $"Export fehlgeschlagen: {ex.Message}";
        }

        // Semikolon und Zeilenumbrueche wuerden die Spalten zerreissen.
        static string Csv(string? value) =>
            (value ?? string.Empty).Replace(';', ',').Replace('\r', ' ').Replace('\n', ' ');
    }
}
