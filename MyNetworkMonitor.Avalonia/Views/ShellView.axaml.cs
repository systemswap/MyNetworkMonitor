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

        _shell = new ShellViewModel(_engine, _store)
        {
            // Fuer Rueckfragen waehrend eines Laufs - etwa wenn der Satellit
            // eines Bereichs nicht verbunden ist.
            Dialogs = new AvaloniaDialogService()
        };

        DataContext = _shell;

        // Die gespeicherten Einstellungen zuerst - Zeitlimit und Portschalter
        // gehen in die Verfuegbarkeitspruefung der Verfahren ein.
        _shell.AttachSettings(SettingsFolder());

        LoadScopes();

        _shell.PortEditor.Load(System.IO.Path.Combine(SettingsFolder(), "portsToScan.xml"));
        _shell.ServiceEditor.Load(ServiceXmlPath());

        // Erst jetzt sind die Dienstdefinitionen da, aus denen die Auswahl
        // "welche Dienste werden zusammengefasst" besteht.
        _shell.BuildGroupableServices();

        BuildMethodDrawer();

        _shell.Devices.AvailableServices.CollectionChanged += (_, _) => BuildServiceFacets();
        _shell.Devices.AvailableScopes.CollectionChanged += (_, _) => BuildScopeFacets();
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
            scopeFlyout.Opened += (_, _) =>
            {
                BuildScopeRows();

                // Auch die Adapterliste: ein VPN-Adapter oder ein Dock kommt
                // und geht, und eine Liste vom Programmstart waere dann falsch.
                _shell.RefreshCustomTargetAdapters();
            };
        }

        // Die Version gehoert in den Titel: die letzte Stelle wird bei jeder
        // Veroeffentlichung hochgezaehlt, und bei einer Rueckfrage ist das die
        // erste Angabe, nach der gefragt wird. Vierstellig, wie sie in der
        // csproj steht.
        Title = $"My Network Monitor  v{OwnVersion()}";

        // Beim Ausprobieren mit zwei Instanzen muss man sie auseinanderhalten
        // koennen - der Name des Zustandsordners steht dafuer im Titel.
        if (AppPaths.HasOwnState)
        {
            string root = System.IO.Path.GetDirectoryName(SettingsFolder()) ?? string.Empty;
            Title += $" - {System.IO.Path.GetFileName(root)}";
        }

        // Die Adapterliste fuer die eigene Eingabe. Wird beim Oeffnen der
        // Auswahl neu gelesen - ein VPN oder ein Dock kommt und geht.
        _shell.RefreshCustomTargetAdapters();

        BuildServiceFacets();
        BuildScopeFacets();
        BuildFindServicePortMenu();
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
    /// Alle heute vorhandenen Verfahren. Die Liste selbst steht seit dem
    /// Satellitendienst in Core (<see cref="ScanEngineFactory"/>) - der Dienst
    /// laeuft ohne Fenster und braucht dieselben Verfahren.
    /// </summary>
    private static void RegisterMethods(ScanEngine engine) =>
        ScanEngineFactory.RegisterAllMethods(engine, ServiceXmlPath());

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
        // Eine zweite Instanz zum Ausprobieren bekommt ueber --state ihren
        // eigenen Ordner - sonst schrieben beide in dieselben Dateien und
        // loeschten sich gegenseitig die Bereiche und den letzten Lauf.
        if (AppPaths.OwnSettingsFolder is { } own) return own;

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
    // ------------------------------------------------------- Satellitenbetrieb

    /// <summary>Die eigene Version, wie sie die Gegenstelle sehen soll.</summary>
    private static string OwnVersion() =>
        System.Reflection.Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? string.Empty;

    /// <summary>
    /// Haengt Lauscher und Verbinder ein. Beides haengt an einer Einstellung -
    /// wer den Satellitenbetrieb nicht will, merkt nichts davon.
    /// </summary>
    private void StartSatelliteLink()
    {
        // Die Ereignisse treffen auf Hintergrund-Threads ein, die Liste haengt
        // aber an der Anzeige.
        _shell.SatelliteEditor.Post = action => global::Avalonia.Threading.Dispatcher.UIThread.Post(action);

        _shell.SatelliteEditor.SetAppVersion(OwnVersion());
        _shell.SatelliteEditor.RefreshFirewall();

        // Erst den Dienst befragen: laeuft er, gehoert ihm die Verbindung nach
        // draussen, und dieses Fenster verbindet sich nicht selbst.
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

    /// <summary>Liest Name, Domaene und Adressen dieser Anlage neu.</summary>
    private void bt_HostInfoRefresh_Click(object? sender, RoutedEventArgs e) =>
        _shell.SatelliteEditor.RefreshHostInfo();

    /// <summary>
    /// Uebernimmt einen Port aus der Firewall-Auswahl als Lauschport. Die Liste
    /// ist damit eine Auswahl und nicht nur eine Auskunft: wer keine Rechte hat,
    /// eine Regel anzulegen, sucht sich hier einen Port, der ohnehin offen ist.
    /// </summary>
    private void cb_AllowedPorts_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        if (!_ready || sender is not ComboBox list || list.SelectedItem is not string entry) return;

        // Die Zeile sieht aus wie "TCP 5900-5904  (only for ...)". Genommen
        // wird die erste Zahl - bei einem Bereich der Anfang, denn irgendeiner
        // muss es sein, und der erste ist der naheliegende.
        string digits = new([.. entry.SkipWhile(c => !char.IsDigit(c)).TakeWhile(char.IsDigit)]);

        if (int.TryParse(digits, out int port) && port is > 0 and <= 65535)
        {
            _shell.Settings.SatelliteListenPort = port;
        }
    }

    // ---------------------------------------------------- Empfaenger (Hosts)

    private void bt_SatelliteConnect_Click(object? sender, RoutedEventArgs e)
    {
        // Der Knopf setzt den Schalter mit: wer hier verbindet, will es auch
        // beim naechsten Start.
        _shell.Settings.SatelliteModeEnabled = true;

        _shell.SatelliteEditor.ConnectAllHosts();
    }

    private void bt_SatelliteDisconnect_Click(object? sender, RoutedEventArgs e)
    {
        _shell.Settings.SatelliteModeEnabled = false;
        _shell.SatelliteEditor.DisconnectAllHosts();
    }

    private void LoadScopes()
    {
        // Die Satelliten zuerst: die Bereichsmaske bietet ihre Namen zur
        // Auswahl an, und eine Auswahl, die beim Laden des Bereichs noch leer
        // ist, verwirft dessen gespeicherten Wert.
        _shell.SatelliteEditor.Load(SettingsFolder());

        // Bis zur Hostliste gab es genau einen Hauptscanner als Einstellung.
        // Wer den gesetzt hatte, findet ihn als ersten Eintrag wieder, statt
        // ihn neu eintippen zu muessen.
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

        // Bereiche zeigten frueher auf den Namen des Satelliten. Einmalig auf
        // die Kennung umschreiben - danach ueberlebt die Zuordnung jede
        // Umbenennung. Was sich nicht zuordnen laesst, bleibt stehen und wird
        // beim Lauf als "nicht verbunden" gemeldet.
        _shell.MigrateScannedByToIds();

        _shell.RefreshAvailability();

        // Erst jetzt: der Lauscher gibt nur frei, wer in der geladenen Liste
        // steht - vorher waere jeder Satellit "unbekannt".
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

        // Der Quervergleich sitzt mitten in der Liste, direkt hinter der
        // Rueckwaertsaufloesung: er gehoert thematisch zwischen die beiden
        // DNS-Verfahren und nicht unter alle Verfahren der Spalte.
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

                // Der Tooltip erklaert das Verfahren in ganzen Saetzen. Als
                // blosser Text laeuft er auf eine Zeile hinaus, die breiter ist
                // als der Bildschirm - darum ein umbrechender TextBlock mit
                // fester Hoechstbreite statt der Zeichenkette selbst.
                TextBlock hint = new()
                {
                    FontSize = 11,
                    TextWrapping = global::Avalonia.Media.TextWrapping.Wrap,
                    MaxWidth = 320
                };

                hint.Bind(TextBlock.TextProperty,
                    new global::Avalonia.Data.Binding(nameof(ScanMethodChoice.Hint)) { Source = choice });

                ToolTip.SetTip(box, hint);

                // Ausgegraute Verfahren zeigen sonst gar nichts an - gerade
                // dort will man aber wissen, warum.
                ToolTip.SetShowOnDisabled(box, true);

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

                if (extra is not null && choice.Id == after) boxes.Add(extra);
            }

            target.ItemsSource = boxes;
        }
    }

    /// <summary>
    /// Das Kaestchen des DNS-Quervergleichs. Kein eigenes Verfahren, sondern
    /// eine Unterfunktion des Namensscans - eingerueckt, damit man das sieht,
    /// und gesperrt, solange keines der beiden DNS-Verfahren angehakt ist.
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
    /// Haelt die Mehrfachauswahl der Gerätetabelle im Ansichtsmodell nach.
    /// <c>SelectedItem</c> kennt nur die zuletzt angeklickte Zeile; das
    /// erneute Scannen soll aber alle markierten treffen, so wie es die
    /// alte Oberflaeche ueber <c>SelectedCells</c> getan hat.
    /// </summary>
    private void dg_Devices_SelectionChanged(object? sender, SelectionChangedEventArgs e)
    {
        _shell.Devices.SelectedDevices.Clear();

        foreach (Device device in dg_Devices.SelectedItems.OfType<Device>())
        {
            _shell.Devices.SelectedDevices.Add(device);
        }
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

    /// <summary>
    /// Die Bereichsauswahl, gebaut wie die Dienstauswahl. Angezeigt wird je
    /// Bereich, wie viele Geraete daraus stammen und wie viele davon gerade
    /// antworten - daran sieht man, ob sich das Filtern ueberhaupt lohnt.
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

    // Nicht "ScopesNone": so heisst bereits das Zuruecksetzen der
    // Umfangs-Auswahl im Kommandobalken. Zwei verschiedene Dinge - was
    // gescannt wird und wonach gefiltert wird - duerfen nicht denselben
    // Namen tragen.
    /// <summary>
    /// Fuellt das Untermenue der Portsuche mit den Diensten. Ein Dienst je
    /// Eintrag - die Suche laeuft ueber 65 536 Ports und dauert; sie fuer alle
    /// Dienste auf einmal anzubieten waere ein Klick, nach dem man eine
    /// Viertelstunde wartet.
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
        view_Satellites.IsVisible = section == ShellSection.Satellites;
        view_Settings.IsVisible = section == ShellSection.Settings;
        view_Network.IsVisible = section == ShellSection.Network;
        view_Findings.IsVisible = section == ShellSection.Findings;

        // Die Webansicht wird erst hier eingehaengt, und erst beim ersten Mal.
        // Vor dem Sichtbarschalten, damit sie beim Aufschlagen schon steht -
        // aber eben nur, wenn der Nutzer die Topologie ueberhaupt aufruft.
        if (section == ShellSection.Topology) PrepareTopologyView();

        view_Topology.IsVisible = section == ShellSection.Topology;

        // Beim Aufschlagen neu pruefen: die Adapterregel liest den Zustand des
        // Rechners, und der aendert sich auch ohne Scan.
        if (section == ShellSection.Findings) _shell.FindingsView.Refresh();

        // Adapter kommen und gehen - ein VPN-Client, ein Dock, ein Stick.
        // Beim Aufschlagen der Ansicht neu lesen ist billiger als der
        // Versuch, das mitzubekommen.
        if (section == ShellSection.Network) _shell.NetworkView.Refresh();

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
    /// Welcher Unterbau der eingebetteten Webansicht auf diesem System zur
    /// Verfuegung steht.
    /// </summary>
    private enum WebEngine
    {
        /// <summary>Kein Unterbau vorhanden - es bleibt nur der Browser.</summary>
        None,

        /// <summary>Der Normalfall: Windows WebView2 oder Linux mit WPE WebKit.</summary>
        Native,

        /// <summary>Linux ohne WPE, aber mit WebKitGTK - eingebettet ueber den Ersatzweg.</summary>
        WebKitGtk
    }

    /// <summary>
    /// Die nativen Bibliotheken, die die eingebettete Ansicht unter Linux
    /// braucht.
    /// <para>
    /// Der Linux-Unterbau von <c>NativeWebView</c> ist nicht WebKitGTK, sondern
    /// <b>WPE WebKit</b> - die Namen stehen als P/Invoke-Ziele in
    /// <c>Avalonia.Controls.WebView.dll</c>. Debian 13 hat die Pakete, aber
    /// installiert sie nicht von sich aus; fehlen sie, scheitert der Ladevorgang
    /// im nativen Teil und nimmt den Prozess mit, statt eine Ausnahme zu werfen,
    /// die sich abfangen liesse. Darum wird vorher geprueft statt hinterher
    /// aufgefangen.
    /// </para>
    /// </summary>
    private static readonly string[] WpeLibraries =
    [
        "libWPEWebKit-2.0.so.1",
        "libwpe-1.0.so.1",
        "libWPEBackend-fdo-1.0.so.1"
    ];

    /// <summary>Die GTK-Webengine, der dokumentierte Ersatzweg unter Linux.</summary>
    private static readonly string[] WebKitGtkLibraries =
    [
        "libwebkit2gtk-4.1.so.0",
        "libwebkit2gtk-4.0.so.37"
    ];

    /// <summary>
    /// Ordnet jeder Bibliothek aus <see cref="WpeLibraries"/> das apt-Paket zu,
    /// das sie mitbringt - nur so laesst sich der Hinweistext auf das
    /// beschraenken, was tatsaechlich fehlt.
    /// </summary>
    private static readonly IReadOnlyDictionary<string, string> WpePackageBySoName =
        new Dictionary<string, string>
        {
            ["libWPEWebKit-2.0.so.1"] = "libwpewebkit-2.0-1",
            ["libwpe-1.0.so.1"] = "libwpe-1.0-1",
            ["libWPEBackend-fdo-1.0.so.1"] = "libwpebackend-fdo-1.0-1"
        };

    /// <summary>
    /// Die apt-Pakete fuer die WPE-Bibliotheken, die auf diesem System fehlen.
    /// Leer, wenn WPE vollstaendig vorhanden ist.
    /// </summary>
    private static IEnumerable<string> MissingWpePackages() =>
        WpeLibraries.Where(lib => !IsLibraryPresent(lib)).Select(lib => WpePackageBySoName[lib]);

    /// <summary>
    /// Was in der Statuszeile steht, wenn der Graph im Browser geoeffnet wurde.
    /// Nennt die Ursache und die Abhilfe beim Namen - "geht nicht" allein hilft
    /// niemandem weiter. Listet nur die Pakete, die auf diesem System
    /// tatsaechlich fehlen, statt pauschal alle drei - und nennt den echten
    /// Grund, wenn WPE zwar da, das Embedding aber absichtlich aus ist.
    /// </summary>
    private static string NoEmbeddedViewHint()
    {
        if (OperatingSystem.IsLinux() && !EmbeddedWebViewEnabledOnLinux && WpeLibraries.All(IsLibraryPresent))
        {
            return "Opened in your browser: the embedded view is disabled on Linux for now - " +
                   "it loads the page but never paints it (Avalonia.Controls.WebView issue, not a missing package).";
        }

        return "Opened in your browser: this system has no embedded web engine. " +
               "To get the view back inside the window, install WPE WebKit - on Debian and " +
               "Ubuntu that is: sudo apt install " + string.Join(' ', MissingWpePackages());
    }

    /// <summary>
    /// Unter Linux abgeschaltet, obwohl die Erkennung und das Control fertig
    /// dastehen. Getestet mit vollstaendig installiertem WPE (alle drei
    /// Bibliotheken vorhanden, Prozesse starten, Seite laedt laut
    /// <c>NavigationCompleted</c> erfolgreich, JavaScript und WebGL laufen) -
    /// im Fenster bleibt es trotzdem leer. Es ist also nicht die Erkennung
    /// oder das Nachladen, sondern die Bruecke zwischen WPEs Offscreen-Puffer
    /// und Avalonias Compositor in <c>Avalonia.Controls.WebView</c> 12.0.1,
    /// die auf diesem Weg nichts zeichnet. Ein kaputtes Embedding, das Erfolg
    /// meldet, ist schlimmer als gar keins - deshalb bleibt es auf
    /// <see cref="WebEngine.None"/> und damit beim Systembrowser, bis eine
    /// neuere Paketversion das Zeichnen tatsaechlich zustande bringt.
    /// </summary>
    private const bool EmbeddedWebViewEnabledOnLinux = false;

    /// <summary>
    /// Bestimmt, womit die eingebettete Ansicht arbeiten kann.
    /// <para>
    /// Geprueft wird durch Laden der Bibliothek und nicht durch einen Versuch,
    /// das Control zu erzeugen: der Fehlversuch beendet den Prozess, und ein
    /// <c>try</c> darum herum hilft dagegen nicht.
    /// </para>
    /// </summary>
    private static WebEngine AvailableWebEngine()
    {
        // Windows und macOS bringen ihre Engine mit.
        if (!OperatingSystem.IsLinux()) return WebEngine.Native;

        if (!EmbeddedWebViewEnabledOnLinux) return WebEngine.None;

        if (WpeLibraries.All(IsLibraryPresent)) return WebEngine.Native;
        if (WebKitGtkLibraries.Any(IsLibraryPresent)) return WebEngine.WebKitGtk;

        return WebEngine.None;
    }

    /// <summary>
    /// Der Unterbau, den die Webansicht auf diesem System bekommt. Einmal
    /// beim Erzeugen bestimmt.
    /// </summary>
    private WebEngine _webEngine = WebEngine.Native;

    /// <summary>
    /// Bereitet die Topologie-Ansicht vor, <b>bevor</b> sie zum ersten Mal
    /// sichtbar wird.
    /// <para>
    /// Das ist der Kern der Sache: <c>NativeWebView</c> erzeugt seinen nativen
    /// Unterbau, sobald das Control in den sichtbaren Baum kommt - also
    /// bereits beim Umschalten auf den Abschnitt, nicht erst beim Zeichnen.
    /// Scheitert das unter Linux mangels WPE, bricht der Wechsel mittendrin ab
    /// und die vorherige Ansicht bleibt stehen. Genau dieses Bild.
    /// </para>
    /// <para>
    /// Darum wird das Control hier entweder auf den GTK-Ersatzweg gestellt
    /// oder ganz aus dem Baum genommen - was nicht da ist, kann sich auch
    /// nicht aufbauen.
    /// </para>
    /// </summary>
    /// <summary>Die eingebettete Webansicht - erst vorhanden, wenn sie gebraucht wird.</summary>
    private NativeWebView? _webTopology;

    private bool _topologyPrepared;

    /// <summary>
    /// Haengt die Webansicht ein - beim ersten Aufschlagen der Topologie und
    /// nicht frueher.
    /// <para>
    /// <b>Warum so spaet:</b> die Anwendung darf beim Start nicht davon
    /// abhaengen, dass eine Webengine vorhanden und heil ist. Ein Fehlschlag
    /// unter Linux ist ein nativer Absturz, kein Fehler, den man abfangen kann.
    /// Passiert er beim Erzeugen des Hauptfensters, verschwindet die ganze
    /// Anwendung - und niemand kommt darauf, dass es an der Topologie lag, die
    /// man gar nicht geoeffnet hat. Passiert er hier, hat der Nutzer gerade auf
    /// "Topology" geklickt, und der Zusammenhang ist offensichtlich.
    /// </para>
    /// </summary>
    private void PrepareTopologyView()
    {
        if (_topologyPrepared) return;
        _topologyPrepared = true;

        _webEngine = AvailableWebEngine();

        if (_webEngine == WebEngine.None)
        {
            // Kein Unterbau: gar nicht erst erzeugen. An seine Stelle kommt,
            // was fehlt und wie es zu beheben ist - oder, falls WPE zwar da
            // ist aber absichtlich abgeschaltet, dass es an Avalonia liegt
            // und nicht an einer fehlenden Bibliothek.
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
                      "sudo apt install " + string.Join(' ', MissingWpePackages()),
                FontSize = 11.5,
                TextWrapping = global::Avalonia.Media.TextWrapping.Wrap,
                Foreground = new SolidColorBrush(Color.Parse("#5C6F73")),
                VerticalAlignment = VerticalAlignment.Top
            });

            return;
        }

        _webTopology = new NativeWebView();

        // Ohne WPE, aber mit GTK: der dokumentierte Ersatzweg. Der Haken muss
        // stehen, bevor das Control seinen Unterbau erzeugt - also jetzt.
        if (_webEngine == WebEngine.WebKitGtk) PreferWebKitGtk(_webTopology);

        host_Topology.Children.Add(_webTopology);
    }

    /// <summary>
    /// Ob eine native Bibliothek auf diesem System vorhanden ist.
    /// <para>
    /// <b>Bewusst ohne sie zu laden.</b> Die naheliegende Fassung -
    /// <c>NativeLibrary.TryLoad</c> und anschliessend <c>Free</c> - ist genau
    /// hier gefaehrlich: <c>Free</c> ist ein <c>dlclose</c>, und WebKit, GTK und
    /// WPE vertragen das nicht. Sie registrieren GObject-Typen, halten
    /// threadlokalen Zustand und haengen sich in <c>atexit</c>; werden sie
    /// wieder entladen, bleiben Zeiger auf Code stehen, den es nicht mehr gibt,
    /// und der Prozess stirbt - ohne Ausnahme, die sich abfangen liesse.
    /// </para>
    /// <para>
    /// Gesucht wird darum im Verzeichnis, so wie es auch der dynamische Linker
    /// tut: erst der Zwischenspeicher von <c>ldconfig</c>, dann die ueblichen
    /// Pfade als Rueckfall.
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
    /// Die Namen aller dem Linker bekannten Bibliotheken. Einmal gelesen, denn
    /// dafuer laeuft ein fremder Prozess.
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

            // Zeilenformat: "\tlibfoo.so.1 (libc6,x86-64) => /usr/lib/libfoo.so.1"
            foreach (string line in output.Split('\n'))
            {
                string trimmed = line.Trim();
                int space = trimmed.IndexOf(' ');

                if (space > 0) names.Add(trimmed[..space]);
            }
        }
        catch (Exception)
        {
            // Kein ldconfig erreichbar - dann entscheidet die Suche im
            // Verzeichnis allein.
        }

        return names;
    });

    /// <summary>
    /// Schaltet die Ansicht auf den GTK-Unterbau um.
    /// <para>
    /// Der Schalter kommt ueber <c>EnvironmentRequested</c>: das Ereignis wird
    /// gerufen, waehrend die Ansicht ihren Unterbau aufbaut, und die
    /// Ereignisdaten sind je Plattform andere. Unter Linux sind es
    /// <c>LinuxWpeWebViewEnvironmentRequestedEventArgs</c> - nur dort gibt es
    /// <c>PreferWebKitGtkInstead</c>, darum die Pruefung auf den Typ statt auf
    /// das Betriebssystem.
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

        // Welche Sicht gezeichnet wird, entscheidet allein der Schalter - der
        // Weg dorthin ist ab hier ein anderer, damit die Netzansicht von der
        // Dienstansicht nichts mitbekommt.
        bool services = rb_TopologyService.IsChecked == true;

        try
        {
            tb_TopologyHint.Text = $"Drawing {devices.Count} devices...";

            // Der Unterbau steht seit dem Erzeugen des Fensters fest - er wird
            // hier nur noch benutzt. Ihn jetzt erst zu bestimmen waere zu
            // spaet: die Ansicht ist beim Umschalten laengst aufgebaut worden.
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

        // Die Satelliten schreiben bei jeder Aenderung sofort - kein
        // Zeitgeber, keine Verzoegerung, weil die Liste kurz ist. Der Aufruf
        // hier ist der Gurt fuer den Fall, dass doch etwas offen blieb.
        _shell.SatelliteEditor.Save();
        _shell.SatelliteEditor.SaveHosts();

        // Verbindungen sauber schliessen, damit die Gegenstellen sofort
        // merken, dass hier Schluss ist, statt in eine Zeitgrenze zu laufen.
        // Der Dienst ist davon nicht betroffen - er laeuft weiter, und genau
        // dafuer gibt es ihn.
        _shell.SatelliteEditor.StopListening();
        _shell.SatelliteEditor.DisconnectAllHosts();

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
