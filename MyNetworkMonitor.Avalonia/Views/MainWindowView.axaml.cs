using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Avalonia.Collections;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Avalonia.Media.Imaging;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using MyNetworkMonitor.Avalonia.Controls;
using MyNetworkMonitor.Avalonia.Platform;
using MyNetworkMonitor.Core.Persistence;
using MyNetworkMonitor.Core.Services;
using MyNetworkMonitor.Core.ViewModels;

namespace MyNetworkMonitor.Avalonia.Views
{
    /// <summary>
    /// Avalonia-Portierung des WPF-MainWindow.
    /// Schritt 1 der Funktions-Portierung: Initialisierung (Einstellungs-XMLs,
    /// DataGrid-Bindung), Tab "From NIC" (Adapterauswahl, Subnetz-Felder,
    /// IP-Anzahl, TimeOut) sowie die Infos-Buttons und der Zeilenzaehler.
    /// Die uebrigen Handler (Scans, Filter, Export, Gruppierung) folgen in den
    /// naechsten Schritten und sind hier noch Stubs.
    /// </summary>
    public partial class MainWindowView : Window
    {
        private static readonly CultureInfo GermanCulture = CultureInfo.GetCultureInfo("de-DE");

        /// <summary>
        /// Muss exakt dem WPF-Pfad entsprechen, damit beide Versionen dieselben
        /// Einstellungen lesen. Achtung: bei aktivem OneDrive-Ordnerschutz zeigt
        /// SpecialFolder.MyDocuments nach OneDrive, %userprofile%\Documents aber
        /// auf den lokalen Ordner - WPF nutzt letzteren.
        /// </summary>
        private static readonly string _settingsFolder = BuildSettingsFolder();

        private static string BuildSettingsFolder()
        {
            string documents = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                ? Path.Combine(Environment.ExpandEnvironmentVariables("%userprofile%"), "Documents")
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents");

            return Path.Combine(documents, "MyNetworkMonitor", "Settings");
        }

        private readonly string _portsToScanXML = Path.Combine(_settingsFolder, "portsToScan.xml");
        private readonly string _ipGroupsXML = Path.Combine(_settingsFolder, "ipGroups.xml");
        private readonly string _lastScanResultXML = Path.Combine(_settingsFolder, "lastScanResult.xml");
        private readonly string _InternalNamesXML = Path.Combine(_settingsFolder, "internalNames.xml");
        private readonly string _ServicesXML = Path.Combine(_settingsFolder, "services.xml");

        private List<NicInfo> nicInfos = new List<NicInfo>();
        private bool TextChangedByComboBox;
        private int _TimeOut = 1000;

        private readonly ScanResults _scannResults = new ScanResults();
        private readonly PortCollection _portCollection = new PortCollection();
        private readonly IPGroupData ipGroupData = new IPGroupData();
        private readonly InternalDeviceNames _internalNames = new InternalDeviceNames();

        private DataView? dv_resultTable;
        private DataView? dv_InternalNames;

        /// <summary>
        /// Pendants zu den CollectionViewSources des WPF-Fensters
        /// (cvTasks_scanResults / cvTasks_IP_Ranges). Ueber sie wird die
        /// Gruppierung zur Laufzeit umgeschaltet.
        /// </summary>
        private DataGridCollectionView? cv_resultTable;
        private DataGridCollectionView? cv_IP_Ranges;

        /// <summary>Im WPF ueber AutoGeneratingColumn ausgeblendete Spalten.</summary>
        private static readonly string[] HiddenResultColumns = { "IPGroupDescription", "IPToSort" };
        private static readonly string[] HiddenIPRangeColumns = { "IPGroupDescription", "AutomaticScan", "ScanIntervalMinutes" };

        /// <summary>Die Spalte "IP" sortiert wie in WPF ueber "IPToSort".</summary>
        private static readonly Dictionary<string, string> ResultSortOverrides = new() { ["IP"] = "IPToSort" };

        /// <summary>
        /// Spalten, deren Werte aus der Scan-Logik mit Tabulatoren gegliedert
        /// kommen und darum spaltenweise ausgerichtet dargestellt werden.
        /// </summary>
        private static readonly string[] TabularResultColumns =
            { "SNMPInfos", "detectedServicePorts", "LookUpIPs", "mDNSInfos" };

        private ScanningMethod_Services? scanningMethod_Services;

        /// <summary>Ersetzt WPFs Properties.Settings.</summary>
        private readonly UserSettings _userSettings = new(_settingsFolder);

        public MainWindowView()
        {
            InitializeComponent();

            // Vierstellig ausgeben (5.1.0.3): die letzte Stelle wird bei jeder
            // Veroeffentlichung hochgezaehlt und gehoert deshalb in den Titel.
            Version? version = Assembly.GetExecutingAssembly().GetName().Version;
            Title += " - version: " + (version?.ToString() ?? string.Empty);

            if (!Directory.Exists(_settingsFolder)) Directory.CreateDirectory(_settingsFolder);

            chk_dg_Result_ShowEmptyColumns.IsChecked = _userSettings.GetBool("ShowEmptyColumns", true);

            LoadNetworkInterfaces();
            LoadSettingsTables();
            InitializeScanners();
            LoadLogo();

            // WPF erledigte das in mainWindow_Loaded
            Loaded += async (_, _) =>
            {
                await reGroupScanResult();
                HideEmptyColumnsFromDataTable();
            };
        }

        // ------------------------------------------------------------------
        // Initialisierung
        // ------------------------------------------------------------------

        private void LoadNetworkInterfaces()
        {
            nicInfos = new Supporter_NetworkInterfaces().GetNetworkInterfaces();
            cb_NetworkAdapters.ItemsSource = nicInfos.Select(n => n.NicName).ToList();
            if (nicInfos.Count > 0) cb_NetworkAdapters.SelectedIndex = 0;
        }

        private void LoadSettingsTables()
        {
            // Ergebnistabelle des letzten Scans
            if (File.Exists(_lastScanResultXML))
            {
                try { _scannResults.ResultTable.ReadXml(_lastScanResultXML); }
                catch (Exception) { /* beschaedigte Datei ignorieren */ }
            }
            _scannResults.ResultTable.RowChanged += (s, e) => UpdateRowCount();
            _scannResults.ResultTable.RowDeleted += (s, e) => UpdateRowCount();

            dv_resultTable = new DataView(_scannResults.ResultTable);
            cv_resultTable = DataTableGridSource.Bind(dgv_Results, dv_resultTable,
                                                      HiddenResultColumns, ResultSortOverrides,
                                                      TabularResultColumns);
            ApplyScanResultGrouping();

            // IP-Gruppen
            if (File.Exists(_ipGroupsXML))
            {
                try { ipGroupData.IPGroupsDT.ReadXml(_ipGroupsXML); }
                catch (Exception) { }
            }
            cv_IP_Ranges = DataTableGridSource.Bind(dgv_IP_Ranges, ipGroupData.IPGroupsDT.DefaultView,
                                                    HiddenIPRangeColumns);
            ApplyIPRangeGrouping();

            // Ports
            if (File.Exists(_portsToScanXML))
            {
                try
                {
                    _portCollection.TableOfPortsToScan.Rows.Clear();
                    _portCollection.TableOfPortsToScan.ReadXml(_portsToScanXML);
                }
                catch (Exception) { }
            }
            else
            {
                _portCollection.TableOfPortsToScan.WriteXml(_portsToScanXML);
            }
            BindDataTable(dg_PortsToScan, _portCollection.TableOfPortsToScan.DefaultView);

            // Interne Namen
            if (File.Exists(_InternalNamesXML))
            {
                try { _internalNames.InternalNames.ReadXml(_InternalNamesXML); }
                catch (Exception) { }
            }
            dv_InternalNames = _internalNames.InternalNames.DefaultView;
            BindDataTable(dg_InternalNames, dv_InternalNames);

            // Services (Spalten stehen im AXAML, Gruppierung wie in WPF nach ServiceGroup)
            scanningMethod_Services = new ScanningMethod_Services(_ServicesXML);
            DataTableGridSource.BindGrouped(dg_Services, scanningMethod_Services.Services.DefaultView,
                                            "ServiceGroup", keepColumns: true);

            UpdateRowCount();
        }

        private static void BindDataTable(DataGrid grid, DataView view)
            => DataTableGridSource.Bind(grid, view);

        private void UpdateRowCount()
        {
            rowCountTextBlock.Text = $"{_scannResults.ResultTable.Rows.Count} Devices, {dv_resultTable?.Count ?? 0} Filtered";
        }

        private void LoadLogo()
        {
            string folder = "images";
            foreach (string ext in new[] { ".png", ".jpg", ".jpeg" })
            {
                string path = Path.Combine(folder, "logo" + ext);
                if (!File.Exists(path)) continue;

                try { img_Logo.Source = new Bitmap(path); }
                catch (Exception) { }
                return;
            }
        }

        // ------------------------------------------------------------------
        // From NIC
        // ------------------------------------------------------------------

        private void cb_NetworkAdapters_SelectionChanged(object? sender, SelectionChangedEventArgs e)
        {
            if (cb_NetworkAdapters.SelectedItem == null) return;

            string selectedNicName = cb_NetworkAdapters.SelectedItem.ToString()!;
            NicInfo? n = nicInfos.FirstOrDefault(nic => nic.NicName == selectedNicName);
            if (n == null) return;

            TextChangedByComboBox = true;

            tb_AdapterIP.Text = n.IPv4;
            tb_AdapterSubnetMask.Text = n.IPv4Mask;
            tb_Adapter_FirstSubnetIP.Text = n.FirstSubnetIP;
            tb_Adapter_LastSubnetIP.Text = n.LastSubnetIP;
            lb_IPsToScan.Content = n.IPsCount.ToString("n0", GermanCulture);

            SupportMethods.SelectedNetworkInterfaceInfos.Name = selectedNicName;
            SupportMethods.SelectedNetworkInterfaceInfos.IPv4 =
                !string.IsNullOrEmpty(n.IPv4) ? IPAddress.Parse(n.IPv4) : null!;

            NetworkInterface? nic = NetworkInterface.GetAllNetworkInterfaces()
                                                    .FirstOrDefault(ni => ni.Name == selectedNicName);
            lstb_DNSServers.ItemsSource = nic != null
                ? nic.GetIPProperties().DnsAddresses.Select(dns => dns.ToString()).ToList()
                : new List<string> { "" };

            TextChangedByComboBox = false;
        }

        private void tb_Adapter_FirstSubnetIP_TextChanged(object? sender, TextChangedEventArgs e) => UpdateIPsToScanCount();

        private void tb_Adapter_LastSubnetIP_TextChanged(object? sender, TextChangedEventArgs e) => UpdateIPsToScanCount();

        private void UpdateIPsToScanCount()
        {
            if (TextChangedByComboBox) return;

            try
            {
                lb_IPsToScan.Content = "calc. number of IPs";
                lb_IPsToScan.Content = new IpRanges.IPRange()
                    .NumberOfIPsInRange(tb_Adapter_FirstSubnetIP.Text ?? string.Empty,
                                        tb_Adapter_LastSubnetIP.Text ?? string.Empty)
                    .ToString("n0", GermanCulture);
            }
            catch (Exception)
            {
                lb_IPsToScan.Content = "...";
            }
        }

        private void slider_TimeOut_ValueChanged(object? sender, RangeBaseValueChangedEventArgs e)
        {
            _TimeOut = (int)e.NewValue;
        }


        // ------------------------------------------------------------------
        // Infos
        // ------------------------------------------------------------------

        private void bt_openApplicationFolder_Click(object? sender, RoutedEventArgs e)
            => OpenFolder(AppContext.BaseDirectory);

        private void bt_openSettingsFolder_Click(object? sender, RoutedEventArgs e)
            => OpenFolder(_settingsFolder);

        private static void OpenFolder(string path)
        {
            if (!Directory.Exists(path)) return;

            // Plattformneutral: Windows explorer, Linux xdg-open, macOS open
            string fileName = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "explorer"
                            : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "open"
                            : "xdg-open";

            try { Process.Start(new ProcessStartInfo(fileName, path) { UseShellExecute = true }); }
            catch (Exception) { }
        }

        private void bt_PayPal_Click(object? sender, RoutedEventArgs e)
            => new PayPalDonationView().Show(this);

        // ------------------------------------------------------------------
        // noch offen (folgende Schritte)
        // ------------------------------------------------------------------

        // ---- From IP Ranges ----

        private async void bt_Edit_IP_Range_Click(object? sender, RoutedEventArgs e)
        {
            var viewModel = new ManageIPGroupsViewModel(ipGroupData.IPGroupsDT, _ipGroupsXML,
                                                        new AvaloniaDialogService());

            await new ManageIPGroupsView(viewModel).ShowDialog(this);

            // Die Gruppenverwaltung schreibt in dieselbe DataTable-Instanz zurueck
            cv_IP_Ranges = DataTableGridSource.Bind(dgv_IP_Ranges, ipGroupData.IPGroupsDT.DefaultView,
                                                    HiddenIPRangeColumns);
            ApplyIPRangeGrouping();
        }

        private void chk_IPRanges_groupDevices_Click(object? sender, RoutedEventArgs e) => ApplyIPRangeGrouping();

        private void ApplyIPRangeGrouping()
        {
            DataTableGridSource.SetGrouping(cv_IP_Ranges,
                chk_IPRanges_groupDevices.IsChecked == true ? new[] { "DeviceDescription" } : Array.Empty<string>());
        }


        // ---- Ports To Scan ----
        private void bt_SavePortsToScan_Click(object? sender, RoutedEventArgs e)
        {
            DataView dv = _portCollection.TableOfPortsToScan.DefaultView;
            dv.Sort = "Ports asc";
            dv.ToTable().WriteXml(_portsToScanXML, XmlWriteMode.WriteSchema);
        }

        // ---- Services ----

        private void dg_ServicesGetDefaultPorts_Click(object? sender, RoutedEventArgs e)
        {
            if (dg_Services.SelectedItem is not DataRowProxy row) return;

            if (!Enum.TryParse<ServiceType>(row["Service"]?.ToString(), out var serviceType)) return;

            row["Ports"] = string.Join(", ", ScanningMethod_Services.GetDefaultServicePorts(serviceType));
        }

        // WPF-Original: beide Handler sind leer (Filter derzeit ohne Funktion)
        private void chk_Services_showOnlyIsRunning_Changed(object? sender, RoutedEventArgs e) { }

        // ---- Hostname Mapping ----

        private void bt_SaveNames_Click(object? sender, RoutedEventArgs e)
        {
            DataView dv = _internalNames.InternalNames.DefaultView;
            dv.Sort = "Hostname asc";
            dv.ToTable().WriteXml(_InternalNamesXML, XmlWriteMode.WriteSchema);
        }

        private void bt_AddInternalNamesToScanResult_Click(object? sender, RoutedEventArgs e)
        {
            foreach (DataRow row in _scannResults.ResultTable.Rows)
            {
                string resultHostname = row["Hostname"].ToString()!.ToUpperInvariant();

                try
                {
                    row["InternalName"] = !string.IsNullOrEmpty(resultHostname)
                        ? _internalNames.InternalNames.Select($"Hostname = '{resultHostname}'")[0]["InternalName"].ToString()
                        : row["InternalName"];
                }
                catch (Exception)
                {
                    row["InternalName"] = string.Empty;
                }
            }

            UpdateInternalNamesHighlighting();
        }

        /// <summary>
        /// Faerbt Dubletten in der Namenstabelle ein (Spalte "RowColor", die
        /// <see cref="dg_InternalNames_LoadingRow"/> auswertet).
        /// </summary>
        private void UpdateInternalNamesHighlighting()
        {
            DataTable table = _internalNames.InternalNames;

            HashSet<string?> Duplicates(string columnName) => table.AsEnumerable()
                .GroupBy(r => r.Field<string>(columnName))
                .Where(g => !string.IsNullOrEmpty(g.Key) && g.Count() > 1)
                .Select(g => g.Key)
                .ToHashSet();

            HashSet<string?> macs = Duplicates("MAC");
            HashSet<string?> ips = Duplicates("StaticIP");
            HashSet<string?> internalNames = Duplicates("InternalName");

            HashSet<string?> scanHostnames = _scannResults.ResultTable.AsEnumerable()
                .Where(r => !r.IsNull("Hostname"))
                .Select(r => r.Field<string>("Hostname"))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            foreach (DataRow row in table.Rows)
            {
                string? mac = row["MAC"]?.ToString();
                string? ip = row["StaticIP"]?.ToString();
                string? internalName = row["InternalName"]?.ToString();
                string? hostname = row["Hostname"]?.ToString();

                row["RowColor"] = DBNull.Value;

                if (!string.IsNullOrEmpty(mac) && macs.Contains(mac)) row["RowColor"] = "Red";
                else if (!string.IsNullOrEmpty(ip) && ips.Contains(ip)) row["RowColor"] = "Yellow";
                else if (!string.IsNullOrEmpty(internalName) && internalNames.Contains(internalName)) row["RowColor"] = "LightGreen";
                else if (!string.IsNullOrEmpty(hostname) && scanHostnames.Contains(hostname)) row["RowColor"] = "#C5EDC9";
            }

            dg_InternalNames.InvalidateVisual();
        }

        /// <summary>
        /// Ersetzt WPFs DataGridRow-Style mit DataTriggern auf "RowColor".
        /// Avalonia recycelt Zeilen, deshalb wird auch der Normalfall gesetzt.
        /// </summary>
        private void dg_InternalNames_LoadingRow(object? sender, DataGridRowEventArgs e)
        {
            string? rowColor = (e.Row.DataContext as DataRowProxy)?["RowColor"]?.ToString();
            e.Row.Background = RowBrushes.FromRowColor(rowColor);
        }

        /// <summary>
        /// WPF musste hier ein vorzeitiges Refresh waehrend der Bearbeitung
        /// verhindern. Avalonia aktualisiert die Zeile ueber PropertyChanged des
        /// Zeilen-Proxys, ein Eingriff ist nicht noetig.
        /// </summary>
        private void dg_InternalNames_CellEditEnding(object? sender, DataGridCellEditEndingEventArgs e)
        {
        }

        /// <summary>
        /// Nach dem Bearbeiten koennen sich Dubletten geaendert haben - die
        /// Faerbung wird deshalb neu berechnet (WPF rief hier nur Items.Refresh).
        /// </summary>
        private void dg_InternalNames_RowEditEnding(object? sender, DataGridRowEditEndingEventArgs e)
        {
            if (e.EditAction != DataGridEditAction.Commit) return;

            Dispatcher.UIThread.Post(UpdateInternalNamesHighlighting, DispatcherPriority.Background);
        }

        /// <summary>
        /// Einfuegen aus der Zwischenablage ab der aktuellen Zelle (Tab-getrennt,
        /// wie aus Excel). In Avalonia ist der Clipboard-Zugriff async.
        /// </summary>
        private async void dg_InternalNames_ContextMenu_Click(object? sender, RoutedEventArgs e)
        {
            IClipboard? clipboard = GetTopLevel(this)?.Clipboard;
            if (clipboard == null) return;

            // Avalonia 12: Zwischenablage liefert ein IAsyncDataTransfer, das der
            // Aufrufer freigeben muss.
            using IAsyncDataTransfer? transfer = await clipboard.TryGetDataAsync();
            if (transfer == null) return;

            string clipboardText = await transfer.TryGetTextAsync() ?? string.Empty;
            if (string.IsNullOrEmpty(clipboardText)) return;

            int columnIndex = Math.Max(0, dg_InternalNames.CurrentColumn?.DisplayIndex ?? 0);
            int rowIndex = dg_InternalNames.SelectedIndex < 0 ? 0 : dg_InternalNames.SelectedIndex;

            DataTable table = _internalNames.InternalNames;

            // Nur die vier Datenspalten befuellen - "RowColor" ist Ergebnis der
            // Dublettenpruefung und darf nicht ueberschrieben werden.
            const int lastEditableColumn = 4;

            foreach (string line in clipboardText.Replace("\r\n", "\n").Split('\n'))
            {
                if (string.IsNullOrEmpty(line)) continue;

                string[] cells = line.Split('\t');

                DataRow row = rowIndex < table.Rows.Count ? table.Rows[rowIndex] : table.NewRow();

                int currentCell = 0;
                for (int i = columnIndex; i < lastEditableColumn && currentCell < cells.Length; i++)
                {
                    row[i] = cells[currentCell];
                    currentCell++;
                }

                if (row.RowState == DataRowState.Detached) table.Rows.Add(row);

                rowIndex++;
            }

            UpdateInternalNamesHighlighting();
        }

        private void tb_InternalNamesFilter_TextChanged(object? sender, TextChangedEventArgs e)
        {
            if (dv_InternalNames == null) return;

            string filter = tb_InternalNamesFilter.Text ?? string.Empty;

            dv_InternalNames.RowFilter = filter.Length == 0
                ? "1 = 1"
                : $"InternalName LIKE '%{filter}%' OR Hostname LIKE '%{filter}%'" +
                  $" OR MAC LIKE '%{filter}%' OR StaticIP LIKE '%{filter}%'";
        }

        // ---- Methoden-Raster / Scan ----

        private async void bt_ScanIP_Click(object? sender, RoutedEventArgs e) => await CheckCustomHostIP();

        /// <summary>
        /// Scan der im Feld "IP / Hostname.domain" eingetragenen Ziele. Ohne
        /// Eingabe werden die im Ergebnis markierten Zeilen erneut gescannt.
        /// </summary>
        private async Task CheckCustomHostIP()
        {
            _IPsToScan.Clear();
            List<int> TCPPorts = CollectTcpPortsFromUi();

            string input = tb_IP_Address.Text ?? string.Empty;

            if (!string.IsNullOrEmpty(input))
            {
                List<string> targets = input.Split(',').Select(s => s.Trim()).ToList();

                for (int i = 0; i < targets.Count; i++)
                {
                    string target = targets[i];
                    lbl_ScanStatus.Content = $"Resolving IP: {i + 1} / {targets.Count}";

                    if (supportMethods.Is_Valid_IP(target))
                    {
                        DataRow? groupedRow = GetIPDescription(target);

                        _IPsToScan.Add(new IPToScan
                        {
                            IPGroupDescription = groupedRow?["IPGroupDescription"]?.ToString() ?? string.Empty,
                            DeviceDescription = groupedRow?["DeviceDescription"]?.ToString() ?? string.Empty,
                            IPorHostname = target,
                            HostName = string.Empty,
                            TCPPortsToScan = TCPPorts,
                            UDPPortsToScan = null,
                            DNSServerList = new List<string> { tb_DNSServerIP.Text ?? string.Empty },
                            TimeOut = _TimeOut
                        });

                        continue;
                    }

                    IPHostEntry? entry = await scanningMethod_LookUp!.nsLookup(target);

                    if (entry != null)
                    {
                        foreach (IPAddress address in entry.AddressList)
                        {
                            DataRow? groupedRow = GetIPDescription(address.ToString());

                            var ipToScan = new IPToScan
                            {
                                IPGroupDescription = groupedRow?["IPGroupDescription"]?.ToString() ?? string.Empty,
                                DeviceDescription = groupedRow?["DeviceDescription"]?.ToString() ?? string.Empty,
                                IPorHostname = address.ToString(),
                                TCPPortsToScan = TCPPorts,
                                UDPPortsToScan = null,
                                DNSServerList = null,
                                TimeOut = _TimeOut
                            };

                            // FQDN in Hostname und Domaene zerlegen
                            if (entry.HostName.Split('.').Length > 2)
                            {
                                string[] parts = entry.HostName.Split(new[] { '.' }, 2);
                                ipToScan.HostName = parts.Length > 0 ? parts[0] : string.Empty;
                                ipToScan.Domain = parts.Length > 1 ? parts[1] : string.Empty;
                            }
                            else
                            {
                                ipToScan.HostName = entry.HostName;
                            }

                            _IPsToScan.Add(ipToScan);
                        }
                    }
                    else if (chk_ShowNotRegisteredHostnames.IsChecked == true)
                    {
                        InsertIPToScanResult(new IPToScan
                        {
                            HostName = target,
                            IPorHostname = "000.000.000.000",
                            UsedScanMethod = ScanMethod.dontResolvedHostname
                        });
                    }
                }
            }
            else
            {
                foreach (DataRow row in SelectedResultRows())
                {
                    string ip = row["IP"].ToString() ?? string.Empty;
                    if (_IPsToScan.Any(i => i.IPorHostname == ip)) continue;

                    _IPsToScan.Add(new IPToScan
                    {
                        IPGroupDescription = row["IPGroupDescription"].ToString(),
                        DeviceDescription = row["DeviceDescription"].ToString(),
                        IPorHostname = ip,
                        HostName = row["Hostname"].ToString(),
                        Domain = row["Domain"].ToString(),
                        TCPPortsToScan = TCPPorts,
                        UDPPortsToScan = null,
                        DNSServerList = (row["DNSServers"].ToString() ?? string.Empty).Split(',').Select(s => s.Trim()).ToList(),
                        TimeOut = _TimeOut,
                        NMGatewayIP = row["NMGatewayIP"].ToString(),
                        NMGatewayPort = row["NMGatewayPort"].ToString()
                    });
                }
            }

            await DoWork(false);
        }

        private async void chk_ARP_DeleteCacheBefore_Click(object? sender, RoutedEventArgs e)
        {
            if (chk_ARP_DeleteCacheBefore.IsChecked != true) return;
            if (supportMethods.IsAdministrator()) return;

            chk_ARP_DeleteCacheBefore.IsChecked = false;
            await new AvaloniaDialogService().ShowInfoAsync("you need admin right");
        }

        // ---- Ergebnis-DataGrid / Kontextmenue ----

        /// <summary>Die im Ergebnisraster markierten Zeilen.</summary>
        private List<DataRow> SelectedResultRows()
            => dgv_Results.SelectedItems.OfType<DataRowProxy>().Select(p => p.Row).Distinct().ToList();

        /// <summary>Eindeutige IPs der markierten Zeilen.</summary>
        private List<string> SelectedResultIPs()
            => SelectedResultRows()
               .Select(r => r["IP"].ToString() ?? string.Empty)
               .Where(ip => !string.IsNullOrWhiteSpace(ip))
               .Distinct()
               .ToList();

        private async void ScanSelectedIPs_Click(object? sender, RoutedEventArgs e)
        {
            _IPsToScan.Clear();

            foreach (string ip in SelectedResultIPs())
            {
                DataRow? groupedRow = GetIPDescription(ip);

                string hostname = _scannResults.ResultTable.AsEnumerable()
                    .Where(row => row.Field<string>("IP") == ip)
                    .Select(row => row.Field<string>("Hostname"))
                    .FirstOrDefault() ?? string.Empty;

                _IPsToScan.Add(new IPToScan
                {
                    IPGroupDescription = groupedRow?["IPGroupDescription"].ToString() ?? string.Empty,
                    DeviceDescription = groupedRow?["DeviceDescription"].ToString() ?? string.Empty,
                    IPorHostname = ip,
                    HostName = hostname
                });
            }

            await DoWork(true);
        }

        /// <summary>
        /// Sucht den Port genau eines Dienstes ueber alle 65536 Ports - deshalb
        /// die Beschraenkung auf einen Dienst und eine IP.
        /// </summary>
        private async void SelectedIPFindServicePort_Click(object? sender, RoutedEventArgs e)
        {
            var dialogService = new AvaloniaDialogService();

            List<string> selectedIps = SelectedResultIPs();
            if (selectedIps.Count == 0)
            {
                await dialogService.ShowInfoAsync("select an IP in the result table at first.", "Hint");
                return;
            }

            _IPsToScan.Clear();
            _IPsToScan.Add(new IPToScan { IPorHostname = selectedIps[0] });

            List<ServiceType> services = new();
            foreach (DataRow row in scanningMethod_Services!.Services.Rows)
            {
                if (row["toScan"] is bool toScan && toScan)
                {
                    services.Add((ServiceType)Enum.Parse(typeof(ServiceType), row["Service"].ToString()!));
                }
            }

            if (services.Count == 0)
            {
                await dialogService.ShowErrorAsync(
                    "please choos max. one service, because of the duration of thise kind of scan.", "Hint");
                return;
            }

            if (services.Count > 1)
            {
                await dialogService.ShowInfoAsync("select only one service for this scan.", "to many services selected");
                return;
            }

            status_Services_Scan = ScanStatus.running;
            await scanningMethod_Services.FindServicePortAsync(_IPsToScan[0], services[0]);
        }

        private async void resolve_ip_across_dns_servers_Click(object? sender, RoutedEventArgs e)
        {
            List<string> selectedIps = SelectedResultIPs();
            if (selectedIps.Count == 0)
            {
                await new AvaloniaDialogService().ShowInfoAsync("select an IP in the result table at first.", "Hint");
                return;
            }

            _IPsToScan.Clear();
            _IPsToScan.Add(new IPToScan { IPorHostname = selectedIps[0] });

            status_DNS_HostName_Scan = ScanStatus.running;
            counted_total_DNS_HostNames = _IPsToScan.Count;
            Status();

            await Task.Run(() => scanningMethode_ReverseLookupToHostAndAliases!.GetHost_Aliases(_IPsToScan, true), _cts.Token);
        }

        // ---- Filterleiste ----

        /// <summary>
        /// Entprellung der Filter-Eingaben. WPF wartete pauschal 600 ms in jedem
        /// Aufruf; hier verwirft ein Zaehler die zwischenzeitlich veralteten
        /// Durchlaeufe, damit nur die letzte Eingabe den Filter setzt.
        /// </summary>
        private int _filterGeneration;

        private async void Filter_ScanResults_Explicite(object? sender, RoutedEventArgs e)
        {
            int generation = ++_filterGeneration;

            await Task.Delay(600);
            if (generation != _filterGeneration) return;

            ApplyScanResultFilter();
        }

        private void ApplyScanResultFilter()
        {
            if (dv_resultTable == null) return;

            string allFilter = (tb_Filter_All1.Text ?? string.Empty).Trim();
            string allFilter2 = (tb_Filter_All2.Text ?? string.Empty).Trim();
            string ipFilter = (tb_Filter_IP.Text ?? string.Empty).Trim();
            string internalName = (tb_Filter_InternalName.Text ?? string.Empty).Trim();
            string hostName = (tb_Filter_HostName.Text ?? string.Empty).Trim();
            string tcpPort = (tb_Filter_TCPPort.Text ?? string.Empty).Trim();
            string mac = (tb_Filter_Mac.Text ?? string.Empty).Trim();
            string vendor = (tb_Filter_Vendor.Text ?? string.Empty).Trim();

            var whereFilter = new StringBuilder("1 = 1");

            var columnConditions = new List<string>();
            foreach (string columnName in new[] { "IP", "Hostname", "Vendor", "Mac", "TCP_Ports", "InternalName" })
            {
                if (!string.IsNullOrEmpty(allFilter)) columnConditions.Add($"{columnName} LIKE '%{allFilter}%'");
                if (!string.IsNullOrEmpty(allFilter2)) columnConditions.Add($"{columnName} LIKE '%{allFilter2}%'");
            }

            if (columnConditions.Count > 0)
                whereFilter.Append($" AND ({string.Join(" OR ", columnConditions)})");

            // "*" ist die im UI dokumentierte Wildcard, DataView erwartet "%"
            if (!string.IsNullOrEmpty(ipFilter))
                whereFilter.AppendFormat(" AND IP LIKE '{0}'", ipFilter.Replace("*", "%"));

            if (!string.IsNullOrEmpty(internalName)) whereFilter.AppendFormat(" AND InternalName LIKE '%{0}%'", internalName);
            if (!string.IsNullOrEmpty(hostName)) whereFilter.AppendFormat(" AND Hostname LIKE '%{0}%'", hostName);
            if (!string.IsNullOrEmpty(tcpPort)) whereFilter.AppendFormat(" AND TCP_Ports LIKE '%{0}%'", tcpPort);
            if (!string.IsNullOrEmpty(mac)) whereFilter.AppendFormat(" AND Mac LIKE '%{0}%'", mac);
            if (!string.IsNullOrEmpty(vendor)) whereFilter.AppendFormat(" AND Vendor LIKE '%{0}%'", vendor);

            if (chk_Filter_IsIPCam.IsChecked == true) whereFilter.Append(" AND IsIPCam IS NOT NULL");
            if (chk_Filter_IsSSDP.IsChecked == true) whereFilter.Append(" AND SSDPStatus IS NOT NULL");
            if (chk_Filter_SupportSMB.IsChecked == true) whereFilter.Append(" AND detectedSMBVersions IS NOT NULL");
            if (chk_Filter_SupportSNMP.IsChecked == true) whereFilter.Append(" AND SNMPSysName IS NOT NULL");
            if (chk_Filter_SupportNetBios.IsChecked == true) whereFilter.Append(" AND NetBiosHostname IS NOT NULL");

            string finalFilter = whereFilter.ToString();

            if (dv_resultTable.RowFilter != finalFilter)
            {
                try { dv_resultTable.RowFilter = finalFilter; }
                catch (Exception ex) { Debug.WriteLine(ex.Message); }
            }

            UpdateRowCount();
        }

        // ---- Export ----

        private async void bt_exportResult_Click(object? sender, RoutedEventArgs e)
        {
            var dialogService = new AvaloniaDialogService();

            YesNoCancel scope = await dialogService.AskYesNoCancelAsync(
                "Export whole table?\r\n\r\nTo export only selected rows select \"No\"", "Export");

            if (scope == YesNoCancel.Cancel) return;
            bool exportAllRows = scope == YesNoCancel.Yes;

            List<DataRow> rows = CollectRowsForExport(exportAllRows);

            if (rows.Count == 0)
            {
                await dialogService.ShowInfoAsync("for export select the rows at first.", "Export");
                return;
            }

            bool splitServices = await dialogService.ConfirmAsync(
                "Would you split detectedServicePorts in seperate rows?", "Split Services");

            DataTable exportTable = splitServices
                ? ScanResultExport.BuildServiceSplitTable(_scannResults.ResultTable, rows)
                : ScanResultExport.BuildFlatTable(rows, escapeForCsv: true);

            await SaveCsvAsync(exportTable, dialogService);
        }

        /// <summary>
        /// "Ganze Tabelle" meint die gefilterte Ansicht (wie in WPF), "Auswahl"
        /// die im Grid markierten Zeilen.
        /// </summary>
        private List<DataRow> CollectRowsForExport(bool allRows)
        {
            if (allRows)
            {
                return dv_resultTable?.Cast<DataRowView>().Select(v => v.Row).ToList() ?? new List<DataRow>();
            }

            return dgv_Results.SelectedItems
                              .OfType<DataRowProxy>()
                              .Select(p => p.Row)
                              .Distinct()
                              .ToList();
        }

        private async Task SaveCsvAsync(DataTable table, IDialogService dialogService)
        {
            IStorageFile? file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
            {
                Title = "Export",
                SuggestedFileName = "Export.csv",
                DefaultExtension = "csv",
                ShowOverwritePrompt = true,
                FileTypeChoices = new[]
                {
                    new FilePickerFileType("CSV") { Patterns = new[] { "*.csv" } }
                }
            });

            if (file == null) return;

            try
            {
                await using (Stream stream = await file.OpenWriteAsync())
                {
                    ScanResultExport.WriteCsv(table, stream);
                }

                await dialogService.ShowInfoAsync($"CSV-Datei erfolgreich gespeichert:\n{file.Path.LocalPath}",
                                                  "Export abgeschlossen");
            }
            catch (Exception ex)
            {
                await dialogService.ShowErrorAsync($"Fehler beim CSV-Export: {ex.Message}");
            }
        }

        private void bt_clearScanResultTable_Click(object? sender, RoutedEventArgs e)
        {
            _scannResults.ResultTable.Rows.Clear();
            UpdateRowCount();
        }

        /// <summary>
        /// Entspricht Window_Closing im WPF: Service-Einstellungen und - falls
        /// gewuenscht - die Ergebnistabelle sichern. Ohne das waere z.B. eine
        /// ueber "clear table" geleerte Tabelle nach dem Neustart wieder da.
        /// </summary>
        protected override void OnClosing(WindowClosingEventArgs e)
        {
            try
            {
                scanningMethod_Services?.SaveServiceSettingsToXML();

                if (chk_SaveLastScanResult.IsChecked == true)
                {
                    foreach (DataRow row in _scannResults.ResultTable.Rows)
                    {
                        if (!string.IsNullOrEmpty(row["ARPStatus"].ToString())) row["ARPStatus"] = gray_dot_s;
                        if (!string.IsNullOrEmpty(row["PingStatus"].ToString())) row["PingStatus"] = gray_dot_s;
                    }

                    _scannResults.ResultTable.WriteXml(_lastScanResultXML, XmlWriteMode.WriteSchema);
                }
            }
            catch (Exception)
            {
                // Ein Fehler beim Speichern darf das Schliessen nicht verhindern
            }

            base.OnClosing(e);
        }
        private async void chk_ScanResults_groupDevices_Click(object? sender, RoutedEventArgs e)
            => await reGroupScanResult();

        /// <summary>
        /// Uebertraegt die Gruppen-/Geraetebeschreibung aus den IP-Gruppen in die
        /// Ergebniszeilen und setzt die Gruppierung neu (WPF: reGroupScanResult).
        /// </summary>
        public async Task reGroupScanResult()
        {
            await Task.Run(() =>
            {
                foreach (DataRow row in _scannResults.ResultTable.Rows)
                {
                    DataRow? descriptionRow = GetIPDescription(row["IP"].ToString()!);
                    if (descriptionRow == null) continue;

                    string ipGroupDescription = descriptionRow["IPGroupDescription"].ToString() ?? string.Empty;
                    string deviceDescription = descriptionRow["DeviceDescription"].ToString() ?? string.Empty;

                    if (!string.IsNullOrEmpty(ipGroupDescription)) row["IPGroupDescription"] = ipGroupDescription;
                    if (!string.IsNullOrEmpty(deviceDescription)) row["DeviceDescription"] = deviceDescription;
                }
            });

            ApplyScanResultGrouping();
        }

        private void ApplyScanResultGrouping()
        {
            DataTableGridSource.SetGrouping(cv_resultTable, chk_ScanResults_groupDevices.IsChecked == true
                ? new[] { "IPGroupDescription", "DeviceDescription" }
                : new[] { "DeviceDescription" });
        }

        /// <summary>
        /// WPF schaltete hier zwischen Zellen- und Zeilenauswahl um. Avalonias
        /// DataGrid kennt keine Zellenauswahl - die Checkbox steuert deshalb, ob
        /// Entf die ganze Zeile oder nur den Zelleninhalt loescht
        /// (siehe <see cref="dgv_Results_KeyDown"/>) und ob mehrere Zeilen
        /// gleichzeitig markiert werden koennen.
        /// </summary>
        private void chk_allowDeleteRow_Click(object? sender, RoutedEventArgs e)
        {
            dgv_Results.SelectionMode = chk_allowDeleteRow.IsChecked == true
                ? DataGridSelectionMode.Extended
                : DataGridSelectionMode.Single;
        }

        private void dgv_Results_KeyDown(object? sender, KeyEventArgs e)
        {
            if (e.Key != Key.Delete) return;

            if (chk_allowDeleteRow.IsChecked == true)
            {
                foreach (DataRow row in dgv_Results.SelectedItems.OfType<DataRowProxy>().Select(p => p.Row).ToList())
                {
                    if (row.RowState != DataRowState.Detached) _scannResults.ResultTable.Rows.Remove(row);
                }
            }
            else if (dgv_Results.CurrentColumn?.Header is string columnName
                     && dgv_Results.SelectedItem is DataRowProxy proxy)
            {
                proxy[columnName] = string.Empty;
            }

            e.Handled = true;
        }

        /// <summary>
        /// Faerbt Zeilen mit doppelten Werten ein (WPF: dgv_Results_LoadingRow).
        /// Avalonia recycelt Zeilen, deshalb wird jeder Fall explizit gesetzt.
        /// </summary>
        private void dgv_Results_LoadingRow(object? sender, DataGridRowEventArgs e)
        {
            e.Row.Background = RowBrushes.None;
            e.Row.Foreground = RowBrushes.DefaultForeground;

            if (e.Row.DataContext is not DataRowProxy proxy) return;

            try
            {
                if (HasDuplicate("InternalName", proxy)) e.Row.Background = RowBrushes.DuplicateInternalName;
                if (HasDuplicate("IP", proxy)) e.Row.Background = RowBrushes.DuplicateIP;
                if (HasDuplicate("Hostname", proxy)) e.Row.Background = RowBrushes.DuplicateHostname;

                if (HasDuplicate("Mac", proxy))
                {
                    e.Row.Background = RowBrushes.DuplicateMac;
                    e.Row.Foreground = RowBrushes.DuplicateMacForeground;
                }
            }
            catch (Exception)
            {
                // Werte mit Sonderzeichen koennen den Select-Ausdruck sprengen
            }
        }

        private bool HasDuplicate(string columnName, DataRowProxy proxy)
        {
            string value = proxy[columnName]?.ToString() ?? string.Empty;
            if (string.IsNullOrEmpty(value)) return false;

            return _scannResults.ResultTable.Select($"{columnName} = '{value.Replace("'", "''")}'").Length > 1;
        }

        // ---- Unterer Bereich ----

        private void bt_VisualizeTable_Click(object? sender, RoutedEventArgs e)
        {
            new VisualizeTopologieView(_scannResults.ResultTable,
                                       chk_3dForceGraph_OnlineVersion.IsChecked == true).Show();
        }

        private void chk_dg_Result_ShowEmptyColumns_Click(object? sender, RoutedEventArgs e)
        {
            HideEmptyColumnsFromDataTable();
            _userSettings.SetBool("ShowEmptyColumns", chk_dg_Result_ShowEmptyColumns.IsChecked == true);
        }

        /// <summary>
        /// Blendet Spalten aus, in denen kein Wert steht. Die im WPF ohnehin
        /// unsichtbaren Spalten (<see cref="HiddenResultColumns"/>) bleiben
        /// ausgeblendet - sie liefern nur Sortier- und Gruppierschluessel.
        /// </summary>
        private void HideEmptyColumnsFromDataTable()
        {
            bool showAll = chk_dg_Result_ShowEmptyColumns.IsChecked == true;
            DataTable table = _scannResults.ResultTable;

            foreach (DataGridColumn gridColumn in dgv_Results.Columns)
            {
                if (gridColumn.Header is not string columnName) continue;
                if (HiddenResultColumns.Contains(columnName)) continue;

                if (showAll)
                {
                    gridColumn.IsVisible = true;
                    continue;
                }

                DataColumn? column = table.Columns.Contains(columnName) ? table.Columns[columnName] : null;
                if (column == null) continue;

                bool allEmpty = table.AsEnumerable()
                    .All(row => row.IsNull(column) || string.IsNullOrWhiteSpace(row[column].ToString()));

                gridColumn.IsVisible = !allEmpty;
            }
        }
    }
}
