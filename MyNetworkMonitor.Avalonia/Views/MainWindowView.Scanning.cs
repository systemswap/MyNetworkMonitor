using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Avalonia.Interactivity;
using Avalonia.Platform;
using Avalonia.Threading;
using MyNetworkMonitor.Avalonia.Platform;

namespace MyNetworkMonitor.Avalonia.Views
{
    /// <summary>
    /// Portierung der Scan-Logik aus MainWindow.xaml.cs (WPF).
    /// Aufbau und Reihenfolge sind 1:1 uebernommen; ersetzt sind nur die
    /// WPF-Bausteine: Dispatcher -> Dispatcher.UIThread, MessageBox -> IDialogService,
    /// Properties.Resources -> avares-Ressourcen.
    /// </summary>
    public partial class MainWindowView
    {
        private CancellationTokenSource _cts = new();

        private readonly List<IPToScan> _IPsToScan = new();
        private readonly SupportMethods supportMethods = new();

        private ScanningMethod_ARP? scanningMethode_ARP;
        private ScanningMethods_Ping? scanningMethods_Ping;
        private ScanningMethod_ONVIF_IPCam? scanningMethod_Find_ONVIF_IP_Cameras;
        private ScanningMethod_SSDP_UPNP? scanningMethode_SSDP_UPNP;
        private ScanningMethod_mDNS? scanningMethod_MDNS;
        private ScanningMethod_NetBios? scanningMethode_NetBios;
        private ScanningMethod_SMBVersionCheck? scanningMethod_SMB_VersionCheck;
        private ScanningMethod_SNMP? scanningMethode_SNMP;
        private ScanningMethod_ReverseLookupToHostAndAlieases? scanningMethode_ReverseLookupToHostAndAliases;
        private ScanningMethod_LookUp? scanningMethod_LookUp;
        private ScanningMethod_PortsTCP? scanningMethode_PortsTCP;
        private ScanningMethod_PortsUDP? scanningMethode_PortsUDP;

        // Status-Punkte der Ergebnistabelle
        private static readonly byte[] green_dot_s = LoadResource("green_dot_s.png");
        private static readonly byte[] red_dot_s = LoadResource("red_dot_s.png");
        private static readonly byte[] gray_dot_s = LoadResource("gray_dot_s.png");

        private static byte[] LoadResource(string fileName)
        {
            try
            {
                using Stream stream = AssetLoader.Open(
                    new Uri($"avares://MyNetworkMonitor.Avalonia/Resources/{fileName}"));
                using var memory = new MemoryStream();
                stream.CopyTo(memory);
                return memory.ToArray();
            }
            catch (Exception)
            {
                return Array.Empty<byte>();
            }
        }

        #region ScanStatus

        private ScanStatus status_ARP_A_Scan = ScanStatus.ignored;

        private ScanStatus status_Ping_Scan = ScanStatus.ignored;
        private int counted_current_Ping_Scan, counted_responded_Ping_Scan, counted_total_Ping_Scan;

        private ScanStatus status_SSDP_Scan = ScanStatus.ignored;
        private int counted_responded_SSDP_device, counted_total_SSDPs;

        private ScanStatus status_ONVIF_IP_Cam_Scan = ScanStatus.ignored;
        private int counted_current__ONVIF_IP_Cam, counted_responded_ONVIF_IP_Cams, counted_total_ONVIF_IPs_toScan;

        private ScanStatus status_DNS_HostName_Scan = ScanStatus.ignored;
        private int counted_current_DNS_HostNames, counted_responded_DNS_HostNames, counted_total_DNS_HostNames;

        private ScanStatus status_NetBios_Scan = ScanStatus.ignored;
        private int counted_current_NetBiosScan, counted_responded_NetBiosInfos, counted_total_NetBiosInfos;

        private ScanStatus status_SMB_VersionCheck = ScanStatus.ignored;
        private int counted_current_SMB_VersionCheck, counted_responded_SMB_VersionCheck, counted_total_SMB_VersionCheck;

        private ScanStatus status_Services_Scan = ScanStatus.ignored;
        private int counted_current_Service_IP_Scan, counted_responded_Services_IP_Scan, counted_total_Services_IP_Scan;

        private ScanStatus status_SNMP_Scan = ScanStatus.ignored;
        private int counted_current_SNMP_Scan, counted_responded_SNMP_Devices, counted_total_SNMP_Devices;

        private ScanStatus status_Lookup_Scan = ScanStatus.ignored;
        private int counted_current_Lookup_Scan, counted_responded_Lookup_Devices, counted_total_Lookup_Scans;

        private ScanStatus status_mDNS_Scan = ScanStatus.ignored;
        private int countdown_mDNS, counted_responded_mDNS_Devices;

        private ScanStatus status_ARP_Request_Scan = ScanStatus.ignored;
        private int counted_current_ARP_Requests, counted_responded_ARP_Requests, counted_total_ARP_Requests;

        private ScanStatus status_TCP_Port_Scan = ScanStatus.ignored;
        private int counted_current_TCP_Port_Scan, counted_responded_TCP_Port_Scan_Devices, counted_total_TCP_Port_Scans;

        private ScanStatus status_UDP_Port_Scan = ScanStatus.ignored;
        private int counted_current_UDP_Port_Scan, counted_responded_UDP_Port_Devices, counted_total_UDP_Port_Devices;

        public void Status()
        {
            var lst = new List<string> { " * current / responded / total * " };

            if (status_ARP_Request_Scan != ScanStatus.ignored) lst.Add($"ARP Request: {status_ARP_Request_Scan} {counted_current_ARP_Requests} / {counted_responded_ARP_Requests} / {counted_total_ARP_Requests}");
            if (status_Ping_Scan != ScanStatus.ignored) lst.Add($"Ping: {status_Ping_Scan} {counted_current_Ping_Scan} / {counted_responded_Ping_Scan} / {counted_total_Ping_Scan}");
            if (status_SSDP_Scan != ScanStatus.ignored) lst.Add($"SSDP: {status_SSDP_Scan} ... / {counted_responded_SSDP_device} / ...");
            if (status_ONVIF_IP_Cam_Scan != ScanStatus.ignored) lst.Add($"IP-Cam`s: {status_ONVIF_IP_Cam_Scan} {counted_current__ONVIF_IP_Cam} / {counted_responded_ONVIF_IP_Cams} / {counted_total_ONVIF_IPs_toScan}");
            if (status_DNS_HostName_Scan != ScanStatus.ignored) lst.Add($"DNS Hostnames: {status_DNS_HostName_Scan} {counted_current_DNS_HostNames} / {counted_responded_DNS_HostNames} / {counted_total_DNS_HostNames}");
            if (status_mDNS_Scan != ScanStatus.ignored) lst.Add($"mDNS: {status_mDNS_Scan} {countdown_mDNS} / {counted_responded_mDNS_Devices} / ...");
            if (status_Lookup_Scan != ScanStatus.ignored) lst.Add($"Lookup: {status_Lookup_Scan} {counted_current_Lookup_Scan} / {counted_responded_Lookup_Devices} / {counted_total_Lookup_Scans}");
            if (status_SMB_VersionCheck != ScanStatus.ignored) lst.Add($"SMB Check: {status_SMB_VersionCheck} {counted_current_SMB_VersionCheck} / {counted_responded_SMB_VersionCheck} / {counted_total_SMB_VersionCheck}");
            if (status_NetBios_Scan != ScanStatus.ignored) lst.Add($"NetBios: {status_NetBios_Scan} {counted_current_NetBiosScan} / {counted_responded_NetBiosInfos} / {counted_total_NetBiosInfos}");
            if (status_SNMP_Scan != ScanStatus.ignored) lst.Add($"SNMP: {status_SNMP_Scan} {counted_current_SNMP_Scan} / {counted_responded_SNMP_Devices} / {counted_total_SNMP_Devices}");
            if (status_Services_Scan != ScanStatus.ignored) lst.Add($"Services: {status_Services_Scan} {counted_current_Service_IP_Scan} / {counted_responded_Services_IP_Scan} / {counted_total_Services_IP_Scan}");
            if (status_TCP_Port_Scan != ScanStatus.ignored) lst.Add($"TCP Ports: {status_TCP_Port_Scan} {counted_current_TCP_Port_Scan} / {counted_responded_TCP_Port_Scan_Devices} / {counted_total_TCP_Port_Scans}");
            if (status_UDP_Port_Scan != ScanStatus.ignored) lst.Add($"UDP Ports: {status_UDP_Port_Scan} {counted_current_UDP_Port_Scan} / {counted_responded_UDP_Port_Devices} / {counted_total_UDP_Port_Devices}");
            if (status_ARP_A_Scan != ScanStatus.ignored) lst.Add($"APR A: {status_ARP_A_Scan} ... / ... / ...");

            lbl_ScanStatus.Content = string.Join("    ", lst).Replace(ScanStatus.finished.ToString(), string.Empty);
        }

        #endregion

        // ------------------------------------------------------------------
        // Scanner-Instanzen und Events (WPF: im Konstruktor)
        // ------------------------------------------------------------------

        private void InitializeScanners()
        {
            scanningMethode_SSDP_UPNP = new ScanningMethod_SSDP_UPNP();
            scanningMethode_SSDP_UPNP.ProgressUpdated += ScanningMethode_SSDP_UPNP_ProgressUpdated;
            scanningMethode_SSDP_UPNP.SSDP_foundNewDevice += SSDP_foundNewDevice;
            scanningMethode_SSDP_UPNP.SSDP_Scan_Finished += SSDP_Scan_Finished;

            scanningMethod_MDNS = new ScanningMethod_mDNS();
            scanningMethod_MDNS.ProgressUpdated += ScanningMethod_MDNS_ProgressUpdated;
            scanningMethod_MDNS.found_mDNS_Device += ScanningMethod_MDNS_found_mDNS_Device;
            scanningMethod_MDNS.mDNS_ScanStatus += ScanningMethod_mDNS_ScanStatus;

            scanningMethode_SNMP = new ScanningMethod_SNMP();
            scanningMethode_SNMP.ProgressUpdated += ScanningMethode_SNMP_ProgressUpdated;
            scanningMethode_SNMP.SNMB_Task_Finished += ScanningMethode_SNMP_SNMB_Task_Finished;
            scanningMethode_SNMP.SNMBFinished += ScanningMethode_SNMP_SNMBFinished;

            scanningMethode_NetBios = new ScanningMethod_NetBios();
            scanningMethode_NetBios.ProgressUpdated += ScanningMethode_NetBios_ProgressUpdated;
            scanningMethode_NetBios.NetbiosIPScanFinished += ScanningMethod_NetBios_NetbiosIPScanFinished;
            scanningMethode_NetBios.NetbiosScanFinished += ScanningMethod_NetBios_NetbiosScanFinished;

            scanningMethod_SMB_VersionCheck = new ScanningMethod_SMBVersionCheck();
            scanningMethod_SMB_VersionCheck.ProgressUpdated += ScanningMethod_SMB_VersionCheck_ProgressUpdated;
            scanningMethod_SMB_VersionCheck.SMBIPScanFinished += ScanningMethod_SMB_VersionCheck_SMB_IP_Scan_Finished;
            scanningMethod_SMB_VersionCheck.SMBScanFinished += ScanningMethod_SMBVersionCheck_SMB_Scan_Finished;

            // scanningMethod_Services wird beim Laden der Einstellungen erzeugt (Tab "Services")
            scanningMethod_Services!.ScanStatusUpdated += ScanningMethod_Services_ScanStatusUpdated;
            scanningMethod_Services.FindServicePortProgressUpdated += ScanningMethod_Services_FindServicePortProgressUpdated;
            scanningMethod_Services.FindServicePortFinished += ScanningMethod_Services_FindServicePortFinished;
            scanningMethod_Services.ServiceIPScanFinished += ScanningMethod_Services_ServiceIPScanFinished;
            scanningMethod_Services.ProgressUpdated += ScanningMethod_Services_ProgressUpdated;
            scanningMethod_Services.ServiceScanFinished += ScanningMethod_Services_ServiceScanFinished;

            scanningMethode_ARP = new ScanningMethod_ARP();
            scanningMethode_ARP.ProgressUpdated += ScanningMethode_ARP_ProgressUpdated;
            scanningMethode_ARP.ARP_A_newDevice += ARP_A_newDevive_Finished;
            scanningMethode_ARP.ARP_Request_Task_Finished += ARP_Request_Task_Finished;
            scanningMethode_ARP.ARP_Request_Finished += ARP_Request_Finished;

            scanningMethods_Ping = new ScanningMethods_Ping();
            scanningMethods_Ping.ProgressUpdated += ScanningMethods_Ping_ProgressUpdated;
            scanningMethods_Ping.Ping_Task_Finished += Ping_Task_Finished;
            scanningMethods_Ping.PingFinished += PingFinished_Event;

            scanningMethod_Find_ONVIF_IP_Cameras = new ScanningMethod_ONVIF_IPCam();
            scanningMethod_Find_ONVIF_IP_Cameras.ProgressUpdated += ScanningMethod_Find_ONVIF_IP_Cameras_ProgressUpdated;
            scanningMethod_Find_ONVIF_IP_Cameras.new_ONVIF_IP_Camera_Found_Task_Finished += newIPCameraFound_Task_Finished;
            scanningMethod_Find_ONVIF_IP_Cameras.ONVIF_IP_Camera_Scan_Finished += IPCameraScan_Finished;

            scanningMethode_ReverseLookupToHostAndAliases = new ScanningMethod_ReverseLookupToHostAndAlieases();
            scanningMethode_ReverseLookupToHostAndAliases.ProgressUpdated += ScanningMethode_ReverseLookupToHostAndAliases_ProgressUpdated;
            scanningMethode_ReverseLookupToHostAndAliases.GetHostAliases_Task_Finished += DNS_GetHostAliases_Task_Finished;
            scanningMethode_ReverseLookupToHostAndAliases.GetHostAliases_Finished += DNS_GetHostAndAliasFromIP_Finished;

            scanningMethod_LookUp = new ScanningMethod_LookUp();
            scanningMethod_LookUp.ProgressUpdated += ScanningMethod_LookUp_ProgressUpdated;
            scanningMethod_LookUp.Lookup_Task_Finished += Lookup_Task_Finished;
            scanningMethod_LookUp.Lookup_Finished += Lookup_Finished;

            scanningMethode_PortsTCP = new ScanningMethod_PortsTCP();
            scanningMethode_PortsTCP.TcpPortScan_Task_Finished += TcpPortScan_Task_Finished;
            scanningMethode_PortsTCP.TcpPortScan_Finished += TcpPortScan_Finished;

            scanningMethode_PortsUDP = new ScanningMethod_PortsUDP();
            scanningMethode_PortsUDP.UDPPortScan_Task_Finished += UDPPortScan_Task_Finished;
            scanningMethode_PortsUDP.UDPPortScan_Finished += UDPPortScan_Finished;
        }

        // ------------------------------------------------------------------
        // Scan-Start
        // ------------------------------------------------------------------

        private async void bt_StartScanFromNIC_Click(object? sender, RoutedEventArgs e)
        {
            _IPsToScan.Clear();

            List<int> TCPPorts = CollectTcpPortsFromUi();

            var range = new IpRanges.IPRange(tb_Adapter_FirstSubnetIP.Text ?? string.Empty,
                                             tb_Adapter_LastSubnetIP.Text ?? string.Empty);

            foreach (var item in range.GetAllIP())
            {
                _IPsToScan.Add(new IPToScan
                {
                    IPGroupDescription = "NetworkInterface",
                    DeviceDescription = "NIC: " + cb_NetworkAdapters.SelectedItem,
                    IPorHostname = item.ToString(),
                    TCPPortsToScan = TCPPorts,
                    TimeOut = _TimeOut
                });
            }

            await DoWork(false);
        }

        private async void bt_Scan_IP_Ranges_Click(object? sender, RoutedEventArgs e)
        {
            _IPsToScan.Clear();

            List<int> TCPPorts = new();
            if (chk_Methodes_ScanTCPPorts.IsChecked == true && chk_allTCPPorts.IsChecked != true)
            {
                TCPPorts.AddRange(_portCollection.TCPPorts);
            }
            else
            {
                TCPPorts.AddRange(Enumerable.Range(1, 65536));
            }

            foreach (DataRow row in ipGroupData.IPGroupsDT.Rows)
            {
                if (row["IsActive"] == DBNull.Value || !(bool)row["IsActive"]) continue;

                if (string.IsNullOrEmpty(row["LastIP"].ToString()))
                {
                    string ipOrHostname = row["FirstIP"].ToString()!;

                    if (supportMethods.Is_Valid_IP(ipOrHostname))
                    {
                        _IPsToScan.Add(CreateIPToScan(row, ipOrHostname, TCPPorts));
                    }
                    else
                    {
                        IPHostEntry? entry = await Task.Run(() => scanningMethod_LookUp!.nsLookup(ipOrHostname));
                        if (entry == null) continue;

                        foreach (IPAddress address in entry.AddressList)
                        {
                            _IPsToScan.Add(CreateIPToScan(row, address.ToString(), TCPPorts));
                        }
                    }
                }
                else
                {
                    foreach (string ip in GetIPRange(row["FirstIP"].ToString()!, row["LastIP"].ToString()!))
                    {
                        IPToScan ipToScan = CreateIPToScan(row, ip, _portCollection.TCPPorts);
                        ipToScan.HostName = string.Empty;
                        ipToScan.UDPPortsToScan = _portCollection.UDPPorts;
                        _IPsToScan.Add(ipToScan);
                    }
                }
            }

            await DoWork(false);
        }

        private IPToScan CreateIPToScan(DataRow row, string ipOrHostname, List<int> tcpPorts) => new()
        {
            IPGroupDescription = row["IPGroupDescription"].ToString(),
            DeviceDescription = row["DeviceDescription"].ToString(),
            IPorHostname = ipOrHostname,
            Domain = row["Domain"].ToString(),
            TCPPortsToScan = tcpPorts,
            UDPPortsToScan = null,
            DNSServerList = row["DNSServers"].ToString()!.Split(',').ToList(),
            TimeOut = _TimeOut,
            NMGatewayIP = row["NMGatewayIP"].ToString(),
            NMGatewayPort = row["NMGatewayPort"].ToString()
        };

        private List<int> CollectTcpPortsFromUi()
        {
            var tcpPorts = new List<int>();

            if (chk_Methodes_ScanTCPPorts.IsChecked == true && chk_allTCPPorts.IsChecked != true)
            {
                tcpPorts.AddRange(_portCollection.TCPPorts);

                // zusaetzliche Ports aus dem Textfeld
                if (!string.IsNullOrEmpty(tb_TCPPorts.Text))
                {
                    foreach (string part in tb_TCPPorts.Text.Split(',', StringSplitOptions.RemoveEmptyEntries))
                    {
                        if (int.TryParse(part.Trim(), out int port)) tcpPorts.Add(port);
                    }
                }
            }

            if (chk_Methodes_ScanTCPPorts.IsChecked == true && chk_allTCPPorts.IsChecked == true)
            {
                tcpPorts.AddRange(Enumerable.Range(1, 65536));
            }

            return tcpPorts;
        }

        // ------------------------------------------------------------------
        // Scan-Kette
        // ------------------------------------------------------------------

        public async Task DoWork(bool IsSelectiveScan, bool ClearTable = false)
        {
            if (!ScannerCanStart())
            {
                await new AvaloniaDialogService().ShowInfoAsync(
                    "scanner is running, or waiting, you have to stop first");
                return;
            }

            _cts = new CancellationTokenSource();

            try
            {
                ResetCounters();
                lbl_ScanStatus.Content = "...";

                foreach (DataRow row in _scannResults.ResultTable.Rows)
                {
                    DataRow? groupedRow = GetIPDescription(row["IP"].ToString()!);

                    if (groupedRow != null)
                    {
                        if (string.IsNullOrEmpty(row["IPGroupDescription"].ToString()) && !string.IsNullOrEmpty(groupedRow["IPGroupDescription"].ToString())) row["IPGroupDescription"] = groupedRow["IPGroupDescription"].ToString();
                        if (string.IsNullOrEmpty(row["DeviceDescription"].ToString()) && !string.IsNullOrEmpty(groupedRow["DeviceDescription"].ToString())) row["DeviceDescription"] = groupedRow["DeviceDescription"].ToString();
                    }

                    if (_IPsToScan.Any(i => i.IPorHostname == row["IP"].ToString()))
                    {
                        byte[]? arpStatus = row["ARPStatus"] as byte[];
                        if ((chk_ARPRequest.IsChecked == true || chk_Methodes_ARP_A.IsChecked == true) && arpStatus != null)
                        {
                            row["ARPStatus"] = gray_dot_s;
                        }

                        if (chk_Methodes_Ping.IsChecked == true && !string.IsNullOrEmpty(row["PingStatus"].ToString())) row["PingStatus"] = gray_dot_s;
                        if (chk_Methodes_Ping.IsChecked == true) row["ResponseTime"] = string.Empty;

                        if (chk_Methodes_SSDP.IsChecked == true && !string.IsNullOrEmpty(row["SSDPStatus"].ToString())) row["SSDPStatus"] = gray_dot_s;

                        if (chk_Methodes_ONVIF.IsChecked == true && !string.IsNullOrEmpty(row["IsIPCam"].ToString())) row["IsIPCam"] = gray_dot_s;

                        if (chk_Methodes_ScanTCPPorts.IsChecked == true) row["TCP_Ports"] = DBNull.Value;

                        if (chk_Methodes_ScanHostnames.IsChecked == true)
                        {
                            row["Domain"] = string.Empty;
                            row["Hostname"] = string.Empty;
                            row["Aliases"] = string.Empty;
                        }

                        if (chk_Methodes_LookUp.IsChecked == true) row["LookUpIPs"] = string.Empty;
                    }
                }

                _cts.Token.ThrowIfCancellationRequested();

                /* set the states */
                if (chk_Methodes_SSDP.IsChecked == true) status_SSDP_Scan = ScanStatus.waiting;
                if (chk_Methodes_ONVIF.IsChecked == true) status_ONVIF_IP_Cam_Scan = ScanStatus.waiting;
                if (chk_ARPRequest.IsChecked == true) status_ARP_Request_Scan = ScanStatus.waiting;
                if (chk_Methodes_Ping.IsChecked == true) status_Ping_Scan = ScanStatus.waiting;
                if (chk_Methodes_ScanHostnames.IsChecked == true) status_DNS_HostName_Scan = ScanStatus.waiting;
                if (chk_Methodes_mDNS.IsChecked == true) status_mDNS_Scan = ScanStatus.waiting;
                if (chk_Methodes_ScanNetBios.IsChecked == true) status_NetBios_Scan = ScanStatus.waiting;
                if (chk_Methodes_Scan_SMBVersions.IsChecked == true) status_SMB_VersionCheck = ScanStatus.waiting;
                if (chk_Methodes_Scan_Services.IsChecked == true) status_Services_Scan = ScanStatus.waiting;
                if (chk_Methodes_SNMP.IsChecked == true) status_SNMP_Scan = ScanStatus.waiting;
                if (chk_Methodes_LookUp.IsChecked == true) status_Lookup_Scan = ScanStatus.waiting;
                if (chk_Methodes_ScanTCPPorts.IsChecked == true) status_TCP_Port_Scan = ScanStatus.waiting;
                if (chk_Methodes_ARP_A.IsChecked == true) status_ARP_A_Scan = ScanStatus.waiting;

                Status();

                _cts.Token.ThrowIfCancellationRequested();
                if (chk_ARP_DeleteCacheBefore.IsChecked == true)
                {
                    foreach (DataRow row in _scannResults.ResultTable.Rows) row["ARPStatus"] = DBNull.Value;

                    await Task.Run(() => scanningMethode_ARP!.DeleteARPCache(), _cts.Token);
                    await Task.Delay(2000);
                }

                _cts.Token.ThrowIfCancellationRequested();
                if (chk_ARPRequest.IsChecked == true)
                {
                    counted_total_ARP_Requests = _IPsToScan.Count;
                    status_ARP_Request_Scan = ScanStatus.running;
                    Status();
                    await Task.Run(() => scanningMethode_ARP!.SendARPRequestAsync(_IPsToScan), _cts.Token);
                }

                _cts.Token.ThrowIfCancellationRequested();
                if (chk_Methodes_Ping.IsChecked == true)
                {
                    status_Ping_Scan = ScanStatus.running;
                    counted_total_Ping_Scan = _IPsToScan.Count;
                    Status();
                    await Task.Run(() => scanningMethods_Ping!.PingIPsAsync(_IPsToScan, false), _cts.Token);
                }

                _cts.Token.ThrowIfCancellationRequested();
                if (chk_Methodes_SSDP.IsChecked == true)
                {
                    status_SSDP_Scan = ScanStatus.running;
                    counted_total_SSDPs = _IPsToScan.Count;
                    Status();
                    await Task.Run(() => scanningMethode_SSDP_UPNP!.Scan_for_SSDP_devices_async(), _cts.Token);
                }

                _cts.Token.ThrowIfCancellationRequested();
                if (chk_Methodes_mDNS.IsChecked == true)
                {
                    status_mDNS_Scan = ScanStatus.running;
                    Status();

                    string selectedInterface = cb_NetworkAdapters.SelectedItem?.ToString() ?? string.Empty;
                    await Task.Run(() => scanningMethod_MDNS!.DiscoverAsync(selectedInterface));
                }

                _cts.Token.ThrowIfCancellationRequested();
                if (chk_Methodes_ONVIF.IsChecked == true)
                {
                    status_ONVIF_IP_Cam_Scan = ScanStatus.running;
                    Status();
                    await Task.Run(() => scanningMethod_Find_ONVIF_IP_Cameras!.Discover(_IPsToScan), _cts.Token);
                }

                _cts.Token.ThrowIfCancellationRequested();
                var DNS_Hostname_IPsToScan = new List<IPToScan>();
                if (chk_Methodes_ScanHostnames.IsChecked == true)
                {
                    if (_scannResults.ResultTable.Rows.Count == 0 || rb_ScanHostnames_All_IPs.IsChecked == true || IsSelectiveScan)
                    {
                        DNS_Hostname_IPsToScan = _IPsToScan;
                    }
                    else
                    {
                        foreach (DataRow row in _scannResults.ResultTable.Rows)
                        {
                            DNS_Hostname_IPsToScan.Add(new IPToScan
                            {
                                IPGroupDescription = row["IPGroupDescription"].ToString(),
                                DeviceDescription = row["DeviceDescription"].ToString(),
                                IPorHostname = row["ip"].ToString(),
                                HostName = row["Hostname"].ToString(),
                                Domain = row["Domain"].ToString(),
                                TCPPortsToScan = _portCollection.TCPPorts,
                                UDPPortsToScan = _portCollection.UDPPorts,
                                DNSServerList = row["DNSServers"].ToString()!.Split(',').ToList(),
                                TimeOut = _TimeOut,
                                NMGatewayIP = row["NMGatewayIP"].ToString(),
                                NMGatewayPort = row["NMGatewayPort"].ToString()
                            });
                        }
                    }

                    status_DNS_HostName_Scan = ScanStatus.running;
                    counted_total_DNS_HostNames = DNS_Hostname_IPsToScan.Count;
                    Status();

                    await Task.Run(() => scanningMethode_ReverseLookupToHostAndAliases!.GetHost_Aliases(DNS_Hostname_IPsToScan, false), _cts.Token);
                }

                _cts.Token.ThrowIfCancellationRequested();
                if (chk_Methodes_LookUp.IsChecked == true)
                {
                    // etwas Zeit, damit die DNS-Ergebnisse in der Tabelle stehen
                    await Task.Delay(500);

                    var IPsForLookUp = new List<IPToScan>();

                    if (_scannResults.ResultTable.Rows.Count != 0 && IsSelectiveScan)
                    {
                        IPsForLookUp = _IPsToScan;
                    }
                    else
                    {
                        foreach (DataRow row in _scannResults.ResultTable.Select("Hostname <> ''"))
                        {
                            IPsForLookUp.Add(new IPToScan
                            {
                                IPGroupDescription = row["IPGroupDescription"].ToString(),
                                DeviceDescription = row["DeviceDescription"].ToString(),
                                IPorHostname = row["IP"].ToString(),
                                HostName = row["Hostname"].ToString(),
                                Domain = row["Domain"].ToString(),
                                DNSServerList = row["DNSServers"].ToString()!.Split(',').ToList(),
                                NMGatewayIP = row["NMGatewayIP"].ToString(),
                                NMGatewayPort = row["NMGatewayPort"].ToString()
                            });
                        }
                    }

                    status_Lookup_Scan = ScanStatus.running;
                    counted_total_Lookup_Scans = IPsForLookUp.Count;
                    Status();

                    await Task.Run(() => scanningMethod_LookUp!.LookupAsync(IPsForLookUp), _cts.Token);
                }

                _cts.Token.ThrowIfCancellationRequested();
                if (chk_Methodes_Scan_SMBVersions.IsChecked == true)
                {
                    List<IPToScan> SMB_IPsToScan = SelectTargets(IsSelectiveScan);

                    status_SMB_VersionCheck = ScanStatus.running;
                    await Task.Run(() => scanningMethod_SMB_VersionCheck!.ScanMultipleIPsAsync(SMB_IPsToScan), _cts.Token);
                }

                _cts.Token.ThrowIfCancellationRequested();
                if (chk_Methodes_ScanNetBios.IsChecked == true)
                {
                    List<IPToScan> NetBios_IPsToScan = SelectTargets(IsSelectiveScan);

                    status_NetBios_Scan = ScanStatus.running;
                    await Task.Run(() => scanningMethode_NetBios!.ScanMultipleIPsAsync(NetBios_IPsToScan), _cts.Token);
                }

                _cts.Token.ThrowIfCancellationRequested();
                if (chk_Methodes_SNMP.IsChecked == true)
                {
                    status_SNMP_Scan = ScanStatus.running;
                    Status();
                    await Task.Run(() => scanningMethode_SNMP!.ScanAsync(_IPsToScan), _cts.Token);
                }

                _cts.Token.ThrowIfCancellationRequested();
                if (chk_Methodes_Scan_Services.IsChecked == true)
                {
                    List<IPToScan> Services_IPsToScan = SelectTargets(IsSelectiveScan);

                    status_Services_Scan = ScanStatus.running;

                    var services = new List<ServiceType>();
                    var additionalServicePorts = new Dictionary<ServiceType, List<int>>();

                    foreach (DataRow row in scanningMethod_Services!.Services.Rows)
                    {
                        if (row["toScan"] == DBNull.Value || !(bool)row["toScan"]) continue;

                        var type = (ServiceType)Enum.Parse(typeof(ServiceType), row["Service"].ToString()!);
                        services.Add(type);

                        List<int> ports = row["Ports"].ToString()!
                            .Split(',', StringSplitOptions.RemoveEmptyEntries)
                            .Select(p => int.Parse(p.Trim()))
                            .ToList();

                        additionalServicePorts[type] = ports;
                    }

                    await Task.Run(() => scanningMethod_Services.ScanIPsAsync(Services_IPsToScan, services, additionalServicePorts), _cts.Token);
                }

                _cts.Token.ThrowIfCancellationRequested();
                if (chk_Methodes_ScanTCPPorts.IsChecked == true)
                {
                    var _IPsForTCPPortScan = new List<IPToScan>();

                    if (_scannResults.ResultTable.Rows.Count == 0 || rb_ScanHostnames_onlyIPsInTable.IsChecked != true || IsSelectiveScan)
                    {
                        _IPsForTCPPortScan = _IPsToScan;
                    }
                    else
                    {
                        foreach (DataRow row in _scannResults.ResultTable.Rows)
                        {
                            _IPsForTCPPortScan.Add(new IPToScan
                            {
                                IPGroupDescription = row["IPGroupDescription"].ToString(),
                                DeviceDescription = row["DeviceDescription"].ToString(),
                                IPorHostname = row["ip"].ToString(),
                                HostName = row["Hostname"].ToString(),
                                Domain = row["Domain"].ToString(),
                                TCPPortsToScan = _portCollection.TCPPorts,
                                UDPPortsToScan = _portCollection.UDPPorts,
                                DNSServerList = row["DNSServers"].ToString()!.Split(',').ToList(),
                                TimeOut = _TimeOut,
                                NMGatewayIP = row["NMGatewayIP"].ToString(),
                                NMGatewayPort = row["NMGatewayPort"].ToString()
                            });
                        }
                    }

                    status_TCP_Port_Scan = ScanStatus.running;
                    counted_total_TCP_Port_Scans = _IPsForTCPPortScan.Count;
                    Status();

                    List<int> ports = _portCollection.TableOfPortsToScan.AsEnumerable()
                        .Where(row => row.Field<bool>("TCPScan"))
                        .Select(row => row.Field<int>("Ports"))
                        .ToList();

                    await Task.Run(() => scanningMethode_PortsTCP!.ScanTCPPortsAsync(
                        _IPsForTCPPortScan, ports, new TimeSpan(0, 0, 0, 0, _TimeOut)), _cts.Token);
                }

                _cts.Token.ThrowIfCancellationRequested();
                if (chk_Methodes_ARP_A.IsChecked == true)
                {
                    status_ARP_A_Scan = ScanStatus.running;
                    Status();

                    _ = Task.Run(() => scanningMethode_ARP!.ARP_A(_IPsToScan), _cts.Token);
                }
            }
            catch (OperationCanceledException)
            {
                // Scan wurde ueber Stop abgebrochen - regulaerer Fall, kein Fehler.
            }
        }

        /// <summary>
        /// Zielauswahl fuer SMB / NetBios / Services: entweder die geplanten IPs
        /// oder - bei bereits gefuellter Tabelle - deren IPs (WPF-Verhalten).
        /// </summary>
        private List<IPToScan> SelectTargets(bool isSelectiveScan)
        {
            if (_scannResults.ResultTable.Rows.Count == 0 || rb_ScanHostnames_All_IPs.IsChecked == true || isSelectiveScan)
            {
                return _IPsToScan;
            }

            return _scannResults.ResultTable.Rows.Cast<DataRow>()
                .Select(row => new IPToScan { IPorHostname = row["ip"].ToString() })
                .ToList();
        }

        private void ResetCounters()
        {
            counted_current_Ping_Scan = counted_responded_Ping_Scan = counted_total_Ping_Scan = 0;
            counted_responded_SSDP_device = counted_total_SSDPs = 0;
            counted_current_SNMP_Scan = counted_responded_SNMP_Devices = counted_total_SNMP_Devices = 0;
            counted_current_DNS_HostNames = counted_responded_DNS_HostNames = counted_total_DNS_HostNames = 0;
            countdown_mDNS = counted_responded_mDNS_Devices = 0;
            counted_current_NetBiosScan = counted_responded_NetBiosInfos = counted_total_NetBiosInfos = 0;
            counted_current_Service_IP_Scan = counted_responded_Services_IP_Scan = counted_total_Services_IP_Scan = 0;
            counted_current_Lookup_Scan = counted_responded_Lookup_Devices = counted_total_Lookup_Scans = 0;
            counted_current_ARP_Requests = counted_responded_ARP_Requests = counted_total_ARP_Requests = 0;
            counted_current_TCP_Port_Scan = counted_responded_TCP_Port_Scan_Devices = counted_total_TCP_Port_Scans = 0;
            counted_current_UDP_Port_Scan = counted_total_UDP_Port_Devices = 0;
        }

        // ------------------------------------------------------------------
        // Stop
        // ------------------------------------------------------------------

        private void StopScanning_Click(object? sender, RoutedEventArgs e) => StopScanning();

        public void StopScanning()
        {
            if (_cts is { IsCancellationRequested: false }) _cts.Cancel();

            scanningMethode_SSDP_UPNP?.StopScan();
            scanningMethode_SNMP?.StopScan();
            scanningMethode_NetBios?.StopScan();
            scanningMethod_SMB_VersionCheck?.StopScan();
            scanningMethod_Services?.StopScan();
            scanningMethode_ARP?.StopScan();
            scanningMethods_Ping?.StopScan();
            scanningMethod_LookUp?.StopScan();
            scanningMethode_ReverseLookupToHostAndAliases?.StopScan();
            scanningMethod_Find_ONVIF_IP_Cameras?.StopScan();
            scanningMethode_PortsTCP?.StopScan();

            ResetAllScanStatuses();

            // _cts hier NICHT neu anlegen - der frische Token entsteht in DoWork.
        }

        private void ResetAllScanStatuses()
        {
            status_ARP_A_Scan = ScanStatus.stopped;
            status_ARP_Request_Scan = ScanStatus.stopped;
            status_Ping_Scan = ScanStatus.stopped;
            status_SSDP_Scan = ScanStatus.stopped;
            status_ONVIF_IP_Cam_Scan = ScanStatus.stopped;
            status_DNS_HostName_Scan = ScanStatus.stopped;
            status_NetBios_Scan = ScanStatus.stopped;
            status_SMB_VersionCheck = ScanStatus.stopped;
            status_Services_Scan = ScanStatus.stopped;
            status_SNMP_Scan = ScanStatus.stopped;
            status_Lookup_Scan = ScanStatus.stopped;
            status_mDNS_Scan = ScanStatus.stopped;
            status_TCP_Port_Scan = ScanStatus.stopped;
            status_UDP_Port_Scan = ScanStatus.stopped;

            Status();
        }

        public bool ScannerCanStart()
        {
            var statuses = new List<ScanStatus>
            {
                status_ARP_A_Scan, status_ARP_Request_Scan, status_DNS_HostName_Scan, status_Lookup_Scan,
                status_NetBios_Scan, status_ONVIF_IP_Cam_Scan, status_Ping_Scan, status_Services_Scan,
                status_SMB_VersionCheck, status_SNMP_Scan, status_SSDP_Scan, status_TCP_Port_Scan
            };

            return !statuses.Any(status => status is ScanStatus.running or ScanStatus.waiting);
        }

        // ------------------------------------------------------------------
        // IP-Hilfsfunktionen
        // ------------------------------------------------------------------

        public DataRow? GetIPDescription(string IP)
        {
            if (string.IsNullOrEmpty(IP)) return null;

            foreach (DataRow row in ipGroupData.IPGroupsDT.Rows)
            {
                if (IsIPInRange(IP, row["FirstIP"].ToString()!, row["LastIP"].ToString()!)) return row;
            }

            return null;

            static bool IsIPInRange(string ip, string startIP, string endIP)
            {
                if (!TryIPToUInt(ip, out uint ipVal)) return false;
                if (!TryIPToUInt(startIP, out uint startVal)) return false;
                if (!TryIPToUInt(endIP, out uint endVal)) return false;

                return ipVal >= Math.Min(startVal, endVal) && ipVal <= Math.Max(startVal, endVal);
            }
        }

        private static bool TryIPToUInt(string ip, out uint value)
        {
            value = 0;
            if (string.IsNullOrWhiteSpace(ip)) return false;

            if (!IPAddress.TryParse(ip.Trim(), out IPAddress? address) ||
                address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            {
                return false;
            }

            byte[] bytes = address.GetAddressBytes();
            if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
            value = BitConverter.ToUInt32(bytes, 0);
            return true;
        }

        public List<string> GetIPRange(string ip1, string ip2)
        {
            if (ip2.Split('.').Length < 4) ip2 = CompleteIP(ip2, ip1);

            uint start = Math.Min(IPToUInt32(ip1), IPToUInt32(ip2));
            uint end = Math.Max(IPToUInt32(ip1), IPToUInt32(ip2));

            var result = new List<string>();
            for (uint ip = start; ip <= end; ip++)
            {
                string ipAddress = UInt32ToIP(ip);

                // Netzadresse (.0) ueberspringen
                if (int.Parse(ipAddress.Split('.')[3]) == 0) continue;

                result.Add(ipAddress);
            }
            return result;

            static string CompleteIP(string partialIP, string baseIP)
            {
                string[] baseParts = baseIP.Split('.');
                string[] partialParts = partialIP.Split('.');

                int missingParts = 4 - partialParts.Length;
                if (missingParts < 0 || missingParts > 3)
                    throw new ArgumentException("Ungueltige IP-Adresse oder zu viele Segmente in der zweiten IP.");

                var completedParts = new string[4];
                for (int i = 0; i < missingParts; i++) completedParts[i] = baseParts[i];
                for (int i = 0; i < partialParts.Length; i++) completedParts[missingParts + i] = partialParts[i];

                return string.Join(".", completedParts);
            }

            static uint IPToUInt32(string ipString)
            {
                byte[] bytes = IPAddress.Parse(ipString).GetAddressBytes();
                if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
                return BitConverter.ToUInt32(bytes, 0);
            }

            static string UInt32ToIP(uint ip)
            {
                byte[] bytes = BitConverter.GetBytes(ip);
                if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
                return new IPAddress(bytes).ToString();
            }
        }

        // ------------------------------------------------------------------
        // Ergebnis-Uebernahme
        // ------------------------------------------------------------------

        public void InsertIPToScanResult(IPToScan ipToScan)
        {
            ipToScan.Services.ShowOnlyIsRunningServices = chk_Services_showOnlyIsRunning.IsChecked == true;

            List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + ipToScan.IPorHostname + "'").ToList();

            var ports = new List<string>();
            if (ipToScan.TCP_OpenPorts.Count > 0) ports.Add($"Open: {string.Join("; ", ipToScan.TCP_OpenPorts)}");
            if (ipToScan.TCP_FirewallBlockedPorts.Count > 0) ports.Add($"ACL blocked: {string.Join("; ", ipToScan.TCP_FirewallBlockedPorts)}");

            if (rows.Count > 0 && ipToScan.IPorHostname != "000.000.000.000")
            {
                DataRow row = rows[0];
                FillRow(row, ipToScan, ports, isNewRow: false);
            }
            else
            {
                DataRow row = _scannResults.ResultTable.NewRow();
                FillRow(row, ipToScan, ports, isNewRow: true);
                _scannResults.ResultTable.Rows.Add(row);
            }
        }

        private void FillRow(DataRow row, IPToScan ipToScan, List<string> ports, bool isNewRow)
        {
            if (isNewRow && ipToScan.UsedScanMethod == ScanMethod.dontResolvedHostname)
            {
                row["Hostname"] = ipToScan.HostName;
            }

            if (!string.IsNullOrEmpty(ipToScan.IPGroupDescription)) row["IPGroupDescription"] = ipToScan.IPGroupDescription;
            if (!string.IsNullOrEmpty(ipToScan.DeviceDescription)) row["DeviceDescription"] = ipToScan.DeviceDescription;

            row["IP"] = ipToScan.IPorHostname;

            if (supportMethods.Is_Valid_IP(ipToScan.IPorHostname))
            {
                row["IPToSort"] = string.Join('.', ipToScan.IPorHostname.Split('.').Select(o => o.PadLeft(3, '0')));
            }

            if (ipToScan.DNSServerList != null)
            {
                row["DNSServers"] = string.Join(',', ipToScan.DNSServerList);
                row["NMGatewayIP"] = ipToScan.NMGatewayIP;
                row["NMGatewayPort"] = ipToScan.NMGatewayPort;
            }

            switch (ipToScan.UsedScanMethod)
            {
                case ScanMethod.SSDP:
                    row["SSDPStatus"] = ipToScan.SSDPStatus ? green_dot_s : red_dot_s;
                    break;

                case ScanMethod.NetBios:
                    row["NetBiosHostname"] = ipToScan.NetBiosHostname;
                    break;

                case ScanMethod.SMB:
                    row["detectedSMBVersions"] = ipToScan.SMBVersionsToString();
                    break;

                case ScanMethod.Services:
                    row["detectedServicePorts"] = ipToScan.Services.ToString();
                    break;

                case ScanMethod.SNMP:
                    row["SNMPSysName"] = ipToScan.SNMP_SysName;
                    row["SNMPInfos"] = ipToScan.SNMPInfos;
                    break;

                case ScanMethod.ARPRequest:
                    row["ARPStatus"] = ipToScan.ARPStatus ? green_dot_s : red_dot_s;
                    row["MAC"] = ipToScan.MAC;
                    row["Vendor"] = ipToScan.Vendor;
                    break;

                case ScanMethod.ARP_A:
                    if (row["ARPStatus"] is byte[] cellValue && cellValue.Length > 0)
                    {
                        if (!green_dot_s.SequenceEqual(cellValue)) row["ARPStatus"] = gray_dot_s;
                    }
                    else
                    {
                        row["ARPStatus"] = gray_dot_s;
                    }
                    row["MAC"] = ipToScan.MAC;
                    row["Vendor"] = ipToScan.Vendor;
                    break;

                case ScanMethod.Ping:
                    row["PingStatus"] = ipToScan.PingStatus ? green_dot_s : red_dot_s;
                    row["ResponseTime"] = ipToScan.ResponseTime;
                    break;

                case ScanMethod.ONVIF_IPCam:
                    row["IsIPCam"] = ipToScan.IsIPCam ? green_dot_s : (object)DBNull.Value;
                    row["IPCamName"] = ipToScan.IPCamName;
                    row["IPCamXAddress"] = ipToScan.IPCamXAddress;
                    break;

                case ScanMethod.ReverseLookup:
                    row["Hostname"] = ipToScan.HostName;
                    row["Domain"] = ipToScan.Domain;
                    row["Aliases"] = string.Join("\r\n", ipToScan.Aliases);
                    row["DNSServers"] = string.Join("\r\n", ipToScan.DNSServerList);

                    string resultHostname = row["Hostname"].ToString()!.ToUpper();
                    try
                    {
                        if (!string.IsNullOrEmpty(resultHostname))
                        {
                            row["InternalName"] = _internalNames.InternalNames
                                .Select("Hostname = '" + resultHostname + "'")[0]["InternalName"].ToString();
                        }
                    }
                    catch
                    {
                        row["InternalName"] = string.Empty;
                    }
                    break;

                case ScanMethod.Lookup:
                    row["LookUpIPs"] = ipToScan.LookUpIPs;
                    break;

                case ScanMethod.mDNS:
                    row["mDNSInfos"] = ipToScan.mDNS_toMultiLineString;
                    break;

                case ScanMethod.TCPPorts:
                    row["TCP_Ports"] = string.Join("\r\n", ports);
                    break;

                case ScanMethod.UDPPorts:
                    if (isNewRow) row["OpenUDP_Ports"] = string.Join("; ", ipToScan.UDP_OpenPorts);
                    break;
            }
        }

        // ------------------------------------------------------------------
        // Events der Scan-Methoden (UI-Thread ueber Dispatcher.UIThread)
        // ------------------------------------------------------------------

        private static void OnUi(Action action) => Dispatcher.UIThread.Post(action);

        private void ARP_A_newDevive_Finished(object? sender, ScanTask_Finished_EventArgs e) => OnUi(() =>
        {
            InsertIPToScanResult(e.ipToScan);
            status_ARP_A_Scan = ScanStatus.finished;
            Status();
        });

        private void ScanningMethods_Ping_ProgressUpdated(int arg1, int arg2, int arg3, ScanStatus scanStatus) => OnUi(() =>
        {
            counted_current_Ping_Scan = arg1;
            counted_responded_Ping_Scan = arg2;
            counted_total_Ping_Scan = arg3;
            status_Ping_Scan = scanStatus;
            Status();
        });

        private void Ping_Task_Finished(object? sender, ScanTask_Finished_EventArgs e) => OnUi(() => InsertIPToScanResult(e.ipToScan));

        private void PingFinished_Event(ScanStatus status) => OnUi(() =>
        {
            status_Ping_Scan = status;
            Status();
        });

        private void ScanningMethod_Find_ONVIF_IP_Cameras_ProgressUpdated(int arg1, int arg2, int arg3, ScanStatus scanStatus) => OnUi(() =>
        {
            counted_current__ONVIF_IP_Cam = arg1;
            counted_responded_ONVIF_IP_Cams = arg2;
            counted_total_ONVIF_IPs_toScan = arg3;
            status_ONVIF_IP_Cam_Scan = scanStatus;
            Status();
        });

        private void newIPCameraFound_Task_Finished(object? sender, ScanTask_Finished_EventArgs e) => OnUi(() => InsertIPToScanResult(e.ipToScan));

        private void IPCameraScan_Finished(ScanStatus status) => OnUi(() =>
        {
            status_ONVIF_IP_Cam_Scan = status;
            Status();
        });

        private void SSDP_foundNewDevice(object? sender, ScanTask_Finished_EventArgs e) => OnUi(() => InsertIPToScanResult(e.ipToScan));

        private void ScanningMethode_SSDP_UPNP_ProgressUpdated(int arg1, int arg2, int arg3, ScanStatus scanStatus) => OnUi(() =>
        {
            counted_responded_SSDP_device = arg2;
            status_SSDP_Scan = scanStatus;
            Status();
        });

        private void SSDP_Scan_Finished(ScanStatus status) => OnUi(() =>
        {
            status_SSDP_Scan = status;
            Status();
        });

        private void ScanningMethode_SNMP_SNMBFinished(bool obj) => OnUi(() =>
        {
            status_SNMP_Scan = ScanStatus.finished;
            Status();
        });

        private void ScanningMethode_SNMP_SNMB_Task_Finished(IPToScan obj) => OnUi(() =>
        {
            InsertIPToScanResult(obj);
            Status();
        });

        private void ScanningMethode_SNMP_ProgressUpdated(int arg1, int arg2, int arg3, ScanStatus scanStatus) => OnUi(() =>
        {
            counted_current_SNMP_Scan = arg1;
            counted_responded_SNMP_Devices = arg2;
            counted_total_SNMP_Devices = arg3;
            status_SNMP_Scan = scanStatus;
            Status();
        });

        private void ScanningMethod_SMBVersionCheck_SMB_Scan_Finished() => OnUi(() =>
        {
            status_SMB_VersionCheck = ScanStatus.finished;
            Status();
        });

        private void ScanningMethod_SMB_VersionCheck_ProgressUpdated(int arg1, int arg2, int arg3, ScanStatus scanStatus) => OnUi(() =>
        {
            counted_current_SMB_VersionCheck = arg1;
            counted_responded_SMB_VersionCheck = arg2;
            counted_total_SMB_VersionCheck = arg3;
            status_SMB_VersionCheck = scanStatus;
            Status();
        });

        private void ScanningMethod_SMB_VersionCheck_SMB_IP_Scan_Finished(IPToScan ipToScan) => OnUi(() =>
        {
            if (string.IsNullOrEmpty(ipToScan.IPorHostname)) return;
            InsertIPToScanResult(ipToScan);
        });

        private void ScanningMethod_NetBios_NetbiosIPScanFinished(IPToScan ipToScan) => OnUi(() =>
        {
            if (string.IsNullOrEmpty(ipToScan.NetBiosHostname)) return;
            InsertIPToScanResult(ipToScan);
        });

        private void ScanningMethode_NetBios_ProgressUpdated(int current, int responsed, int total, ScanStatus scanStatus) => OnUi(() =>
        {
            status_NetBios_Scan = scanStatus;
            counted_current_NetBiosScan = current;
            counted_responded_NetBiosInfos = responsed;
            counted_total_NetBiosInfos = total;
            Status();
        });

        private void ScanningMethod_NetBios_NetbiosScanFinished(bool obj) => OnUi(() =>
        {
            status_NetBios_Scan = ScanStatus.finished;
            Status();
        });

        private void ScanningMethod_Services_ScanStatusUpdated(ScanStatus obj) => OnUi(() =>
        {
            status_Services_Scan = obj;
            Status();
        });

        private void ScanningMethod_Services_ProgressUpdated(int arg1, int arg2, int arg3) => OnUi(() =>
        {
            counted_current_Service_IP_Scan = arg1;
            counted_responded_Services_IP_Scan = arg2;
            counted_total_Services_IP_Scan = arg3;
            Status();
        });

        private void ScanningMethod_Services_ServiceIPScanFinished(IPToScan ipToScan) => OnUi(() => InsertIPToScanResult(ipToScan));

        private void ScanningMethod_Services_ServiceScanFinished() => OnUi(() =>
        {
            status_Services_Scan = ScanStatus.finished;
            Status();
        });

        private void ScanningMethod_Services_FindServicePortProgressUpdated(int arg1, int arg2, int arg3) => OnUi(() =>
        {
            lbl_ScanStatus.Content = $"DeepScanedPorts: {arg1} / {arg2} / {arg3}";
        });

        private void ScanningMethod_Services_FindServicePortFinished(IPToScan obj) => OnUi(() =>
        {
            InsertIPToScanResult(obj);
            lbl_ScanStatus.Content = "find service port finished.";
        });

        private void ScanningMethode_ARP_ProgressUpdated(int arg1, int arg2, int arg3, ScanStatus scanStatus) => OnUi(() =>
        {
            counted_current_ARP_Requests = arg1;
            counted_responded_ARP_Requests = arg2;
            counted_total_ARP_Requests = arg3;
            status_ARP_Request_Scan = scanStatus;
            Status();
        });

        private void ARP_Request_Task_Finished(object? sender, ScanTask_Finished_EventArgs e) => OnUi(() =>
        {
            if (string.IsNullOrEmpty(e.ipToScan.IPorHostname)) return;
            InsertIPToScanResult(e.ipToScan);
        });

        private void ARP_Request_Finished(ScanStatus status) => OnUi(() =>
        {
            status_ARP_Request_Scan = status;
            Status();
        });

        private void ScanningMethode_ReverseLookupToHostAndAliases_ProgressUpdated(int arg1, int arg2, int arg3, ScanStatus status = ScanStatus.running) => OnUi(() =>
        {
            status_DNS_HostName_Scan = status;
            counted_current_DNS_HostNames = arg1;
            counted_responded_DNS_HostNames = arg2;
            counted_total_DNS_HostNames = arg3;
            Status();
        });

        private void DNS_GetHostAliases_Task_Finished(object? sender, ScanTask_Finished_EventArgs e) => OnUi(() =>
        {
            if (e == null || string.IsNullOrEmpty(e.ipToScan.HostName)) return;
            InsertIPToScanResult(e.ipToScan);
        });

        private void DNS_GetHostAndAliasFromIP_Finished(ScanStatus status) => OnUi(() =>
        {
            status_DNS_HostName_Scan = status;
            Status();
        });

        private void ScanningMethod_LookUp_ProgressUpdated(int arg1, int arg2, int arg3, ScanStatus arg4) => OnUi(() =>
        {
            counted_current_Lookup_Scan = arg1;
            counted_responded_Lookup_Devices = arg2;
            counted_total_Lookup_Scans = arg3;
            status_Lookup_Scan = arg4;
            Status();
        });

        private void Lookup_Task_Finished(object? sender, ScanTask_Finished_EventArgs e) => OnUi(() => InsertIPToScanResult(e.ipToScan));

        private void Lookup_Finished(ScanStatus status) => OnUi(() =>
        {
            status_Lookup_Scan = status;
            Status();
        });

        private void ScanningMethod_mDNS_ScanStatus(ScanStatus obj) => OnUi(() =>
        {
            status_mDNS_Scan = obj;
            Status();
        });

        private void ScanningMethod_MDNS_found_mDNS_Device(IPToScan obj) => OnUi(() => InsertIPToScanResult(obj));

        private void ScanningMethod_MDNS_ProgressUpdated(int arg1, int arg2, int arg3, ScanStatus arg4) => OnUi(() =>
        {
            countdown_mDNS = arg1;
            counted_responded_mDNS_Devices = arg2;
            Status();
        });

        private void TcpPortScan_Task_Finished(object? sender, ScanTask_Finished_EventArgs e) => OnUi(() =>
        {
            ++counted_current_TCP_Port_Scan;
            Status();

            if (e == null) return;

            InsertIPToScanResult(e.ipToScan);

            ++counted_responded_TCP_Port_Scan_Devices;
            Status();
        });

        private void TcpPortScan_Finished(ScanStatus status) => OnUi(() =>
        {
            status_TCP_Port_Scan = status;
            Status();
        });

        private void UDPPortScan_Task_Finished(object? sender, ScanTask_Finished_EventArgs e) => OnUi(() =>
        {
            InsertIPToScanResult(e.ipToScan);
            ++counted_current_UDP_Port_Scan;
            Status();
        });

        private void UDPPortScan_Finished(ScanStatus status) => OnUi(() =>
        {
            status_UDP_Port_Scan = status;
            Status();
        });
    }
}
