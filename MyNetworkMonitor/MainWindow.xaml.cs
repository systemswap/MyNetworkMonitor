

using Microsoft.Win32;
using System;

using System.Collections.Generic;

using System.ComponentModel;
using System.Data;
using System.Diagnostics;

using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;

using System.Reflection;

using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;

using System.Windows.Input;
using System.Windows.Media;
using System.Text.Json;
using System.Windows.Media.Imaging;
using static MyNetworkMonitor.SupportMethods;

//using static System.Net.WebRequestMethods;

namespace MyNetworkMonitor
{
    // install as Service https://www.youtube.com/watch?v=y64L-3HKuP0



    public partial class MainWindow : Window
    {        
        public MainWindow()
        {
            InitializeComponent();
           

            mainWindow.Title += " - version: " + Assembly.GetExecutingAssembly().GetName().Version.ToString(); 
           

            if (!Directory.Exists(Path.GetDirectoryName(_portsToScanXML))) Directory.CreateDirectory(Path.GetDirectoryName(_portsToScanXML));


            nicInfos = new Supporter_NetworkInterfaces().GetNetworkInterfaces();
            cb_NetworkAdapters.ItemsSource = nicInfos.Select(n => n.NicName).ToList();
            cb_NetworkAdapters.SelectedIndex = 0;



            supportMethods = new SupportMethods();
            //supportMethods.GetNetworkInterfaces();            

            scanningMethode_SSDP_UPNP = new ScanningMethod_SSDP_UPNP();
            scanningMethode_SSDP_UPNP.ProgressUpdated += ScanningMethode_SSDP_UPNP_ProgressUpdated;
            scanningMethode_SSDP_UPNP.SSDP_foundNewDevice += SSDP_foundNewDevice;
            scanningMethode_SSDP_UPNP.SSDP_Scan_Finished += SSDP_Scan_Finished;

            scanningMethode_SNMP = new ScanningMethod_SNMP();
            scanningMethode_SNMP.ProgressUpdated += ScanningMethode_SNMP_ProgressUpdated; ;
            scanningMethode_SNMP.SNMB_Task_Finished += ScanningMethode_SNMP_SNMB_Task_Finished; ;
            scanningMethode_SNMP.SNMBFinished += ScanningMethode_SNMP_SNMBFinished; ;

            scanningMethode_NetBios = new ScanningMethod_NetBios();
            scanningMethode_NetBios.ProgressUpdated += ScanningMethode_NetBios_ProgressUpdated;
            scanningMethode_NetBios.NetbiosIPScanFinished += ScanningMethod_NetBios_NetbiosIPScanFinished;
            scanningMethode_NetBios.NetbiosScanFinished += ScanningMethod_NetBios_NetbiosScanFinished;

            scanningMethod_SMB_VersionCheck = new ScanningMethod_SMBVersionCheck();
            scanningMethod_SMB_VersionCheck.ProgressUpdated += ScanningMethod_SMB_VersionCheck_ProgressUpdated; ;
            scanningMethod_SMB_VersionCheck.SMBIPScanFinished += ScanningMethod_SMB_VersionCheck_SMB_IP_Scan_Finished;
            scanningMethod_SMB_VersionCheck.SMBScanFinished += ScanningMethod_SMBVersionCheck_SMB_Scan_Finished;

            scanningMethod_Services = new ScanningMethod_Services();
            scanningMethod_Services.FindServicePortProgressUpdated += ScanningMethod_Services_FindServicePortProgressUpdated;
            scanningMethod_Services.FindServicePortFinished += ScanningMethod_Services_FindServicePortFinished; ;
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
            scanningMethode_ReverseLookupToHostAndAliases.GetHostAliases_Task_Finished += DNS_GetHostAliases_Task_Finished;
            scanningMethode_ReverseLookupToHostAndAliases.GetHostAliases_Finished += DNS_GetHostAndAliasFromIP_Finished;

            scanningMethod_LookUp = new ScanningMethod_LookUp();
            scanningMethod_LookUp.Lookup_Task_Finished += Lookup_Task_Finished;
            scanningMethod_LookUp.Lookup_Finished += Lookup_Finished;

            scanningMethode_PortsTCP = new ScanningMethod_PortsTCP();
            scanningMethode_PortsTCP.TcpPortScan_Task_Finished += TcpPortScan_Task_Finished;
            scanningMethode_PortsTCP.TcpPortScan_Finished += TcpPortScan_Finished;

            scanningMethode_PortsUDP = new ScanningMethod_PortsUDP();
            scanningMethode_PortsUDP.UDPPortScan_Task_Finished += UDPPortScan_Task_Finished;
            scanningMethode_PortsUDP.UDPPortScan_Finished += UDPPortScan_Finished;


            dv_resultTable = new DataView(_scannResults.ResultTable);
            dgv_Results.ItemsSource = dv_resultTable;

            if (!(bool)chk_allowDeleteRow.IsChecked)
            {
                dgv_Results.SelectionUnit = DataGridSelectionUnit.Cell;
            }

            cvTasks_scanResults = CollectionViewSource.GetDefaultView(dgv_Results.ItemsSource);
            if (cvTasks_scanResults != null && cvTasks_scanResults.CanGroup == true)
            {
                cvTasks_scanResults.GroupDescriptions.Clear();
                cvTasks_scanResults.GroupDescriptions.Add(new PropertyGroupDescription("IPGroupDescription"));
                cvTasks_scanResults.GroupDescriptions.Add(new PropertyGroupDescription("DeviceDescription"));
            }


            if (File.Exists(_ipGroupsXML))
            {
                try
                {
                    ipGroupData.IPGroupsDT.ReadXml(_ipGroupsXML);
                }
                catch (Exception)
                {

                }
            }

            //DataContext = ipGroupData.IPGroupsDT.DefaultView;

            dgv_IP_Ranges.ItemsSource = ipGroupData.IPGroupsDT.DefaultView;

            cvTasks_IP_Ranges = CollectionViewSource.GetDefaultView(dgv_IP_Ranges.ItemsSource);
            if (cvTasks_IP_Ranges != null && cvTasks_IP_Ranges.CanGroup == true)
            {
                cvTasks_IP_Ranges.GroupDescriptions.Clear();
                cvTasks_IP_Ranges.GroupDescriptions.Add(new PropertyGroupDescription("IPGroupDescription"));
                //cvTasks_IP_Ranges.GroupDescriptions.Add(new PropertyGroupDescription("DeviceDescription"));
            }


            if (File.Exists(_lastScanResultXML))
            {
                try
                {
                    _scannResults.ResultTable.ReadXml(_lastScanResultXML);
                }
                catch (Exception)
                {
                    //throw;
                }
            }

            if (File.Exists(_portsToScanXML))
            {
                try
                {
                    _portCollection.TableOfPortsToScan.Rows.Clear();
                    _portCollection.TableOfPortsToScan.ReadXml(_portsToScanXML);
                }
                catch (Exception)
                {
                    //throw;
                }
            }
            else
            {
                new PortCollection().TableOfPortsToScan.WriteXml(_portsToScanXML);
                //_portCollection.TableOfPortsToScan.ReadXml(_portsToScan);
            }
            dg_PortsToScan.ItemsSource = _portCollection.TableOfPortsToScan.DefaultView;



            if (File.Exists(_InternalNamesXML))
            {
                try
                {
                    _internalNames.InternalNames.ReadXml(_InternalNamesXML);
                }
                catch (Exception)
                {
                    //throw;
                }
            }
            dv_InternalNames = _internalNames.InternalNames.DefaultView;
            dg_InternalNames.ItemsSource = dv_InternalNames;

            LoadLogo();
        }

       

        private void LoadLogo()
        {
            string folder = "images";
            string[] extensions = { ".png", ".jpg", ".jpeg" };
            string logoPath = Array.Find(extensions, ext => File.Exists(Path.Combine(folder, "logo" + ext)));

            if (logoPath != null)
            {
                img_Logo.Source = new BitmapImage(new Uri(Path.Combine(folder, "logo" + logoPath), UriKind.RelativeOrAbsolute));
            }
            
        }


        public class CheckBoxSettings
        {
            public Dictionary<string, bool> CheckBoxStates { get; set; } = new Dictionary<string, bool>();
        }

        // Speichern der Einstellungen in eine JSON-Datei
        private void SaveServiceScanSettings()
        {
            var settings = new CheckBoxSettings
            {
                CheckBoxStates = new Dictionary<string, bool>
                {
                    { chk_Services_Web.Name, chk_Services_Web.IsChecked ?? false },
                    { chk_Services_FTP.Name, chk_Services_FTP.IsChecked ?? false },
                    {chk_Services_SSH.Name, chk_Services_SSH.IsChecked ?? false },
                    { chk_Services_DNS_TCP.Name, chk_Services_DNS_TCP.IsChecked ?? false },
                    {chk_Services_DNS_UDP.Name, chk_Services_DNS_UDP.IsChecked ?? false },
                    {chk_Services_DHCP.Name, chk_Services_DHCP.IsChecked ?? false },
                   
                    {chk_Services_RDP.Name, chk_Services_RDP.IsChecked ?? false },
                    {chk_Services_UltraVNC.Name, chk_Services_UltraVNC.IsChecked ?? false },
                    {chk_Services_TeamViewer.Name, chk_Services_TeamViewer.IsChecked ?? false },
                    {chk_Services_BigFixRemote.Name, chk_Services_BigFixRemote.IsChecked ?? false },
                    {chk_Services_AnyDesk.Name, chk_Services_AnyDesk.IsChecked ?? false },
                    {chk_Services_Rustdesk.Name, chk_Services_Rustdesk.IsChecked ?? false },

                    {chk_Services_MSSQL.Name, chk_Services_MSSQL.IsChecked ?? false },
                    {chk_Services_Postgre.Name, chk_Services_Postgre.IsChecked ?? false },
                    {chk_Services_MongoDB.Name, chk_Services_MongoDB.IsChecked ?? false },
                    {chk_Services_MariaDB.Name, chk_Services_MariaDB.IsChecked ?? false },
                    {chk_Services_MYSQL.Name, chk_Services_MYSQL.IsChecked ?? false },
                    {chk_Services_OracleDB.Name, chk_Services_OracleDB.IsChecked ?? false },

                    {chk_Services_OPCUA.Name, chk_Services_OPCUA.IsChecked ?? false },
                    {chk_Services_ModBus.Name, chk_Services_ModBus.IsChecked ?? false },
                    {chk_Services_SiemensS7.Name, chk_Services_SiemensS7.IsChecked ?? false },

                }
            };

            var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(_ServicesJson, json);
        }

        // Laden der Einstellungen aus JSON
        private void LoadServiceScanSettings()
        {
            if (File.Exists(_ServicesJson))
            {
                var json = File.ReadAllText(_ServicesJson);
                var settings = JsonSerializer.Deserialize<CheckBoxSettings>(json);

                chk_Services_Web.IsChecked = settings.CheckBoxStates.ContainsKey(chk_Services_Web.Name) ? settings.CheckBoxStates[chk_Services_Web.Name] : false;
                chk_Services_FTP.IsChecked = settings.CheckBoxStates.ContainsKey(chk_Services_FTP.Name) ? settings.CheckBoxStates[chk_Services_FTP.Name] : false;
                chk_Services_SSH.IsChecked = settings.CheckBoxStates.ContainsKey(chk_Services_SSH.Name) ? settings.CheckBoxStates[chk_Services_SSH.Name] : false;
                chk_Services_DNS_TCP.IsChecked = settings.CheckBoxStates.ContainsKey(chk_Services_DNS_TCP.Name) ? settings.CheckBoxStates[chk_Services_DNS_TCP.Name] : false;
                chk_Services_DNS_UDP.IsChecked = settings.CheckBoxStates.ContainsKey(chk_Services_DNS_UDP.Name) ? settings.CheckBoxStates[chk_Services_DNS_UDP.Name] : false;
                chk_Services_DHCP.IsChecked = settings.CheckBoxStates.ContainsKey(chk_Services_DHCP.Name) ? settings.CheckBoxStates[chk_Services_DHCP.Name] : false;

                chk_Services_RDP.IsChecked = settings.CheckBoxStates.ContainsKey(chk_Services_RDP.Name) ? settings.CheckBoxStates[chk_Services_RDP.Name] : false;
                chk_Services_UltraVNC.IsChecked = settings.CheckBoxStates.ContainsKey(chk_Services_UltraVNC.Name) ? settings.CheckBoxStates[chk_Services_UltraVNC.Name] : false;
                chk_Services_TeamViewer.IsChecked = settings.CheckBoxStates.ContainsKey(chk_Services_TeamViewer.Name) ? settings.CheckBoxStates[chk_Services_TeamViewer.Name] : false;
                chk_Services_BigFixRemote.IsChecked = settings.CheckBoxStates.ContainsKey(chk_Services_BigFixRemote.Name) ? settings.CheckBoxStates[chk_Services_BigFixRemote.Name] : false;
                chk_Services_AnyDesk.IsChecked = settings.CheckBoxStates.ContainsKey(chk_Services_AnyDesk.Name) ? settings.CheckBoxStates[chk_Services_AnyDesk.Name] : false;
                chk_Services_Rustdesk.IsChecked = settings.CheckBoxStates.ContainsKey(chk_Services_Rustdesk.Name) ? settings.CheckBoxStates[chk_Services_Rustdesk.Name] : false;

                chk_Services_MSSQL.IsChecked = settings.CheckBoxStates.ContainsKey(chk_Services_MSSQL.Name) ? settings.CheckBoxStates[chk_Services_MSSQL.Name] : false;
                chk_Services_Postgre.IsChecked = settings.CheckBoxStates.ContainsKey(chk_Services_Postgre.Name) ? settings.CheckBoxStates[chk_Services_Postgre.Name] : false;
                chk_Services_MongoDB.IsChecked = settings.CheckBoxStates.ContainsKey(chk_Services_MongoDB.Name) ? settings.CheckBoxStates[chk_Services_MongoDB.Name] : false;
                chk_Services_MariaDB.IsChecked = settings.CheckBoxStates.ContainsKey(chk_Services_MariaDB.Name) ? settings.CheckBoxStates[chk_Services_MariaDB.Name] : false;
                chk_Services_MYSQL.IsChecked = settings.CheckBoxStates.ContainsKey(chk_Services_MYSQL.Name) ? settings.CheckBoxStates[chk_Services_MYSQL.Name] : false;
                chk_Services_OracleDB.IsChecked = settings.CheckBoxStates.ContainsKey(chk_Services_OracleDB.Name) ? settings.CheckBoxStates[chk_Services_OracleDB.Name] : false;

                chk_Services_OPCUA.IsChecked = settings.CheckBoxStates.ContainsKey(chk_Services_OPCUA.Name) ? settings.CheckBoxStates[chk_Services_OPCUA.Name] : false;
                chk_Services_ModBus.IsChecked = settings.CheckBoxStates.ContainsKey(chk_Services_ModBus.Name) ? settings.CheckBoxStates[chk_Services_ModBus.Name] : false;
                chk_Services_SiemensS7.IsChecked = settings.CheckBoxStates.ContainsKey(chk_Services_SiemensS7.Name) ? settings.CheckBoxStates[chk_Services_SiemensS7.Name] : false;
            }
        }



        bool TextChangedByComboBox = false;
        List<NicInfo> nicInfos = new List<NicInfo>();

        ICollectionView cvTasks_scanResults;
        ICollectionView cvTasks_IP_Ranges;



        PortCollection _portCollection = new PortCollection();
        //string _portsToScanXML = Path.Combine(Environment.CurrentDirectory, @"Settings\portsToScan.xml");
        //string _ipGroupsXML = Path.Combine(Environment.CurrentDirectory, @"Settings\ipGroups.xml");
        //string _lastScanResultXML = Path.Combine(Environment.CurrentDirectory, @"Settings\lastScanResult.xml");
        //string _InternalNamesXML = Path.Combine(Environment.CurrentDirectory, @"Settings\internalNames.xml");


        string _portsToScanXML = Path.Combine(Path.Combine(Environment.ExpandEnvironmentVariables("%userprofile%"), "Documents"), @"MyNetworkMonitor\Settings\portsToScan.xml");
        string _ipGroupsXML = Path.Combine(Path.Combine(Environment.ExpandEnvironmentVariables("%userprofile%"), "Documents"), @"MyNetworkMonitor\Settings\ipGroups.xml");
        string _lastScanResultXML = Path.Combine(Path.Combine(Environment.ExpandEnvironmentVariables("%userprofile%"), "Documents"), @"MyNetworkMonitor\Settings\lastScanResult.xml");
        string _InternalNamesXML = Path.Combine(Path.Combine(Environment.ExpandEnvironmentVariables("%userprofile%"), "Documents"), @"MyNetworkMonitor\Settings\internalNames.xml");
        string _ServicesJson = Path.Combine(Path.Combine(Environment.ExpandEnvironmentVariables("%userprofile%"), "Documents"), @"MyNetworkMonitor\Settings\services.json");



        IPGroupData ipGroupData = new IPGroupData();


        //List<string> IPsToRefresh = new List<string>();
        int _TimeOut = 250;

        List<IPToScan> _IPsToScan = new List<IPToScan>();
        ScanResults _scannResults = new ScanResults();
        DataView dv_resultTable;


        InternalDeviceNames _internalNames = new InternalDeviceNames();
        DataView dv_InternalNames = new DataView();

        ScanningMethod_ARP scanningMethode_ARP;
        ScanningMethods_Ping scanningMethods_Ping;
        ScanningMethod_ONVIF_IPCam scanningMethod_Find_ONVIF_IP_Cameras;
        ScanningMethod_SSDP_UPNP scanningMethode_SSDP_UPNP;

        ScanningMethod_NetBios scanningMethode_NetBios;
        ScanningMethod_SMBVersionCheck scanningMethod_SMB_VersionCheck;
        ScanningMethod_Services scanningMethod_Services;

        ScanningMethod_SNMP scanningMethode_SNMP;
        ScanningMethod_ReverseLookupToHostAndAlieases scanningMethode_ReverseLookupToHostAndAliases;
        ScanningMethod_LookUp scanningMethod_LookUp;
        ScanningMethod_PortsTCP scanningMethode_PortsTCP;
        ScanningMethod_PortsUDP scanningMethode_PortsUDP;

        ScanningMethod_WiFi scanningMethode_WiFi_Signal;

        SupportMethods supportMethods;

        #region ScanStatus
        public enum ScanStatus
        {
            ignored,
            waiting,
            running,
            finished,
            [Description("port was used by another app, try later again")]
            AnotherLocalAppUsedThePort,

            [Description("wrong network interface selected")]
            wrongNetworkInterfaceSelected
        }


        ScanStatus status_ARP_A_Scan = ScanStatus.ignored;

        ScanStatus status_Ping_Scan = ScanStatus.ignored;
        int counted_current_Ping_Scan = 0;
        int counted_responded_Ping_Scan = 0;
        int counted_total_Ping_Scan = 0;

        ScanStatus status_SSDP_Scan = ScanStatus.ignored;
        int counted_responded_SSDP_device = 0;
        int counted_total_SSDPs = 0;

        ScanStatus status_ONVIF_IP_Cam_Scan = ScanStatus.ignored;
        int counted_responded_ONVIF_IP_Cams = 0;

        

        ScanStatus status_DNS_HostName_Scan = ScanStatus.ignored;
        int counted_current_DNS_HostNames = 0;
        int counted_responded_DNS_HostNames = 0;
        int counted_total_DNS_HostNames = 0;
        

        ScanStatus status_NetBios_Scan = ScanStatus.ignored;              
        int counted_current_NetBiosScan = 0;
        int counted_responded_NetBiosInfos = 0;
        int counted_total_NetBiosInfos = 0;

        ScanStatus status_SMB_VersionCheck = ScanStatus.ignored;
        int counted_current_SMB_VersionCheck = 0;
        int counted_responded_SMB_VersionCheck = 0;   
        int counted_total_SMB_VersionCheck = 0;

        ScanStatus status_Services_Scan = ScanStatus.ignored;
        int counted_current_Service_IP_Scan = 0;
        int counted_responded_Services_IP_Scan = 0;
        int counted_total_Services_IP_Scan = 0;

        ScanStatus status_SNMP_Scan = ScanStatus.ignored;
        int counted_current_SNMP_Scan = 0;
        int counted_responded_SNMP_Devices = 0;
        int counted_total_SNMP_Devices = 0;

        ScanStatus status_Lookup_Scan = ScanStatus.ignored;
        int counted_current_Lookup_Scan = 0;
        int counted_responded_Lookup_Devices = 0;
        int counted_total_Lookup_Scans = 0;
        

        ScanStatus status_ARP_Request_Scan = ScanStatus.ignored;
        int counted_current_ARP_Requests = 0;
        int counted_responded_ARP_Requests = 0;
        int counted_total_ARP_Requests = 0;
        

        ScanStatus status_TCP_Port_Scan = ScanStatus.ignored;
        int counted_current_TCP_Port_Scan = 0;
        int counted_responded_TCP_Port_Scan_Devices = 0;
        int counted_total_TCP_Port_Scans = 0;
       

        ScanStatus status_UDP_Port_Scan = ScanStatus.ignored;
        int counted_current_UDP_Port_Scan = 0;
        int counted_responded_UDP_Port_Devices = 0;
        int counted_total_UDP_Port_Devices = 0;




        public void Status()
        {
            List<string> lst_statusUpdate = new List<string>();
            List<string> lst_ignored =  new List<string>();

            lst_statusUpdate.Add(" * current / responded / total * ");

            if (status_ARP_Request_Scan == ScanStatus.ignored) { lst_ignored.Add("ARP Request: ignored"); } else { lst_statusUpdate.Add($"ARP Request: {status_ARP_Request_Scan.ToString()} {counted_current_ARP_Requests} / {counted_responded_ARP_Requests} / {counted_total_ARP_Requests}"); }
            if (status_Ping_Scan == ScanStatus.ignored) { lst_ignored.Add("Ping: ignored"); } else { lst_statusUpdate.Add($"Ping: {status_Ping_Scan.ToString()} {counted_current_Ping_Scan} / {counted_responded_Ping_Scan} / {counted_total_Ping_Scan}"); }
            if (status_SSDP_Scan == ScanStatus.ignored) { lst_ignored.Add("SSDP: ignored"); } else { lst_statusUpdate.Add($"SSDP: {status_SSDP_Scan.ToString()} ... / {counted_responded_SSDP_device} / ..."); }
            if (status_ONVIF_IP_Cam_Scan == ScanStatus.ignored) { lst_ignored.Add("IP-Cam`s: ignored"); } else { lst_statusUpdate.Add($"IP-Cam`s: {status_ONVIF_IP_Cam_Scan.ToString()} ... / {counted_responded_ONVIF_IP_Cams} / ..."); }            
            if (status_DNS_HostName_Scan == ScanStatus.ignored) { lst_ignored.Add("DNS Hostnames: ignored"); } else { lst_statusUpdate.Add($"DNS Hostnames: {status_DNS_HostName_Scan.ToString()} {counted_current_DNS_HostNames} / {counted_responded_DNS_HostNames} / {counted_total_DNS_HostNames}"); }
            if (status_Lookup_Scan == ScanStatus.ignored) { lst_ignored.Add("Lookup: ignored"); } else { lst_statusUpdate.Add($"Lookup: {status_Lookup_Scan.ToString()} {counted_current_Lookup_Scan} / {counted_responded_Lookup_Devices} / {counted_total_Lookup_Scans}"); }
            if (status_SMB_VersionCheck == ScanStatus.ignored) { lst_ignored.Add("SMB Check: ignored"); } else { lst_statusUpdate.Add($"SMB Check: {status_SMB_VersionCheck.ToString()} {counted_current_SMB_VersionCheck} / {counted_responded_SMB_VersionCheck} / {counted_total_SMB_VersionCheck}"); }
            if (status_NetBios_Scan == ScanStatus.ignored) { lst_ignored.Add("NetBios: ignored"); } else { lst_statusUpdate.Add($"NetBios: {status_NetBios_Scan.ToString()} {counted_current_NetBiosScan} / {counted_responded_NetBiosInfos} / {counted_total_NetBiosInfos}"); }
            if (status_SNMP_Scan == ScanStatus.ignored) { lst_ignored.Add("SNMP: ignored"); } else { lst_statusUpdate.Add($"SNMP: {status_SNMP_Scan.ToString()} {counted_current_SNMP_Scan} / {counted_responded_SNMP_Devices} / {counted_total_SNMP_Devices}"); }
            if (status_Services_Scan == ScanStatus.ignored) { lst_ignored.Add("Services: ignored"); } else { lst_statusUpdate.Add($"Services: {status_Services_Scan.ToString()} {counted_current_Service_IP_Scan} / {counted_responded_Services_IP_Scan} / {counted_total_Services_IP_Scan}"); }            
            if (status_TCP_Port_Scan == ScanStatus.ignored) { lst_ignored.Add("TCP Ports: ignored"); } else { lst_statusUpdate.Add($"TCP Ports: {status_TCP_Port_Scan.ToString()} {counted_current_TCP_Port_Scan} / {counted_responded_TCP_Port_Scan_Devices} / {counted_total_TCP_Port_Scans}"); }
            
            if (status_UDP_Port_Scan == ScanStatus.ignored) { lst_ignored.Add("UDP Ports: ignored"); } else { lst_statusUpdate.Add($"UDP Ports: {status_UDP_Port_Scan.ToString()} {counted_current_UDP_Port_Scan} / {counted_responded_UDP_Port_Devices} / {counted_total_UDP_Port_Devices}"); }
            
            if (status_ARP_A_Scan == ScanStatus.ignored) { lst_ignored.Add("ARP A: ignored"); } else { lst_statusUpdate.Add($"APR A: {status_ARP_A_Scan.ToString()} ... / ... / ..."); }

            lbl_ScanStatus.Content = string.Join("    ", lst_statusUpdate).Replace(ScanStatus.finished.ToString(), string.Empty);// + "    ||    " + ( string.Join("    ", lst_ignored).Replace(ScanStatus.finished.ToString(), string.Empty));
        }
        #endregion

        private void dgv_IPRanges_OnAutoGeneratingColumn(object sender, DataGridAutoGeneratingColumnEventArgs e)
        {
            if (e.PropertyName == "IPGroupDescription")
            {
                // replace text column with image column
                e.Column.Visibility = Visibility.Hidden;
            }

            if (e.PropertyName == "AutomaticScan")
            {
                // replace text column with image column
                e.Column.Visibility = Visibility.Hidden;
            }

            if (e.PropertyName == "ScanIntervalMinutes")
            {
                // replace text column with image column
                e.Column.Visibility = Visibility.Hidden;
            }

            //if (e.PropertyName == "GatewayIP")
            //{
            //    e.Column.Visibility = Visibility.Hidden;                
            //}
        }

        private void dgv_ScanResults_OnAutoGeneratingColumn(object sender, DataGridAutoGeneratingColumnEventArgs e)
        {
            if (e.PropertyName == "IPGroupDescription")
            {
                // replace text column with image column
                e.Column.Visibility = Visibility.Hidden;
            }

            //if (e.PropertyName == "DeviceDescription")
            //{
            //    // replace text column with image column
            //    e.Column.Visibility = Visibility.Hidden;
            //}

            if (e.PropertyName == "IPToSort")
            {
                // replace text column with image column
                e.Column.Visibility = Visibility.Hidden;
            }

            if (e.PropertyName == "SSDPStatus")
            {
                // replace text column with image column
                e.Column = new DataGridTemplateColumn
                {
                    // searching for predefined tenplate in Resources
                    CellTemplate = (sender as DataGrid).Resources["SSDPStatus"] as DataTemplate,
                    HeaderTemplate = e.Column.HeaderTemplate,
                    Header = e.Column.Header
                };
            }

            if (e.PropertyName == "ARPStatus")
            {
                // replace text column with image column
                e.Column = new DataGridTemplateColumn
                {
                    // searching for predefined tenplate in Resources
                    CellTemplate = (sender as DataGrid).Resources["ARPStatus"] as DataTemplate,
                    HeaderTemplate = e.Column.HeaderTemplate,
                    Header = e.Column.Header
                };
            }

            if (e.PropertyName == "PingStatus")
            {
                // replace text column with image column
                e.Column = new DataGridTemplateColumn
                {
                    // searching for predefined tenplate in Resources
                    CellTemplate = (sender as DataGrid).Resources["PingStatus"] as DataTemplate,
                    HeaderTemplate = e.Column.HeaderTemplate,
                    Header = e.Column.Header
                };
            }

            if (e.PropertyName == "IsIPCam")
            {
                // replace text column with image column
                e.Column = new DataGridTemplateColumn
                {
                    // searching for predefined tenplate in Resources
                    CellTemplate = (sender as DataGrid).Resources["IsIPCam"] as DataTemplate,
                    HeaderTemplate = e.Column.HeaderTemplate,
                    Header = e.Column.Header
                };
            }

            if (e.PropertyName == "LookUpStatus")
            {
                // replace text column with image column
                e.Column = new DataGridTemplateColumn
                {
                    // searching for predefined tenplate in Resources
                    CellTemplate = (sender as DataGrid).Resources["LookUpStatus"] as DataTemplate,
                    HeaderTemplate = e.Column.HeaderTemplate,
                    Header = e.Column.Header
                };
            }

            if (e.PropertyName == "MatchedWithInternal")
            {
                // replace text column with image column
                e.Column = new DataGridTemplateColumn
                {
                    // searching for predefined tenplate in Resources
                    CellTemplate = (sender as DataGrid).Resources["MatchedWithInternal"] as DataTemplate,
                    HeaderTemplate = e.Column.HeaderTemplate,
                    Header = e.Column.Header
                };
            }
        }



        private void bt_ScanIP_Click(object sender, RoutedEventArgs e)
        {
            _IPsToScan.Clear();
            List<int> TCPPorts = new List<int>();

            if ((bool)chk_Methodes_ScanTCPPorts.IsChecked && !(bool)chk_allTCPPorts.IsChecked)
            {
                TCPPorts.AddRange(_portCollection.TCPPorts);

                //Additional Ports from Customer
                if (!string.IsNullOrEmpty(tb_TCPPorts.Text))
                {
                    TCPPorts.AddRange(tb_TCPPorts.Text.Split(',')?.Select(Int32.Parse)?.ToList());
                }
            }

            if ((bool)chk_Methodes_ScanTCPPorts.IsChecked && (bool)chk_allTCPPorts.IsChecked)
            {
                TCPPorts.AddRange(Enumerable.Range(1, 65536));
            }


            if (!string.IsNullOrEmpty(tb_IP_Address.Text))
            {
                string IP_or_Hostname = tb_IP_Address.Text;
                if (supportMethods.Is_Valid_IP(IP_or_Hostname))
                {
                    IPToScan ipToScan = new IPToScan();
                    ipToScan.IPGroupDescription = "Custom";
                    ipToScan.DeviceDescription = "Custom";
                    ipToScan.IPorHostname = IP_or_Hostname;
                    ipToScan.HostName = string.Empty;
                    ipToScan.TCPPortsToScan = TCPPorts;
                    ipToScan.UDPPortsToScan = null;
                    ipToScan.DNSServerList.Add(tb_DNSServerIP.Text);
                    ipToScan.TimeOut = _TimeOut;
                    //ipToScan.GatewayIP = row["GatewayIP"].ToString();
                    //ipToScan.GatewayPort = row["GatewayPort"].ToString();

                    _IPsToScan.Add(ipToScan);
                }
                else
                {
                    IPHostEntry _entry = Task.Run(() => scanningMethod_LookUp.nsLookup(IP_or_Hostname)).Result;
                    if (_entry != null)
                    {
                        foreach (IPAddress address in _entry.AddressList)
                        {
                            IPToScan ipToScan = new IPToScan();
                            ipToScan.IPGroupDescription = "Custom";
                            ipToScan.DeviceDescription = "Custom";
                            ipToScan.IPorHostname = address.ToString();
                            if (_entry.HostName.Split('.').ToList().Count > 2)
                            {
                                List<string> HostDomainSplit = new List<string>();
                                HostDomainSplit.AddRange(_entry.HostName.ToString().Split(".", 2, StringSplitOptions.None).ToList());
                                ipToScan.HostName = (HostDomainSplit.Count >= 1) ? HostDomainSplit[0] : string.Empty;
                                ipToScan.Domain = (HostDomainSplit.Count >= 2) ? HostDomainSplit[1] : string.Empty;
                            }
                            else
                            {
                                ipToScan.HostName = _entry.HostName;
                            }
                            ipToScan.TCPPortsToScan = TCPPorts;
                            ipToScan.UDPPortsToScan = null;
                            ipToScan.DNSServerList = null;
                            ipToScan.TimeOut = _TimeOut;
                            //ipToScan.GatewayIP = row["GatewayIP"].ToString();
                            //ipToScan.GatewayPort = row["GatewayPort"].ToString();

                            _IPsToScan.Add(ipToScan);
                        }
                    }
                }
            }
            else
            {
                foreach (DataRowView row in dgv_Results.SelectedItems)
                {
                    if (_IPsToScan.Where(i => i.IPorHostname == row.Row["IP"].ToString()).Count() == 0)
                    {
                        IPToScan ipToScan = new IPToScan();
                        ipToScan.IPGroupDescription = row.Row["IPGroupDescription"].ToString();
                        ipToScan.DeviceDescription = row.Row["DeviceDescription"].ToString();
                        ipToScan.IPorHostname = row.Row["IP"].ToString();
                        ipToScan.HostName = row.Row["Hostname"].ToString();
                        ipToScan.Domain = row.Row["Domain"].ToString();
                        ipToScan.TCPPortsToScan = TCPPorts;
                        ipToScan.UDPPortsToScan = null;
                        ipToScan.DNSServerList = row.Row["DNSServers"].ToString().Split(',').ToList();
                        ipToScan.TimeOut = _TimeOut;
                        ipToScan.GatewayIP = row["GatewayIP"].ToString();
                        ipToScan.GatewayPort = row["GatewayPort"].ToString();

                        _IPsToScan.Add(ipToScan);
                    }
                }
            }
            DoWork(true);
        }


        private void bt_Scan_IP_Ranges_Click(object sender, RoutedEventArgs e)
        {
            _IPsToScan.Clear();

            List<string> IPs = new List<string>();
            string myIP = string.Empty; // new SupportMethods().GetLocalIPv4(System.Net.NetworkInformation.NetworkInterfaceType.Ethernet);

            myIP = "192.168.178.1";
            //myIP = "10.126.75.1";
            //myIP = "172.27.6.25";
            myIP = String.Join(".", myIP.Split(".")[0], myIP.Split(".")[1], myIP.Split(".")[2], "{0}");

            //for (int i = 1; i < 255; i++)
            //{
            //    IPs.Add(string.Format(myIP, i));
            //}


            List<int> TCPPorts = new List<int>();
            if ((bool)chk_Methodes_ScanTCPPorts.IsChecked && !(bool)chk_allTCPPorts.IsChecked)
            {
                TCPPorts.AddRange(_portCollection.TCPPorts);
            }
            else
            {
                TCPPorts.AddRange(Enumerable.Range(1, 65536));
            }


            foreach (DataRow row in ipGroupData.IPGroupsDT.Rows)
            {
                if ((bool)row["IsActive"])
                {


                    if (string.IsNullOrEmpty(row["LastIP"].ToString()))
                    {
                        string IP_or_Hostname = row["FirstIP"].ToString();
                        if (supportMethods.Is_Valid_IP(IP_or_Hostname))
                        {
                            IPToScan ipToScan = new IPToScan();
                            ipToScan.IPGroupDescription = row["IPGroupDescription"].ToString();
                            ipToScan.DeviceDescription = row["DeviceDescription"].ToString();
                            ipToScan.IPorHostname = IP_or_Hostname;
                            ipToScan.Domain = row["Domain"].ToString();
                            ipToScan.TCPPortsToScan = TCPPorts;
                            ipToScan.UDPPortsToScan = null;
                            //toRefresh.DNSServers = row["DNSServers"].ToString();
                            ipToScan.DNSServerList = row["DNSServers"].ToString().Split(',').ToList();
                            ipToScan.TimeOut = _TimeOut;
                            ipToScan.GatewayIP = row["GatewayIP"].ToString();
                            ipToScan.GatewayPort = row["GatewayPort"].ToString();

                            _IPsToScan.Add(ipToScan);
                        }
                        else
                        {
                            IPHostEntry _entry = Task.Run(() => scanningMethod_LookUp.nsLookup(IP_or_Hostname)).Result;
                            if (_entry != null)
                            {
                                foreach (IPAddress address in _entry.AddressList)
                                {
                                    IPToScan ipToScan = new IPToScan();
                                    ipToScan.IPGroupDescription = row["IPGroupDescription"].ToString();
                                    ipToScan.DeviceDescription = row["DeviceDescription"].ToString();
                                    ipToScan.IPorHostname = address.ToString();
                                    ipToScan.Domain = row["Domain"].ToString();
                                    ipToScan.TCPPortsToScan = TCPPorts;
                                    ipToScan.UDPPortsToScan = null;
                                    ipToScan.DNSServerList = row["DNSServers"].ToString().Split(',').ToList();
                                    ipToScan.TimeOut = _TimeOut;
                                    ipToScan.GatewayIP = row["GatewayIP"].ToString();
                                    ipToScan.GatewayPort = row["GatewayPort"].ToString();

                                    _IPsToScan.Add(ipToScan);
                                }
                            }
                        }
                    }
                    else
                    {
                        string[] FirstIP = row["FirstIP"].ToString().Split('.');
                        int LastIP = Convert.ToInt16(row["LastIP"]);

                        for (int i = Convert.ToInt16(FirstIP[3]); i <= LastIP; i++)
                        {
                            string ip = string.Format($"{FirstIP[0]}.{FirstIP[1]}.{FirstIP[2]}.{i}");

                            IPToScan ipToScan = new IPToScan();
                            ipToScan.IPGroupDescription = row["IPGroupDescription"].ToString();
                            ipToScan.DeviceDescription = row["DeviceDescription"].ToString();
                            ipToScan.IPorHostname = ip;
                            ipToScan.HostName = string.Empty;
                            //ipToScan.NetBiosHostname = string.Empty;
                            //ipToScan.destectedServices = string.Empty;
                            //ipToScan.SNMPSysName = string.Empty;
                            //ipToScan.SNMPSysDesc = string.Empty;
                            //ipToScan.SNMPLocation = string.Empty;
                            ipToScan.Domain = row["Domain"].ToString();
                            ipToScan.TCPPortsToScan = _portCollection.TCPPorts;
                            ipToScan.UDPPortsToScan = _portCollection.UDPPorts;
                            ipToScan.DNSServerList = row["DNSServers"].ToString().Split(',').ToList();
                            ipToScan.TimeOut = _TimeOut;
                            ipToScan.GatewayIP = row["GatewayIP"].ToString();
                            ipToScan.GatewayPort = row["GatewayPort"].ToString();

                            _IPsToScan.Add(ipToScan);
                        }
                    }
                }
            }
            DoWork(false);
        }


        public async void DoWork(bool IsSelectiveScan, bool ClearTable = false)
        {
            counted_current_Ping_Scan = 0;
            counted_total_Ping_Scan = 0;

            counted_responded_SSDP_device = 0;
            counted_total_SSDPs = 0;

            counted_current_SNMP_Scan = 0;
            counted_responded_SNMP_Devices = 0;
            counted_total_SNMP_Devices = 0;

            counted_current_DNS_HostNames = 0;
            counted_total_DNS_HostNames = 0;
            counted_responded_DNS_HostNames = 0;

            counted_total_NetBiosInfos = 0;
            counted_current_NetBiosScan = 0;
            counted_responded_NetBiosInfos = 0;

            counted_current_Service_IP_Scan = 0;
            counted_responded_Services_IP_Scan = 0;
            counted_total_Services_IP_Scan = 0;

            counted_current_Lookup_Scan = 0;
            counted_total_Lookup_Scans = 0;
            counted_responded_Lookup_Devices = 0;

            counted_current_ARP_Requests = 0;
            counted_total_ARP_Requests = 0;
            counted_responded_ARP_Requests = 0;

            counted_current_TCP_Port_Scan = 0;
            counted_total_TCP_Port_Scans = 0;
            counted_responded_TCP_Port_Scan_Devices = 0;

            counted_current_UDP_Port_Scan = 0;
            counted_total_UDP_Port_Devices = 0;


            foreach (DataRow row in _scannResults.ResultTable.Rows)
            {
                if (_IPsToScan.Where(i => i.IPorHostname == row["IP"].ToString()).Count() > 0)
                {
                    if ((bool)chk_Methodes_ARP_A.IsChecked && !string.IsNullOrEmpty(row["ARPStatus"].ToString())) row["ARPStatus"] = Properties.Resources.gray_dotTB;


                    if ((bool)chk_Methodes_Ping.IsChecked && !string.IsNullOrEmpty(row["PingStatus"].ToString())) row["PingStatus"] = Properties.Resources.gray_dotTB;
                    if ((bool)chk_Methodes_Ping.IsChecked) row["ResponseTime"] = string.Empty;

                    if ((bool)chk_Methodes_SSDP.IsChecked && !string.IsNullOrEmpty(row["SSDPStatus"].ToString())) row["SSDPStatus"] = Properties.Resources.gray_dotTB;

                    if ((bool)chk_Methodes_ONVIF.IsChecked && !string.IsNullOrEmpty(row["IsIPCam"].ToString())) row["IsIPCam"] = Properties.Resources.gray_dotTB;

                    if ((bool)chk_Methodes_ScanTCPPorts.IsChecked) row["TCP_Ports"] = null;
                    //if ((bool)chk_Methodes_ScanUDPPorts.IsChecked) row["OpenUDP_Ports"] = null;

                    if ((bool)chk_Methodes_ScanHostnames.IsChecked)
                    {
                        row["Domain"] = string.Empty;
                        row["Hostname"] = string.Empty;
                        row["Aliases"] = string.Empty;
                    }

                    if ((bool)chk_Methodes_LookUp.IsChecked && !string.IsNullOrEmpty(row["LookUpStatus"].ToString()))
                    {
                        row["LookUpStatus"] = Properties.Resources.gray_dotTB;
                        row["LookUpIPs"] = string.Empty;
                    }
                }
            }


            /* set the states */
            if ((bool)chk_Methodes_SSDP.IsChecked) status_SSDP_Scan = ScanStatus.waiting;
            if ((bool)chk_Methodes_ONVIF.IsChecked) status_ONVIF_IP_Cam_Scan = ScanStatus.waiting;
            if ((bool)chk_ARPRequest.IsChecked) status_ARP_Request_Scan = ScanStatus.waiting;
            if ((bool)chk_Methodes_Ping.IsChecked) status_Ping_Scan = ScanStatus.waiting;
            if ((bool)chk_Methodes_ScanHostnames.IsChecked) status_DNS_HostName_Scan = ScanStatus.waiting;
            if ((bool)chk_Methodes_ScanNetBios.IsChecked) status_NetBios_Scan = ScanStatus.waiting;
            if ((bool)chk_Methodes_Scan_SMBVersions.IsChecked) status_SMB_VersionCheck = ScanStatus.waiting;
            if ((bool)chk_Methodes_Scan_Services.IsChecked) status_Services_Scan = ScanStatus.waiting; 
            if ((bool)chk_Methodes_SNMP.IsChecked) status_SNMP_Scan = ScanStatus.waiting;
            if ((bool)chk_Methodes_LookUp.IsChecked) status_Lookup_Scan = ScanStatus.waiting;
            if ((bool)chk_Methodes_ScanTCPPorts.IsChecked) status_TCP_Port_Scan = ScanStatus.waiting;
            //if ((bool)chk_Methodes_ScanUDPPorts.IsChecked) status_UDP_Port_Scan = ScanStatus.waiting;
            if ((bool)chk_Methodes_ARP_A.IsChecked) status_ARP_A_Scan = ScanStatus.waiting;


            if ((bool)chk_ARP_DeleteCacheBefore.IsChecked)
            {
                foreach (DataRow row in _scannResults.ResultTable.Rows)
                {
                    row["ARPStatus"] = null;
                }
                await Task.Run(() => scanningMethode_ARP.DeleteARPCache());

                //give the operating systeme time to refresh themself
                await Task.Delay(2000);
            }

            if ((bool)chk_ARPRequest.IsChecked)
            {
                counted_total_ARP_Requests = _IPsToScan.Count;
                status_ARP_Request_Scan = ScanStatus.running;
                Status();

                await Task.Run(() => scanningMethode_ARP.SendARPRequestAsync(_IPsToScan));
            }

            if ((bool)chk_Methodes_Ping.IsChecked)
            {
                status_Ping_Scan = ScanStatus.running;
                counted_total_Ping_Scan = _IPsToScan.Count;
                Status();
                await Task.Run(() => scanningMethods_Ping.PingIPsAsync(_IPsToScan, false));
            }


            if ((bool)chk_Methodes_SSDP.IsChecked)
            {
                status_SSDP_Scan = ScanStatus.running;
                counted_total_SSDPs = _IPsToScan.Count;
                Status();
                await Task.Run(() => scanningMethode_SSDP_UPNP.Scan_for_SSDP_devices_async());
            }


            if ((bool)chk_Methodes_ONVIF.IsChecked)
            {
                status_ONVIF_IP_Cam_Scan = ScanStatus.running;
                Status();
                await Task.Run(() => scanningMethod_Find_ONVIF_IP_Cameras.Discover(_IPsToScan));

                //Task.Run(() => scanningMethod_FindIPCameras.GetSoapResponsesFromCamerasAsync(IPAddress.Parse("192.168.178.255"), _IPsToScan));
            }

            List<IPToScan> DNS_Hostname_IPsToScan = new List<IPToScan>();
            if ((bool)chk_Methodes_ScanHostnames.IsChecked)
            {

                if (_scannResults.ResultTable.Rows.Count == 0 || (bool)rb_ScanHostnames_All_IPs.IsChecked || IsSelectiveScan)
                {
                    DNS_Hostname_IPsToScan = _IPsToScan;
                }
                else
                {
                    foreach (DataRow row in _scannResults.ResultTable.Rows)
                    {
                        IPToScan ipToScan = new IPToScan();
                        ipToScan.IPGroupDescription = row["IPGroupDescription"].ToString();
                        ipToScan.DeviceDescription = row["DeviceDescription"].ToString();
                        ipToScan.IPorHostname = row["ip"].ToString();
                        ipToScan.HostName = row["Hostname"].ToString();
                        ipToScan.Domain = row["Domain"].ToString();
                        ipToScan.TCPPortsToScan = _portCollection.TCPPorts;
                        ipToScan.UDPPortsToScan = _portCollection.UDPPorts;
                        ipToScan.DNSServerList = row["DNSServers"].ToString().Split(',').ToList();
                        ipToScan.TimeOut = _TimeOut;
                        ipToScan.GatewayIP = row["GatewayIP"].ToString();
                        ipToScan.GatewayPort = row["GatewayPort"].ToString();

                        DNS_Hostname_IPsToScan.Add(ipToScan);
                    }
                }

                status_DNS_HostName_Scan = ScanStatus.running;
                counted_total_DNS_HostNames = DNS_Hostname_IPsToScan.Count;
                //CountedHostnames = _IPsToRefresh.Count;
                Status();

                if ((bool)chk_Methodes_LookUp.IsChecked)
                {
                    status_Lookup_Scan = ScanStatus.waiting;
                    Status();
                }

                await Task.Run(() => scanningMethode_ReverseLookupToHostAndAliases.GetHost_Aliases(DNS_Hostname_IPsToScan));
                //await Task.Run(() => scanningMethode_DNS.Get_Host_and_Alias_From_IP(_IPsToRefresh));
            }


            if ((bool)chk_Methodes_LookUp.IsChecked)
            {
                //give some time to insert the results of DNS Hostname into Datatable
                await Task.Run(() => Thread.Sleep(1000));

                List<IPToScan> IPsForLookUp = new List<IPToScan>();
                foreach (IPToScan _ipToScan in DNS_Hostname_IPsToScan)
                {
                    List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + _ipToScan.IPorHostname + "'").ToList();

                    if (rows.Count > 0)
                    {
                        int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);

                        if (!string.IsNullOrEmpty(_scannResults.ResultTable.Rows[rowIndex]["Hostname"].ToString()))
                        {
                            IPToScan ipToScan = new IPToScan();
                            ipToScan.IPGroupDescription = _scannResults.ResultTable.Rows[rowIndex]["IPGroupDescription"].ToString();
                            ipToScan.DeviceDescription = _scannResults.ResultTable.Rows[rowIndex]["DeviceDescription"].ToString();
                            ipToScan.IPorHostname = _ipToScan.IPorHostname;
                            ipToScan.HostName = _scannResults.ResultTable.Rows[rowIndex]["Hostname"].ToString();
                            ipToScan.Domain = _scannResults.ResultTable.Rows[rowIndex]["Domain"].ToString();
                            ipToScan.DNSServerList = _scannResults.ResultTable.Rows[rowIndex]["DNSServers"].ToString().Split(',').ToList();
                            ipToScan.GatewayIP = _scannResults.ResultTable.Rows[rowIndex]["GatewayIP"].ToString();
                            ipToScan.GatewayPort = _scannResults.ResultTable.Rows[rowIndex]["GatewayPort"].ToString();

                            IPsForLookUp.Add(ipToScan);
                        }
                    }
                }

                status_Lookup_Scan = ScanStatus.running;
                counted_total_Lookup_Scans = IPsForLookUp.Count;
                Status();

                Task.Run(() => scanningMethod_LookUp.LookupAsync(IPsForLookUp));
            }

            List<IPToScan> SMB_IPsToScan = new List<IPToScan>();
            if ((bool)chk_Methodes_Scan_SMBVersions.IsChecked)
            {
                if (_scannResults.ResultTable.Rows.Count == 0 || (bool)rb_ScanHostnames_All_IPs.IsChecked || IsSelectiveScan)
                {
                    SMB_IPsToScan = _IPsToScan;
                }
                else
                {
                    foreach (DataRow row in _scannResults.ResultTable.Rows)
                    {
                        IPToScan ipToScan = new IPToScan();
                        ipToScan.IPorHostname = row["ip"].ToString();
                        SMB_IPsToScan.Add(ipToScan);
                    }
                }
                status_SMB_VersionCheck = ScanStatus.running;
                await scanningMethod_SMB_VersionCheck.ScanMultipleIPsAsync(SMB_IPsToScan, CancellationToken.None);
            }

            List<IPToScan> NetBios_IPsToScan = new List<IPToScan>();
            if ((bool)chk_Methodes_ScanNetBios.IsChecked)
            {
                if (_scannResults.ResultTable.Rows.Count == 0 || (bool)rb_ScanHostnames_All_IPs.IsChecked || IsSelectiveScan)
                {
                    NetBios_IPsToScan = _IPsToScan;
                }
                else
                {
                    foreach (DataRow row in _scannResults.ResultTable.Rows)
                    {
                        IPToScan ipToScan = new IPToScan();
                        ipToScan.IPorHostname = row["ip"].ToString();
                        NetBios_IPsToScan.Add(ipToScan);
                    }
                }
                status_NetBios_Scan = ScanStatus.running;
                await Task.Run(() => scanningMethode_NetBios.ScanMultipleIPsAsync(NetBios_IPsToScan, CancellationToken.None));
            }


            if ((bool)chk_Methodes_SNMP.IsChecked)
            {
                status_SNMP_Scan = ScanStatus.running;
                //requestedSNMPCount = _IPsToScan.Count;
                Status();
                await Task.Run(() => scanningMethode_SNMP.ScanAsync(_IPsToScan));
            }
            

            List<IPToScan> Services_IPsToScan = new List<IPToScan>();
            if ((bool)chk_Methodes_Scan_Services.IsChecked)
            {
                if (_scannResults.ResultTable.Rows.Count == 0 || (bool)rb_ScanHostnames_All_IPs.IsChecked || IsSelectiveScan)
                {
                    Services_IPsToScan = _IPsToScan;
                }
                else
                {
                    foreach (DataRow row in _scannResults.ResultTable.Rows)
                    {
                        IPToScan ipToScan = new IPToScan();
                        ipToScan.IPorHostname = row["ip"].ToString();
                        Services_IPsToScan.Add(ipToScan);
                    }
                }

                //var additionalServicePorts = new Dictionary<ServiceType, List<int>>
                //{
                //    { ServiceType.UltraVNC, new List<int> { 5901, 5902 } },
                //    //{ ServiceType.Teamviewer, new List<int> { 5938 } },
                //    //{ ServiceType.RDP, new List<int> { 3389 } }
                //};

                status_Services_Scan = ScanStatus.running;
                //await scanningMethod_Services.ScanIPsAsync(Services_IPsToScan, new List<ServiceType> { ServiceType.DHCP});


                List<ServiceType> services = new List<ServiceType>();
                // 🌍 Netzwerk-Dienste
                if ((bool)chk_Services_Web.IsChecked) services.Add(ServiceType.WebServices);
                if ((bool)chk_Services_FTP.IsChecked) services.Add(ServiceType.FTP);
                if ((bool)chk_Services_SSH.IsChecked) services.Add(ServiceType.SSH);
                if ((bool)chk_Services_DNS_TCP.IsChecked) services.Add(ServiceType.DNS_TCP);
                if ((bool)chk_Services_DNS_UDP.IsChecked) services.Add(ServiceType.DNS_UDP);
                if ((bool)chk_Services_DHCP.IsChecked) services.Add(ServiceType.DHCP);

                // Remote Apps
                if ((bool)chk_Services_RDP.IsChecked) services.Add(ServiceType.RDP);
                if ((bool)chk_Services_UltraVNC.IsChecked) services.Add(ServiceType.UltraVNC);
                if ((bool)chk_Services_TeamViewer.IsChecked) services.Add(ServiceType.TeamViewer);
                if ((bool)chk_Services_BigFixRemote.IsChecked) services.Add(ServiceType.BigFixRemote);
                if ((bool)chk_Services_AnyDesk.IsChecked) services.Add(ServiceType.Anydesk);
                if ((bool)chk_Services_Rustdesk.IsChecked) services.Add(ServiceType.Rustdesk);

                // Datenbanken
                if ((bool)chk_Services_MSSQL.IsChecked) services.Add(ServiceType.MSSQLServer);
                if ((bool)chk_Services_Postgre.IsChecked) services.Add(ServiceType.PostgreSQL);
                if ((bool)chk_Services_MongoDB.IsChecked) services.Add(ServiceType.MongoDB);
                if ((bool)chk_Services_MariaDB.IsChecked) services.Add(ServiceType.MariaDB);
                if ((bool)chk_Services_MYSQL.IsChecked) services.Add(ServiceType.MySQL);
                if ((bool)chk_Services_OracleDB.IsChecked) services.Add(ServiceType.OracleDB);


                // Industrieprotokolle  
                if ((bool)chk_Services_OPCUA.IsChecked) services.Add(ServiceType.OPCUA);
                if ((bool)chk_Services_ModBus.IsChecked) services.Add(ServiceType.ModBus);
                if ((bool)chk_Services_SiemensS7.IsChecked) services.Add(ServiceType.S7);


                await scanningMethod_Services.ScanIPsAsync(Services_IPsToScan, services);
            }
           

            List<IPToScan> _IPsForTCPPortScan = new List<IPToScan>();
            if ((bool)chk_Methodes_ScanTCPPorts.IsChecked)
            {
                if (_scannResults.ResultTable.Rows.Count == 0 || !(bool)chk_TCPPortsScanOnlyIPsInTable.IsChecked || IsSelectiveScan)
                {
                    _IPsForTCPPortScan = _IPsToScan;
                }
                else
                {
                    foreach (DataRow row in _scannResults.ResultTable.Rows)
                    {
                        IPToScan ipToScan = new IPToScan();
                        ipToScan.IPGroupDescription = row["IPGroupDescription"].ToString();
                        ipToScan.DeviceDescription = row["DeviceDescription"].ToString();
                        ipToScan.IPorHostname = row["ip"].ToString();
                        ipToScan.HostName = row["Hostname"].ToString();
                        ipToScan.Domain = row["Domain"].ToString();
                        ipToScan.TCPPortsToScan = _portCollection.TCPPorts;
                        ipToScan.UDPPortsToScan = _portCollection.UDPPorts;
                        ipToScan.DNSServerList = row["DNSServers"].ToString().Split(',').ToList();
                        ipToScan.TimeOut = _TimeOut;
                        ipToScan.GatewayIP = row["GatewayIP"].ToString();
                        ipToScan.GatewayPort = row["GatewayPort"].ToString();

                        _IPsForTCPPortScan.Add(ipToScan);
                    }
                }

                status_TCP_Port_Scan = ScanStatus.running;
                counted_total_TCP_Port_Scans = _IPsForTCPPortScan.Count;
                Status();

                await Task.Run(() => scanningMethode_PortsTCP.ScanTCPPortsAsync(_IPsForTCPPortScan, new TimeSpan(0, 0, 0, 0, _TimeOut)));
            }


            //if ((bool)chk_Methodes_ScanUDPPorts.IsChecked)
            //{
            //    status_UDP_Port_Scan = ScanStatus.running;
            //    Status();

            //    Task.Run(() => scanningMethode_PortsUDP.Get_All_UPD_Listener_as_List(_IPsToScan));
            //}


            if ((bool)chk_Methodes_ARP_A.IsChecked)
            {
                status_ARP_A_Scan = ScanStatus.running;
                Status();

                Task.Run(() => scanningMethode_ARP.ARP_A(_IPsToScan));
            }
        }

        public void InsertIPToScanResult(IPToScan ipToScan)
        {
            Keyboard.ClearFocus();

            List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + ipToScan.IPorHostname + "'").ToList();

            List<string> ports = new List<string>();
            if (ipToScan.TCP_OpenPorts.Count > 0) ports.Add(string.Format($"Open: {string.Join("; ", ipToScan.TCP_OpenPorts)}"));
            if (ipToScan.TCP_FirewallBlockedPorts.Count > 0) ports.Add(string.Format($"ACL blocked: {string.Join("; ", ipToScan.TCP_FirewallBlockedPorts)}"));


            if (rows.Count > 0)
            {
                int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);
                _scannResults.ResultTable.Rows[rowIndex]["IPGroupDescription"] = ipToScan.IPGroupDescription;
                _scannResults.ResultTable.Rows[rowIndex]["DeviceDescription"] = ipToScan.DeviceDescription;
                _scannResults.ResultTable.Rows[rowIndex]["IP"] = ipToScan.IPorHostname;

                if (supportMethods.Is_Valid_IP(ipToScan.IPorHostname))
                {
                    _scannResults.ResultTable.Rows[rowIndex]["IPToSort"] = string.Join('.', ipToScan.IPorHostname.Split('.').Select(o => o.PadLeft(3, '0')));
                }

                _scannResults.ResultTable.Rows[rowIndex]["DNSServers"] = string.Join(',', ipToScan.DNSServerList);
                _scannResults.ResultTable.Rows[rowIndex]["GatewayIP"] = ipToScan.GatewayIP;
                _scannResults.ResultTable.Rows[rowIndex]["GatewayPort"] = ipToScan.GatewayPort;

                if (ipToScan.UsedScanMethod == ScanMethod.SSDP)
                {
                    _scannResults.ResultTable.Rows[rowIndex]["SSDPStatus"] = ipToScan.SSDPStatus ? Properties.Resources.green_dot : Properties.Resources.red_dotTB;
                }


                if (ipToScan.UsedScanMethod == ScanMethod.NetBios)
                {
                    _scannResults.ResultTable.Rows[rowIndex]["NetBiosHostname"] = ipToScan.NetBiosHostname;        
                }

                if (ipToScan.UsedScanMethod == ScanMethod.SMB)
                {
                    if(!string.IsNullOrEmpty(_scannResults.ResultTable.Rows[rowIndex]["detectedSMBVersions"].ToString())) _scannResults.ResultTable.Rows[rowIndex]["detectedSMBVersions"] = ipToScan.SMBVersionsToString();                  
                    _scannResults.ResultTable.Rows[rowIndex]["detectedSMBVersions"] = ipToScan.SMBVersionsToString();
                }

                if (ipToScan.UsedScanMethod == ScanMethod.Services)
                {
                    if(!string.IsNullOrEmpty(_scannResults.ResultTable.Rows[rowIndex]["detectedServicePorts"].ToString())) _scannResults.ResultTable.Rows[rowIndex]["detectedServicePorts"] = ipToScan.Services.ToString();                 
                    _scannResults.ResultTable.Rows[rowIndex]["detectedServicePorts"] = ipToScan.Services.ToString();
                }

                if (ipToScan.UsedScanMethod == ScanMethod.SNMP)
                {
                    _scannResults.ResultTable.Rows[rowIndex]["SNMPSysName"] = ipToScan.SNMPSysName;
                    _scannResults.ResultTable.Rows[rowIndex]["SNMPSysDesc"] = ipToScan.SNMPSysDesc;
                    _scannResults.ResultTable.Rows[rowIndex]["SNMPLocation"] = ipToScan.SNMPLocation;
                }


                if (ipToScan.UsedScanMethod == ScanMethod.ARPRequest)
                {
                    _scannResults.ResultTable.Rows[rowIndex]["ARPStatus"] = ipToScan.ARPStatus ? Properties.Resources.green_dot : Properties.Resources.red_dotTB;
                    _scannResults.ResultTable.Rows[rowIndex]["MAC"] = ipToScan.MAC;
                    _scannResults.ResultTable.Rows[rowIndex]["Vendor"] = ipToScan.Vendor;
                }

                if (ipToScan.UsedScanMethod == ScanMethod.ARP_A)
                {
                    if (!string.IsNullOrEmpty(_scannResults.ResultTable.Rows[rowIndex]["ARPStatus"].ToString()))
                    {
                        byte[] greenDot = Properties.Resources.green_dot;
                        byte[] cellValue = (byte[])_scannResults.ResultTable.Rows[rowIndex]["ARPStatus"];
                        bool bla = greenDot.SequenceEqual(cellValue);
                        if (!bla) _scannResults.ResultTable.Rows[rowIndex]["ARPStatus"] = Properties.Resources.gray_dotTB;
                    }
                    else
                    {
                        _scannResults.ResultTable.Rows[rowIndex]["ARPStatus"] = Properties.Resources.gray_dotTB;
                    }
                    //_scannResults.ResultTable.Rows[rowIndex]["ARPStatus"] = ipToScan.ARPStatus ? Properties.Resources.green_dot : Properties.Resources.red_dotTB;
                    _scannResults.ResultTable.Rows[rowIndex]["MAC"] = ipToScan.MAC;
                    _scannResults.ResultTable.Rows[rowIndex]["Vendor"] = ipToScan.Vendor;
                }


                if (ipToScan.UsedScanMethod == ScanMethod.Ping)
                {
                    _scannResults.ResultTable.Rows[rowIndex]["PingStatus"] = ipToScan.PingStatus ? Properties.Resources.green_dot : Properties.Resources.red_dotTB;
                    _scannResults.ResultTable.Rows[rowIndex]["ResponseTime"] = ipToScan.ResponseTime;
                }

                if (ipToScan.UsedScanMethod == ScanMethod.ONVIF_IPCam)
                {
                    _scannResults.ResultTable.Rows[rowIndex]["IsIPCam"] = ipToScan.IsIPCam ? Properties.Resources.green_dot : null;
                    _scannResults.ResultTable.Rows[rowIndex]["IPCamName"] = ipToScan.IPCamName;
                    _scannResults.ResultTable.Rows[rowIndex]["IPCamXAddress"] = ipToScan.IPCamXAddress;
                }

                if (ipToScan.UsedScanMethod == ScanMethod.ReverseLookup)
                {

                    _scannResults.ResultTable.Rows[rowIndex]["Hostname"] = ipToScan.HostName;
                    _scannResults.ResultTable.Rows[rowIndex]["Domain"] = ipToScan.Domain;
                    _scannResults.ResultTable.Rows[rowIndex]["Aliases"] = string.Join("\r\n", ipToScan.Aliases);

                    string resultHostname = _scannResults.ResultTable.Rows[rowIndex]["Hostname"].ToString().ToUpper();
                    string resultIP = _scannResults.ResultTable.Rows[rowIndex]["IP"].ToString();

                    try
                    {
                        if (!string.IsNullOrEmpty(resultHostname)) _scannResults.ResultTable.Rows[rowIndex]["InternalName"] = _internalNames.InternalNames.Select("Hostname = '" + resultHostname + "'")[0]["InternalName"].ToString();
                    }
                    catch
                    {
                        _scannResults.ResultTable.Rows[rowIndex]["InternalName"] = string.Empty;
                    }

                    try
                    {
                        //check if the IP in the internal names returns the same hostname like the dns server
                        string InternalNames_Hostname_from_ScannedIP = _internalNames.InternalNames.Select("StaticIP = '" + resultIP + "'")[0]["Hostname"].ToString().ToUpper();

                        bool dnsMatched = false;
                        dnsMatched = InternalNames_Hostname_from_ScannedIP == resultHostname;

                        if (dnsMatched && !string.IsNullOrEmpty(resultHostname))
                        {
                            _scannResults.ResultTable.Rows[rowIndex]["MatchedWithInternal"] = Properties.Resources.green_dot;
                        }
                        if (!dnsMatched && !string.IsNullOrEmpty(resultHostname))
                        {
                            _scannResults.ResultTable.Rows[rowIndex]["MatchedWithInternal"] = Properties.Resources.red_dotTB;
                        }
                        if (string.IsNullOrEmpty(resultHostname))
                        {
                            _scannResults.ResultTable.Rows[rowIndex]["MatchedWithInternal"] = null;
                        }
                    }
                    catch (Exception)
                    {
                        _scannResults.ResultTable.Rows[rowIndex]["MatchedWithInternal"] = null;
                    }
                }

                if (ipToScan.UsedScanMethod == ScanMethod.Lookup)
                {
                    _scannResults.ResultTable.Rows[rowIndex]["LookUpStatus"] = ipToScan.LookUpStatus ? Properties.Resources.green_dot : Properties.Resources.red_dotTB;
                    _scannResults.ResultTable.Rows[rowIndex]["LookUpIPs"] = ipToScan.LookUpIPs;
                }

                if (ipToScan.UsedScanMethod == ScanMethod.TCPPorts)
                {
                    _scannResults.ResultTable.Rows[rowIndex]["TCP_Ports"] = string.Join("\r\n", ports);
                }

                if (ipToScan.UsedScanMethod == ScanMethod.UDPPorts)
                {
                    _scannResults.ResultTable.Rows[rowIndex]["OpenUDP_Ports"] = string.Join("; ", ipToScan.UDP_OpenPorts);
                }
            }
            else
            {
                DataRow row = _scannResults.ResultTable.NewRow();
                row["IPGroupDescription"] = ipToScan.IPGroupDescription;
                row["DeviceDescription"] = ipToScan.DeviceDescription;
                row["IP"] = ipToScan.IPorHostname;

                if (supportMethods.Is_Valid_IP(ipToScan.IPorHostname))
                {
                    row["IPToSort"] = string.Join('.', ipToScan.IPorHostname.Split('.').Select(o => o.PadLeft(3, '0')));
                }


                row["DNSServers"] = string.Join(',', ipToScan.DNSServerList);
                row["GatewayIP"] = ipToScan.GatewayIP;
                row["GatewayPort"] = ipToScan.GatewayPort;

                if (ipToScan.UsedScanMethod == ScanMethod.SSDP)
                {
                    row["SSDPStatus"] = ipToScan.SSDPStatus ? Properties.Resources.green_dot : Properties.Resources.red_dotTB;
                }

                if (ipToScan.UsedScanMethod == ScanMethod.SNMP)
                {
                    row["SNMPSysName"] = ipToScan.SNMPSysName;
                    row["SNMPSysDesc"] = ipToScan.SNMPSysDesc;
                    row["SNMPLocation"] = ipToScan.SNMPLocation;
                }

                if (ipToScan.UsedScanMethod == ScanMethod.NetBios)
                {
                    row["NetBiosHostname"] = ipToScan.NetBiosHostname;
                }

                if (ipToScan.UsedScanMethod == ScanMethod.SMB)
                {
                    if(!string.IsNullOrEmpty(row["detectedSMBVersions"].ToString())) row["detectedSMBVersions"] = string.Empty;
                    row["detectedSMBVersions"] = ipToScan.SMBVersionsToString();
                }

                if (ipToScan.UsedScanMethod == ScanMethod.Services)
                {
                    if (!string.IsNullOrEmpty(row["detectedServicePorts"].ToString())) row["detectedServicePorts"] = string.Empty;
                    row["detectedServicePorts"] = ipToScan.Services.ToString();
                }

                if (ipToScan.UsedScanMethod == ScanMethod.ARPRequest)
                {
                    row["ARPStatus"] = ipToScan.ARPStatus ? Properties.Resources.green_dot : Properties.Resources.red_dotTB;
                    row["MAC"] = ipToScan.MAC;
                    row["Vendor"] = ipToScan.Vendor;
                }

                if (ipToScan.UsedScanMethod == ScanMethod.ARP_A)
                {
                    if (!string.IsNullOrEmpty(row["ARPStatus"].ToString()))
                    {
                        byte[] greenDot = Properties.Resources.green_dot;
                        byte[] cellValue = (byte[])row["ARPStatus"];
                        bool bla = greenDot.SequenceEqual(cellValue);
                        if (!bla) row["ARPStatus"] = Properties.Resources.gray_dotTB;
                    }
                    else
                    {
                        row["ARPStatus"] = Properties.Resources.gray_dotTB;
                    }
                    //row["ARPStatus"] = ipToScan.ARPStatus ? Properties.Resources.green_dot : Properties.Resources.red_dotTB;
                    row["MAC"] = ipToScan.MAC;
                    row["Vendor"] = ipToScan.Vendor;
                }

                if (ipToScan.UsedScanMethod == ScanMethod.Ping)
                {
                    row["PingStatus"] = ipToScan.PingStatus ? Properties.Resources.green_dot : Properties.Resources.red_dotTB;
                    row["ResponseTime"] = ipToScan.ResponseTime;
                }



                if (ipToScan.UsedScanMethod == ScanMethod.ONVIF_IPCam)
                {
                    row["IsIPCam"] = ipToScan.IsIPCam ? Properties.Resources.green_dot : null;
                    row["IPCamName"] = ipToScan.IPCamName;
                    row["IPCamXAddress"] = ipToScan.IPCamXAddress;
                }

                if (ipToScan.UsedScanMethod == ScanMethod.ReverseLookup)
                {
                    string resultHostname = row["Hostname"].ToString().ToUpper();
                    string resultIP = row["IP"].ToString();

                    try
                    {
                        if (!string.IsNullOrEmpty(resultHostname)) row["InternalName"] = _internalNames.InternalNames.Select("Hostname = '" + resultHostname + "'")[0]["InternalName"].ToString();
                    }
                    catch
                    {
                        row["InternalName"] = string.Empty;
                    }

                    try
                    {
                        //check if the IP in the internal names returns the same hostname like the dns server
                        string InternalNames_Hostname_from_ScannedIP = _internalNames.InternalNames.Select("StaticIP = '" + resultIP + "'")[0]["Hostname"].ToString().ToUpper();

                        bool dnsMatched = false;
                        dnsMatched = InternalNames_Hostname_from_ScannedIP == resultHostname;

                        if (dnsMatched && !string.IsNullOrEmpty(resultHostname))
                        {
                            row["MatchedWithInternal"] = Properties.Resources.green_dot;
                        }
                        if (!dnsMatched && !string.IsNullOrEmpty(resultHostname))
                        {
                            row["MatchedWithInternal"] = Properties.Resources.red_dotTB;
                        }
                        if (string.IsNullOrEmpty(resultHostname))
                        {
                            row["MatchedWithInternal"] = null;
                        }
                    }
                    catch (Exception)
                    {

                        row["MatchedWithInternal"] = null;
                    }

                    row["Hostname"] = ipToScan.HostName;
                    row["Aliases"] = string.Join("\r\n", ipToScan.Aliases);
                }

                if (ipToScan.UsedScanMethod == ScanMethod.Lookup)
                {
                    row["LookUpStatus"] = ipToScan.LookUpStatus ? Properties.Resources.green_dot : Properties.Resources.red_dotTB;
                    row["LookUpIPs"] = ipToScan.LookUpIPs;
                }

                if (ipToScan.UsedScanMethod == ScanMethod.TCPPorts)
                {
                    row["TCP_Ports"] = string.Join("\r\n", ports);
                }

                if (ipToScan.UsedScanMethod == ScanMethod.UDPPorts)
                {
                    row["OpenUDP_Ports"] = string.Join("; ", ipToScan.UDP_OpenPorts);
                }

                _scannResults.ResultTable.Rows.Add(row);
            }
        }

        private void ARP_A_newDevive_Finished(object? sender, ScanTask_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                InsertIPToScanResult(e.ipToScan);

                status_ARP_A_Scan = ScanStatus.finished;
                Status();
            });
        }


        private void ScanningMethods_Ping_ProgressUpdated(int arg1, int arg2, int arg3)
        {
            //throw new NotImplementedException();
            Dispatcher.Invoke(() =>
            {
                counted_current_Ping_Scan = arg1;
                counted_responded_Ping_Scan = arg2;
                counted_total_Ping_Scan = arg3;
                Status();
            });
        }

        private void Ping_Task_Finished(object? sender, ScanTask_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                InsertIPToScanResult(e.ipToScan);

                //++counted_current_Ping_Scan;
                //Status();
            });
        }
        private void PingFinished_Event(object? sender, Method_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                status_Ping_Scan = ScanStatus.finished;
                Status();
            });
        }

        private void ScanningMethod_Find_ONVIF_IP_Cameras_ProgressUpdated(int arg1, int arg2, int arg3)
        {
            
            Dispatcher.BeginInvoke(() =>
            {
                counted_responded_ONVIF_IP_Cams = arg2;
                Status();
            });
        }

        private void newIPCameraFound_Task_Finished(object? sender, ScanTask_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                InsertIPToScanResult(e.ipToScan);
                
                //IPCameraScanFinishet = true;
                //Status();
            });
        }

        private void IPCameraScan_Finished(object? sender, Method_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                status_ONVIF_IP_Cam_Scan = e.ScanStatus;
                Status();
            });
        }


        private void SSDP_foundNewDevice(object? sender, ScanTask_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                InsertIPToScanResult(e.ipToScan);
            });
        }

        private void ScanningMethode_SSDP_UPNP_ProgressUpdated(int arg1, int arg2, int arg3)
        {
            //throw new NotImplementedException();

            //throw new NotImplementedException();
            Dispatcher.Invoke(() =>
            {                
                counted_responded_SSDP_device = arg2;
                Status();
            });
        }

        private void SSDP_Scan_Finished(object? sender, Method_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                status_SSDP_Scan = e.ScanStatus;
                Status();
            }));
        }


        private void ScanningMethode_SNMP_SNMBFinished(bool obj)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                status_SNMP_Scan = ScanStatus.finished;
                Status();
            }));
        }

        private void ScanningMethode_SNMP_SNMB_Task_Finished(IPToScan obj)
        {
            Dispatcher.BeginInvoke(() =>
            {
                InsertIPToScanResult(obj);
                Status();
            });
        }

        private void ScanningMethode_SNMP_ProgressUpdated(int arg1, int arg2, int arg3)
        {
            Dispatcher.BeginInvoke(() =>
            {
                counted_current_SNMP_Scan = arg1;
                counted_responded_SNMP_Devices = arg2;
                counted_total_SNMP_Devices = arg3;
                Status();
            });
        }

       


        private void ScanningMethod_SMBVersionCheck_SMB_Scan_Finished()
        {
            //throw new NotImplementedException();
            Dispatcher.BeginInvoke(new Action(() =>
            {
                status_SMB_VersionCheck = ScanStatus.finished;
                Status();
            }));
        }

        private void ScanningMethod_SMB_VersionCheck_ProgressUpdated(int arg1, int arg2, int arg3)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                counted_current_SMB_VersionCheck = arg1;
                counted_responded_SMB_VersionCheck = arg2;
                counted_total_SMB_VersionCheck = arg3;
                Status();
            }));
        }

        private void ScanningMethod_SMB_VersionCheck_SMB_IP_Scan_Finished(IPToScan ipToScan)
        {
            Dispatcher.BeginInvoke(() =>
            {
                if (string.IsNullOrEmpty(ipToScan.IPorHostname))
                {
                    return;
                }
                InsertIPToScanResult(ipToScan);
            });
        }

        private void ScanningMethod_NetBios_NetbiosIPScanFinished(IPToScan ipToScan)
        {
            Dispatcher.BeginInvoke(() =>
            {
                if (string.IsNullOrEmpty(ipToScan.NetBiosHostname))
                {
                    return;
                }
                InsertIPToScanResult(ipToScan);
            });
        }
        private void ScanningMethode_NetBios_ProgressUpdated(int current, int responsed, int total)
        {
            Dispatcher.Invoke(() =>
            {
                counted_current_NetBiosScan = current;
                counted_responded_NetBiosInfos = responsed;
                counted_total_NetBiosInfos = total;
                Status();
            });
            
        }
        private void ScanningMethod_NetBios_NetbiosScanFinished(bool obj)
        {
           

            // Falls die Methode aus einem Hintergrund-Thread kommt, UI-Update über Dispatcher
            Dispatcher.Invoke(() =>
            {
                status_NetBios_Scan = ScanStatus.finished;
                Status(); 
            });
        }


        private void ScanningMethod_Services_ProgressUpdated(int arg1, int arg2, int arg3)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                counted_current_Service_IP_Scan = arg1;
                counted_responded_Services_IP_Scan = arg2;
                counted_total_Services_IP_Scan = arg3;
                Status();
            }));
        }

        private void ScanningMethod_Services_ServiceIPScanFinished(IPToScan ipToScan)
        {
            Dispatcher.BeginInvoke(() =>
            {
                InsertIPToScanResult(ipToScan);
            });
        }

        private void ScanningMethod_Services_ServiceScanFinished()
        {
            Dispatcher.Invoke(() =>
            {
                status_Services_Scan = ScanStatus.finished;
                Status(); 
            });
        }

        private void ScanningMethod_Services_FindServicePortProgressUpdated(int arg1, int arg2, int arg3)
        {
            //throw new NotImplementedException();
            Dispatcher.Invoke(() =>
            {
                lbl_ScanStatus.Content = "DeepScanedPorts: " + arg1.ToString() + " / " + arg2.ToString() + " / " + arg3.ToString();                
            });
        }

        private void ScanningMethod_Services_FindServicePortFinished(IPToScan obj)
        {
            //throw new NotImplementedException();
            Dispatcher.Invoke(() =>
            {                
                InsertIPToScanResult(obj);
                lbl_ScanStatus.Content = "find service port finished.";
            });
        }



        private void ScanningMethode_ARP_ProgressUpdated(int arg1, int arg2, int arg3)
        {
            //throw new NotImplementedException();
            Dispatcher.Invoke(() => 
            {
                counted_total_ARP_Requests = arg3;
                Status();
            });
        }


        private void ARP_Request_Task_Finished(object? sender, ScanTask_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                ++counted_current_ARP_Requests;
                Status();

                if (string.IsNullOrEmpty(e.ipToScan.IPorHostname))
                {
                    return;
                }

                InsertIPToScanResult(e.ipToScan);

                ++counted_responded_ARP_Requests;
                Status();
            });
        }
        private void ARP_Request_Finished(object? sender, Method_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                status_ARP_Request_Scan = ScanStatus.finished;
                Status();
            });
        }



        private void DNS_GetHostAliases_Task_Finished(object? sender, ScanTask_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                ++counted_current_DNS_HostNames;
                Status();

                if (e == null || string.IsNullOrEmpty(e.ipToScan.HostName))
                {
                    return;
                }

                InsertIPToScanResult(e.ipToScan);

                ++counted_responded_DNS_HostNames;
                Status();
            });
        }
        private void DNS_GetHostAndAliasFromIP_Finished(object? sender, Method_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                status_DNS_HostName_Scan = ScanStatus.finished;
                Status();
            });
        }



        private void Lookup_Task_Finished(object? sender, ScanTask_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                ++counted_current_Lookup_Scan;
                Status();


                InsertIPToScanResult(e.ipToScan);


                ++counted_responded_Lookup_Devices;
                Status();
            });
        }
        private void Lookup_Finished(object? sender, Method_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                status_Lookup_Scan = ScanStatus.finished;
                Status();
            });
        }



        private void TcpPortScan_Task_Finished(object? sender, ScanTask_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                ++counted_current_TCP_Port_Scan;
                Status();

                if (e == null)
                {
                    return;
                }


                InsertIPToScanResult(e.ipToScan);


                ++counted_responded_TCP_Port_Scan_Devices;
                Status();
            });
        }
        private void TcpPortScan_Finished(object? sender, Method_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                status_TCP_Port_Scan = ScanStatus.finished;
                Status();
            });
        }



        private void UDPPortScan_Task_Finished(object? sender, ScanTask_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                InsertIPToScanResult(e.ipToScan);

                ++counted_current_UDP_Port_Scan;
                Status();
            });
        }
        private void UDPPortScan_Finished(object? sender, Method_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                status_UDP_Port_Scan = ScanStatus.finished;
                //Counted_UDPListener = e.UDPListener;
                Status();
            });
        }

        private void slider_TimeOut_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
        {
            _TimeOut = (int)slider_TimeOut.Value;
        }



        private void bt_Edit_IP_Range_Click(object sender, RoutedEventArgs e)
        {
            ManageIPGroups groups = new ManageIPGroups(ipGroupData.IPGroupsDT, _ipGroupsXML);
            groups.ShowDialog();
        }

        private void chk_ARP_DeleteCacheBefore_Click(object sender, RoutedEventArgs e)
        {
            if ((bool)chk_ARP_DeleteCacheBefore.IsChecked)
            {

                if (!supportMethods.IsAdministrator())
                {
                    chk_ARP_DeleteCacheBefore.IsChecked = false;
                    MessageBox.Show("you need admin right");
                }
            }
        }

        private void bt_clearScanResultTable_Click(object sender, RoutedEventArgs e)
        {
            _scannResults.ResultTable.Rows.Clear();
        }

        private void Window_Closing(object sender, CancelEventArgs e)
        {
            SaveServiceScanSettings();
            if ((bool)chk_SaveLastScanResult.IsChecked)
            {
                foreach (DataRow row in _scannResults.ResultTable.Rows)
                {
                    //if (!string.IsNullOrEmpty(row["SSDPStatus"].ToString())) row["SSDPStatus"] = Properties.Resources.gray_dotTB;
                    if (!string.IsNullOrEmpty(row["ARPStatus"].ToString())) row["ARPStatus"] = Properties.Resources.gray_dotTB;
                    if (!string.IsNullOrEmpty(row["PingStatus"].ToString())) row["PingStatus"] = Properties.Resources.gray_dotTB;
                    //if (!string.IsNullOrEmpty(row["IsIPCam"].ToString())) row["IsIPCam"] = Properties.Resources.gray_dotTB;

                    //if (!string.IsNullOrEmpty(row["LookUpStatus"].ToString()))
                    //{
                    //    byte[] greenDot = Properties.Resources.green_dot;
                    //    byte[] cellValue = (byte[])row["LookUpStatus"];
                    //    bool bla = greenDot.SequenceEqual(cellValue);
                    //    if (bla) row["LookUpStatus"] = Properties.Resources.gray_dotTB;
                    //}
                }
                _scannResults.ResultTable.WriteXml(_lastScanResultXML, XmlWriteMode.WriteSchema);
            }
        }

        private void bt_SavePortsToScan_Click(object sender, RoutedEventArgs e)
        {
            DataView dv = _portCollection.TableOfPortsToScan.DefaultView;
            dv.Sort = "Ports asc";
            DataTable sortedtable1 = dv.ToTable();
            sortedtable1.WriteXml(_portsToScanXML, XmlWriteMode.WriteSchema);
        }

       


        private async void Filter_ScanResults_Explicite()
        {
            //// Lese UI-Daten vorab aus (UI-Thread)
            //string ipFilter = tb_Filter_IP.Text.Trim();
            //string internalName = tb_Filter_InternalName.Text.Trim();
            //string hostName = tb_Filter_HostName.Text.Trim();
            //string tcpPort = tb_Filter_TCPPort.Text.Trim();
            //string mac = tb_Filter_Mac.Text.Trim();
            //string vendor = tb_Filter_Vendor.Text.Trim();
            //bool isIPCamChecked = chk_Filter_IsIPCam.IsChecked ?? false;

            //await Task.Run(() =>
            //{
            //    // StringBuilder für bessere Performance
            //    StringBuilder whereFilter = new StringBuilder(200);
            //    whereFilter.Append("1 = 1");

            //    // IP-Filter mit Wildcard-Handling
            //    if (!string.IsNullOrEmpty(ipFilter))
            //    {
            //        if (ipFilter.Contains("*"))
            //            ipFilter = ipFilter.Replace("*", "%"); // '*' durch '%' ersetzen
            //        else
            //            ipFilter = ipFilter; // Exakte Suche

            //        whereFilter.AppendFormat(" and IP LIKE '{0}'", ipFilter);
            //    }

            //    if (!string.IsNullOrEmpty(internalName))
            //        whereFilter.AppendFormat(" and InternalName LIKE '%{0}%'", internalName);

            //    if (!string.IsNullOrEmpty(hostName))
            //        whereFilter.AppendFormat(" and Hostname LIKE '%{0}%'", hostName);

            //    if (!string.IsNullOrEmpty(tcpPort))
            //        whereFilter.AppendFormat(" and TCP_Ports LIKE '%{0}%'", tcpPort);

            //    if (!string.IsNullOrEmpty(mac))
            //        whereFilter.AppendFormat(" and Mac LIKE '%{0}%'", mac);

            //    if (!string.IsNullOrEmpty(vendor))
            //        whereFilter.AppendFormat(" and Vendor LIKE '%{0}%'", vendor);

            //    if (isIPCamChecked)
            //        whereFilter.Append(" and IsIPCam is not null");

            //    // Falls keine Filterbedingungen gesetzt sind, Filter zurücksetzen
            //    string finalFilter = whereFilter.ToString();
            //    if (finalFilter == "1 = 1")
            //        finalFilter = "";

            //    // Prüfen, ob der Filter sich geändert hat (Performance-Optimierung)
            //    if (dv_resultTable.RowFilter != finalFilter)
            //    {
            //        Dispatcher.Invoke(() =>
            //        {
            //            try
            //            {
            //                dv_resultTable.RowFilter = finalFilter;
            //            }
            //            catch (Exception ex)
            //            {
            //                //MessageBox.Show(ex.Message);
            //            }
            //        });
            //    }
            //});



            // Lese UI-Daten vorab aus (UI-Thread)
            string allFilter = tb_Filter_All1.Text.Trim();
            string allFilter2 = tb_Filter_All2.Text.Trim();
            string ipFilter = tb_Filter_IP.Text.Trim();
            string internalName = tb_Filter_InternalName.Text.Trim();
            string hostName = tb_Filter_HostName.Text.Trim();
            string tcpPort = tb_Filter_TCPPort.Text.Trim();
            string mac = tb_Filter_Mac.Text.Trim();
            string vendor = tb_Filter_Vendor.Text.Trim();
            bool isIPCamChecked = chk_Filter_IsIPCam.IsChecked ?? false;
            bool isSSDP_UPnP_Checked = chk_Filter_IsSSDP.IsChecked ?? false;
            bool supportSMB_Checked = chk_Filter_SupportSMB.IsChecked ?? false;
            bool supportSNMP_Checked = chk_Filter_SupportSNMP.IsChecked ?? false;
            bool supportNETBIOS_Checked = chk_Filter_SupportNetBios.IsChecked ?? false;

            await Task.Run(() =>
            {
                // StringBuilder für bessere Performance
                StringBuilder whereFilter = new StringBuilder(200);
                whereFilter.Append("1 = 1");



                if (!string.IsNullOrEmpty(allFilter) || !string.IsNullOrEmpty(allFilter2))
                {
                    if (allFilter.Contains("*"))
                        allFilter = allFilter.Replace("*", "%"); // '*' durch '%' ersetzen

                    if (allFilter2.Contains("*"))
                        allFilter2 = allFilter2.Replace("*", "%"); // '*' durch '%' ersetzen

                    List<string> columnConditions = new List<string>();  // Bedingungen für `allFilter`
                    List<string> columnConditions2 = new List<string>(); // Bedingungen für `allFilter2`
                    List<string> combinedConditions = new List<string>(); // Bedingungen für beide gleichzeitig

                    foreach (DataColumn column in dv_resultTable.Table.Columns)
                    {
                        if (column.DataType == typeof(string)) // Nur `string`-Spalten durchsuchen
                        {
                            if (!string.IsNullOrEmpty(allFilter))
                                columnConditions.Add($"{column.ColumnName} LIKE '%{allFilter}%'");

                            if (!string.IsNullOrEmpty(allFilter2))
                                columnConditions2.Add($"{column.ColumnName} LIKE '%{allFilter2}%'");

                            // Wenn beide Suchbegriffe vorhanden sind, müssen sie in einer Spalte vorkommen
                            if (!string.IsNullOrEmpty(allFilter) && !string.IsNullOrEmpty(allFilter2))
                                combinedConditions.Add($"{column.ColumnName} LIKE '%{allFilter}%' AND {column.ColumnName} LIKE '%{allFilter2}%'");
                        }
                    }

                    // **Filter zusammensetzen**
                    if (!string.IsNullOrEmpty(allFilter) && !string.IsNullOrEmpty(allFilter2))
                    {
                        // **Wenn beide Filter vorhanden sind, dann nur Treffer mit beiden Werten in einer Spalte**
                        whereFilter.Append($" AND ({string.Join(" OR ", combinedConditions)})");
                    }
                    else if (!string.IsNullOrEmpty(allFilter))
                    {
                        // **Nur `allFilter` vorhanden → Normaler Filter**
                        whereFilter.Append($" AND ({string.Join(" OR ", columnConditions)})");
                    }
                    else if (!string.IsNullOrEmpty(allFilter2))
                    {
                        // **Nur `allFilter2` vorhanden → Normaler Filter**
                        whereFilter.Append($" AND ({string.Join(" OR ", columnConditions2)})");
                    }
                }



                // **Spezifische Filter anwenden**
                if (!string.IsNullOrEmpty(ipFilter))
                {
                    if (ipFilter.Contains("*"))
                        ipFilter = ipFilter.Replace("*", "%");
                    whereFilter.AppendFormat(" and IP LIKE '{0}'", ipFilter);
                }

                if (!string.IsNullOrEmpty(internalName))
                    whereFilter.AppendFormat(" and InternalName LIKE '%{0}%'", internalName);

                if (!string.IsNullOrEmpty(hostName))
                    whereFilter.AppendFormat(" and Hostname LIKE '%{0}%'", hostName);

                if (!string.IsNullOrEmpty(tcpPort))
                    whereFilter.AppendFormat(" and TCP_Ports LIKE '%{0}%'", tcpPort);

                if (!string.IsNullOrEmpty(mac))
                    whereFilter.AppendFormat(" and Mac LIKE '%{0}%'", mac);

                if (!string.IsNullOrEmpty(vendor))
                    whereFilter.AppendFormat(" and Vendor LIKE '%{0}%'", vendor);

                if (isIPCamChecked)
                    whereFilter.Append(" and IsIPCam is not null");

                if (isSSDP_UPnP_Checked)
                    whereFilter.Append(" and SSDPStatus is not null");

                if (supportSMB_Checked)
                    whereFilter.Append(" and detectedSMBVersions is not null");

                if (supportSNMP_Checked)
                    whereFilter.Append(" and SNMPSysName is not null");

                if (supportNETBIOS_Checked)
                    whereFilter.Append(" and NetBiosHostname is not null");

                // Falls keine Filterbedingungen gesetzt sind, Filter zurücksetzen
                string finalFilter = whereFilter.ToString();
                if (finalFilter == "1 = 1")
                    finalFilter = "";

                // Prüfen, ob der Filter sich geändert hat (Performance-Optimierung)
                if (dv_resultTable.RowFilter != finalFilter)
                {
                    Dispatcher.Invoke(() =>
                    {
                        try
                        {
                            dv_resultTable.RowFilter = finalFilter;
                        }
                        catch (Exception ex)
                        {
                            // MessageBox.Show(ex.Message);
                        }
                    });
                }
            });
        }



















        private void Filter_ScanResults_Explicite(object sender, RoutedEventArgs e)
        {
            Filter_ScanResults_Explicite();
        }

        private void dgv_Results_Sorting(object sender, DataGridSortingEventArgs e)
        {
            if (e.Column.Header.ToString() == "IP")
            {
                if (e.Column.SortDirection == null || e.Column.SortDirection == ListSortDirection.Descending)
                {
                    e.Handled = true;
                    e.Column.SortDirection = ListSortDirection.Ascending;
                    dv_resultTable.Sort = "IPGroupDescription asc, DeviceDescription asc, IPToSort asc";

                    //dgv_Results.Columns[6].SortDirection = ListSortDirection.Ascending;
                }
                else
                {
                    e.Handled = true;
                    e.Column.SortDirection = ListSortDirection.Descending;
                    dv_resultTable.Sort = "IPGroupDescription asc, DeviceDescription asc, IPToSort desc";
                }
            }
        }

        private void chk_IPRanges_groupDevices_Click(object sender, RoutedEventArgs e)
        {
            if ((bool)chk_IPRanges_groupDevices.IsChecked)
            {
                cvTasks_IP_Ranges.GroupDescriptions.Add(new PropertyGroupDescription("DeviceDescription"));
            }
            else
            {
                var itemToRemove = cvTasks_IP_Ranges.GroupDescriptions.OfType<PropertyGroupDescription>().FirstOrDefault(pgd => pgd.PropertyName == "DeviceDescription");
                cvTasks_IP_Ranges.GroupDescriptions.Remove(itemToRemove);
            }
        }

        private void chk_ScanResults_groupDevices_Click(object sender, RoutedEventArgs e)
        {
            if ((bool)chk_ScanResults_groupDevices.IsChecked)
            {
                cvTasks_scanResults.GroupDescriptions.Add(new PropertyGroupDescription("DeviceDescription"));
            }
            else
            {
                var itemToRemove = cvTasks_scanResults.GroupDescriptions.OfType<PropertyGroupDescription>().FirstOrDefault(pgd => pgd.PropertyName == "DeviceDescription");
                cvTasks_scanResults.GroupDescriptions.Remove(itemToRemove);
            }
        }

        private void bt_StartScanFromNIC_Click(object sender, RoutedEventArgs e)
        {
            _IPsToScan.Clear();

            List<int> TCPPorts = new List<int>();

            if ((bool)chk_Methodes_ScanTCPPorts.IsChecked && !(bool)chk_allTCPPorts.IsChecked)
            {
                TCPPorts.AddRange(_portCollection.TCPPorts);

                //Additional Ports from Customer
                if (!string.IsNullOrEmpty(tb_TCPPorts.Text))
                {
                    TCPPorts.AddRange(tb_TCPPorts.Text.Split(',')?.Select(Int32.Parse)?.ToList());
                }
            }

            if ((bool)chk_Methodes_ScanTCPPorts.IsChecked && (bool)chk_allTCPPorts.IsChecked)
            {
                TCPPorts.AddRange(Enumerable.Range(1, 65536));
            }

            IpRanges.IPRange range = new IpRanges.IPRange(tb_Adapter_FirstSubnetIP.Text, tb_Adapter_LastSubnetIP.Text);

            foreach (var item in range.GetAllIP())
            {
                IPToScan toScan = new IPToScan();
                toScan.IPGroupDescription = "NetworkInterface";
                toScan.DeviceDescription = "NIC: " + cb_NetworkAdapters.SelectedItem.ToString();
                toScan.IPorHostname = item.ToString();
                toScan.TCPPortsToScan = TCPPorts;
                toScan.TimeOut = _TimeOut;

                _IPsToScan.Add(toScan);
            }

            DoWork(false);
        }

        private static readonly CultureInfo GermanCulture = CultureInfo.GetCultureInfo("de-DE");


        private void cb_NetworkAdapters_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (cb_NetworkAdapters.SelectedItem == null)
                return;

            string selectedNicName = cb_NetworkAdapters.SelectedItem.ToString();
            NicInfo n = nicInfos.FirstOrDefault(nic => nic.NicName == selectedNicName);

            if (n != null)
            {
                TextChangedByComboBox = true;

                tb_AdapterIP.Text = n.IPv4;
                tb_AdapterSubnetMask.Text = n.IPv4Mask;
                tb_Adapter_FirstSubnetIP.Text = n.FirstSubnetIP;
                tb_Adapter_LastSubnetIP.Text = n.LastSubnetIP;
                lb_IPsToScan.Content = n.IPsCount.ToString("n0", GermanCulture);  // Wiederverwendete CultureInfo

                SelectedNetworkInterfaceInfos.Name = selectedNicName;
                SelectedNetworkInterfaceInfos.IPv4 = !string.IsNullOrEmpty(n.IPv4) ? IPAddress.Parse(n.IPv4) : null;

                TextChangedByComboBox = false;
            }
        }

        private void tb_Adapter_FirstSubnetIP_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (TextChangedByComboBox) return;

            try
            {
                lb_IPsToScan.Content = "calc. number of IPs";
                lb_IPsToScan.Content = new IpRanges.IPRange().NumberOfIPsInRange(tb_Adapter_FirstSubnetIP.Text, tb_Adapter_LastSubnetIP.Text).ToString("n0", CultureInfo.GetCultureInfo("de-DE"));
            }
            catch (Exception)
            {

                lb_IPsToScan.Content = "...";
            }
        }
        private void tb_Adapter_LastSubnetIP_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (TextChangedByComboBox) return;

            try
            {
                lb_IPsToScan.Content = "calc. number of IPs";
                lb_IPsToScan.Content = new IpRanges.IPRange().NumberOfIPsInRange(tb_Adapter_FirstSubnetIP.Text, tb_Adapter_LastSubnetIP.Text).ToString("n0", CultureInfo.GetCultureInfo("de-DE"));
            }
            catch (Exception)
            {

                lb_IPsToScan.Content = "...";
            }
        }

        private void bt_SaveNames_Click(object sender, RoutedEventArgs e)
        {
            DataView dv = _internalNames.InternalNames.DefaultView;
            dv.Sort = "Hostname asc";
            DataTable sortedtable1 = dv.ToTable();
            sortedtable1.WriteXml(_InternalNamesXML, XmlWriteMode.WriteSchema);
        }

        private void dg_InternalNames_ContextMenu_Click(object sender, RoutedEventArgs e)
        {
            string str_Clipboard = Clipboard.GetText();

            DataGridCellInfo cell = dg_InternalNames.CurrentCell;
            int columnindex = cell.Column.DisplayIndex;
            int rowIndex = dg_InternalNames.Items.IndexOf(cell.Item);



            foreach (string row in str_Clipboard.Split("\r\n"))
            {
                if (rowIndex < _internalNames.InternalNames.Rows.Count)
                {
                    if (string.IsNullOrEmpty(row)) continue;

                    List<string> cells = row.Split("\t").ToList();
                    int cellCount = cells.Count > 4 ? 4 : cells.Count;

                    int currentCell = 0;


                    for (int i = columnindex; i < 4; i++)
                    {
                        if (currentCell >= cells.Count) break;

                        _internalNames.InternalNames.Rows[rowIndex][i] = cells[currentCell];
                        currentCell++;
                    }
                }
                else
                {
                    if (string.IsNullOrEmpty(row)) continue;

                    List<string> cells = row.Split("\t").ToList();
                    int cellCount = cells.Count > 4 ? 4 : cells.Count;

                    int currentCell = 0;
                    DataRow datarow = _internalNames.InternalNames.NewRow();

                    for (int i = columnindex; i < 4; i++)
                    {
                        if (currentCell >= cells.Count) break;

                        datarow[i] = cells[currentCell];
                        currentCell++;
                    }
                    _internalNames.InternalNames.Rows.Add(datarow);
                }
                rowIndex++;
            }
        }

        private void bt_AddInternalNamesToScanResult_Click(object sender, RoutedEventArgs e)
        {
            foreach (DataRow row in _scannResults.ResultTable.Rows)
            {
                string resultHostname = row["Hostname"].ToString().ToUpper();
                string resultIP = row["IP"].ToString();

                try
                {
                    if (!string.IsNullOrEmpty(resultHostname)) row["InternalName"] = _internalNames.InternalNames.Select("Hostname = '" + resultHostname + "'")[0]["InternalName"].ToString();
                }
                catch
                {
                    row["InternalName"] = string.Empty;
                }

                try
                {
                    //check if the IP in the internal names returns the same hostname like the dns server
                    string InternalNames_Hostname_from_ScannedIP = _internalNames.InternalNames.Select("StaticIP = '" + resultIP + "'")[0]["Hostname"].ToString().ToUpper();

                    bool dnsMatched = false;
                    dnsMatched = InternalNames_Hostname_from_ScannedIP == resultHostname;

                    if (dnsMatched && !string.IsNullOrEmpty(resultHostname))
                    {
                        row["MatchedWithInternal"] = Properties.Resources.green_dot;
                    }
                    if (!dnsMatched && !string.IsNullOrEmpty(resultHostname))
                    {
                        row["MatchedWithInternal"] = Properties.Resources.red_dotTB;
                    }
                    if (string.IsNullOrEmpty(resultHostname))
                    {
                        row["MatchedWithInternal"] = null;
                    }
                }
                catch (Exception)
                {

                    row["MatchedWithInternal"] = null;
                }
            }
        }

        private void bt_openApplicationFolder_Click(object sender, RoutedEventArgs e)
        {
            string applicationFolder = AppDomain.CurrentDomain.BaseDirectory;
            if (Directory.Exists(applicationFolder))
            {
                ProcessStartInfo startInfo = new ProcessStartInfo("explorer.exe", applicationFolder);
                Process.Start(startInfo);
            }
        }

        private void bt_openSettingsFolder_Click(object sender, RoutedEventArgs e)
        {
            string settingsFolder = Path.Combine(Path.Combine(Environment.ExpandEnvironmentVariables("%userprofile%"), "Documents"), @"MyNetworkMonitor\Settings");
            if (Directory.Exists(settingsFolder))
            {
                ProcessStartInfo startInfo = new ProcessStartInfo("explorer.exe", settingsFolder);
                Process.Start(startInfo);
            }
        }

        private void tb_InternalNamesFilter_TextChanged(object sender, TextChangedEventArgs e)
        {
            string whereFilter = "1 = 1";

            if (tb_InternalNamesFilter.Text.Length > 0) whereFilter += " and InternalName Like '%" + tb_InternalNamesFilter.Text + "%'";
            if (tb_InternalNamesFilter.Text.Length > 0) whereFilter += " or Hostname Like '%" + tb_InternalNamesFilter.Text + "%'";
            if (tb_InternalNamesFilter.Text.Length > 0) whereFilter += " or MAC Like '%" + tb_InternalNamesFilter.Text + "%'";
            if (tb_InternalNamesFilter.Text.Length > 0) whereFilter += " or StaticIP Like '%" + tb_InternalNamesFilter.Text + "%'";

            dv_InternalNames.RowFilter = string.Format(whereFilter);
        }

        private void dgv_Results_LoadingRow(object sender, DataGridRowEventArgs e)
        {
            int ipIndex = dgv_Results.Columns.Single(c => c.Header.ToString() == "IP").DisplayIndex;
            int internalNameIndex = dgv_Results.Columns.Single(c => c.Header.ToString() == "InternalName").DisplayIndex;
            int hostnameIndex = dgv_Results.Columns.Single(c => c.Header.ToString() == "Hostname").DisplayIndex;
            int macIndex = dgv_Results.Columns.Single(c => c.Header.ToString() == "Mac").DisplayIndex;

            try
            {
                if (dgv_Results.Items.Count >= 0)
                {
                    var row = e.Row.Item as DataRowView;

                    string rowIP = row[ipIndex].ToString();
                    string rowInternalName = row[internalNameIndex].ToString();
                    string rowHostname = row[hostnameIndex].ToString();
                    string rowMAC = row[macIndex].ToString();

                    int countedDupInternalNames = _scannResults.ResultTable.Select("InternalName = '" + rowInternalName + "'").Length;
                    if (countedDupInternalNames > 1)
                    {
                        if (!string.IsNullOrEmpty(rowInternalName)) e.Row.Background = Brushes.LightGreen;
                    }

                    int countedDupIPs = _scannResults.ResultTable.Select("IP = '" + rowIP + "'").Length;
                    if (countedDupIPs > 1)
                    {
                        e.Row.Background = Brushes.Orange;
                    }

                    int countedDupHostnames = _scannResults.ResultTable.Select("Hostname = '" + rowHostname + "'").Length;
                    if (countedDupHostnames > 1)
                    {
                        if (!string.IsNullOrEmpty(rowHostname))
                        {
                            e.Row.Background = Brushes.DarkOrange;
                        }
                    }

                    int countedDupMac = _scannResults.ResultTable.Select("Mac = '" + rowMAC + "'").Length;
                    if (countedDupMac > 1)
                    {
                        e.Row.Background = (Brush)new BrushConverter().ConvertFromString("#FFC73D3D");
                        e.Row.Foreground = Brushes.WhiteSmoke;                        
                    }
                }
            }
            catch { }
        }
      
        private void dg_InternalNames_LoadingRow(object sender, DataGridRowEventArgs e)
        {
            int internalNameIndex = dg_InternalNames.Columns.Single(c => c.Header.ToString() == "InternalName").DisplayIndex;
            int hostnameIndex = dg_InternalNames.Columns.Single(c => c.Header.ToString() == "Hostname").DisplayIndex;
            int macIndex = dg_InternalNames.Columns.Single(c => c.Header.ToString() == "MAC").DisplayIndex;
            int staticIpIndex = dg_InternalNames.Columns.Single(c => c.Header.ToString() == "StaticIP").DisplayIndex;

            try
            {
                if (dg_InternalNames.Items.Count >= 0)
                {
                    var row = e.Row.Item as DataRowView;

                    if (row == null) { return; }

                    string rowInternalName = row[internalNameIndex].ToString();
                    string rowHostname = row[hostnameIndex].ToString();
                    string rowMAC = row[macIndex].ToString();
                    string rowStaticIP = row[staticIpIndex].ToString();

                    int countedDupInternalNames = _internalNames.InternalNames.Select("InternalName = '" + rowInternalName + "'").Length;
                    if (countedDupInternalNames > 1)
                    {
                        if (!string.IsNullOrEmpty(rowInternalName)) e.Row.Background = Brushes.LightGreen;
                    }

                    var bla = _internalNames.InternalNames.Select("StaticIP = '" + rowStaticIP + "'");
                    int countedDupIPs = _internalNames.InternalNames.Select("StaticIP = '" + rowStaticIP + "'").Length;
                    if (countedDupIPs > 1)
                    {
                        if (!string.IsNullOrEmpty(rowStaticIP))
                        {
                            e.Row.Background = Brushes.Yellow;
                        }
                    }

                    int countedDupHostnames = _internalNames.InternalNames.Select("Hostname = '" + rowHostname + "'").Length;
                    if (countedDupHostnames > 1)
                    {
                        if (!string.IsNullOrEmpty(rowHostname))
                        {
                            e.Row.Background = Brushes.DarkOrange;
                        }
                    }

                    int countedDupMac = _internalNames.InternalNames.Select("MAC = '" + rowMAC + "'").Length;
                    if (countedDupMac > 1)
                    {
                        if (!string.IsNullOrEmpty(rowMAC)) e.Row.Background = Brushes.Red;
                    }
                }
            }
            catch { }
        }

        private void dgv_Results_CellEditEnding(object sender, DataGridCellEditEndingEventArgs e)
        {
            if (e.EditAction == DataGridEditAction.Commit)
            {
                //dgv_Results.Dispatcher.BeginInvoke(new Action(() => dgv_Results.Items.Refresh()), System.Windows.Threading.DispatcherPriority.Background);
                dgv_Results.Dispatcher.BeginInvoke(new Action(() =>
                {
                    if (!dgv_Results.CommitEdit(DataGridEditingUnit.Row, true)) // CommitEdit gibt false zurück, wenn ein Bearbeitungsmodus aktiv ist
                    {
                        return; // Abbrechen, falls noch eine Bearbeitung läuft
                    }

                    dgv_Results.Items.Refresh();
                }), System.Windows.Threading.DispatcherPriority.Background);
            }
         }

        private void dg_InternalNames_CellEditEnding(object sender, DataGridCellEditEndingEventArgs e)
        {
            if (e.EditAction == DataGridEditAction.Commit)
            {
                dg_InternalNames.Dispatcher.BeginInvoke(new Action(() => dg_InternalNames.Items.Refresh()), System.Windows.Threading.DispatcherPriority.Background);
            }
        }

        private void dg_InternalNames_Scroll(object sender, RoutedEventArgs e)
        {
            ScrollEventArgs scrollEvent = e as ScrollEventArgs;
            if (scrollEvent != null)
            {
                if (scrollEvent.ScrollEventType == ScrollEventType.EndScroll)
                {
                    isScrolling = false;
                }
                else
                {
                    isScrolling = true;
                    dg_InternalNames.Dispatcher.BeginInvoke(new Action(() => dg_InternalNames.Items.Refresh()), System.Windows.Threading.DispatcherPriority.Background);                    
                }
            }
        }

        bool isScrolling = false;
        private void dgv_Results_Scroll(object sender, RoutedEventArgs e)
        {
            ScrollEventArgs scrollEvent = e as ScrollEventArgs;
            if (scrollEvent != null && !isScrolling)
            {
                if (scrollEvent.ScrollEventType == ScrollEventType.EndScroll)
                {
                    isScrolling = false;                    
                }
                else
                {
                    isScrolling = true;
                    dgv_Results.Dispatcher.BeginInvoke(new Action(() => dgv_Results.Items.Refresh()), System.Windows.Threading.DispatcherPriority.Background);                    
                }
            }
        }

        //private void bt_exportResult_Click(object sender, RoutedEventArgs e)
        //{
        //    // Frage den Benutzer, ob alle Zeilen oder nur die ausgewählten Zeilen exportiert werden sollen
        //    MessageBoxResult result = MessageBox.Show("Möchten Sie alle Zeilen exportieren? \r\n Für nur Selektierte Zeilen bitte \"Nein\" wählen", "Exportoptionen", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);

        //    if (result == MessageBoxResult.Cancel)
        //    {
        //        return; // Abbrechen
        //    }
        //    int exportedLines = 0;
        //    bool exportAllRows = (result == MessageBoxResult.Yes);

        //    // Hole die DataView aus der ItemsSource des DataGrids
        //    DataView dataView = dgv_Results.ItemsSource as DataView;
        //    if (dataView == null) return;

        //    // Erstelle einen StringBuilder für den CSV-Inhalt
        //    StringBuilder csvContent = new StringBuilder();

        //    // Füge die Header hinzu
        //    foreach (DataColumn column in dataView.Table.Columns)
        //    {
        //        csvContent.Append(column.ColumnName + ";");
        //    }
        //    csvContent.AppendLine();

        //    // Füge die Zeilen hinzu
        //    if (exportAllRows)
        //    {
        //        // Exportiere alle Zeilen
        //        foreach (DataRow row in dataView.Table.Rows)
        //        {
        //            ++exportedLines;
        //            foreach (var item in row.ItemArray)
        //            {
        //                csvContent.Append(item?.ToString() + ";");
        //            }
        //            csvContent.AppendLine();                    
        //        }
        //    }
        //    else
        //    {
        //        // Exportiere nur die ausgewählten Zeilen
        //        // Exportiere nur die Zeilen, die markierte Zellen enthalten
        //        HashSet<DataRowView> rowsToExport = new HashSet<DataRowView>();

        //        foreach (var selectedCell in dgv_Results.SelectedCells)
        //        {
        //            if (selectedCell.Item is DataRowView dataRowView)
        //            {
        //                rowsToExport.Add(dataRowView);
        //            }
        //        }

        //        foreach (var rowView in rowsToExport)
        //        {
        //            ++exportedLines;
        //            foreach (var item in rowView.Row.ItemArray)
        //            {
        //                csvContent.Append(item?.ToString() + ";");
        //            }
        //            csvContent.AppendLine();
        //        }
        //    }

        //    // Zeige den Speichern-Dialog an
        //    SaveFileDialog saveFileDialog = new SaveFileDialog
        //    {
        //        Filter = "CSV files (*.csv)|*.csv",
        //        DefaultExt = "csv",
        //        FileName = "Export.csv",
        //        InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
        //    };

        //    if (saveFileDialog.ShowDialog() == true)
        //    {
        //        // Speichere die CSV-Datei
        //        File.WriteAllText(saveFileDialog.FileName, csvContent.ToString(), Encoding.UTF8);
        //    }
        //    MessageBox.Show(exportedLines + " wurden exportiert");
        //}









        private void bt_exportResult_Click(object sender, RoutedEventArgs e)
        {
            // Frage den Benutzer, ob alle Zeilen oder nur die ausgewählten Zeilen exportiert werden sollen
            MessageBoxResult result = MessageBox.Show(
                "Möchten Sie alle Zeilen exportieren? \r\n Für nur selektierte Zeilen bitte \"Nein\" wählen",
                "Exportoptionen", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);

            if (result == MessageBoxResult.Cancel)
            {
                return; // Abbrechen
            }
            bool exportAllRows = (result == MessageBoxResult.Yes);

            // Neue DataTable zur unabhängigen Speicherung der Daten
            DataTable independentTable = new DataTable();
            DataView dataView = dgv_Results.ItemsSource as DataView;

            if (dataView != null && dataView.Table != null)
            {
                independentTable = dataView.Table.Copy(); // Kopiert alle Daten vollständig
            }
            else
            {
                MessageBox.Show("Fehler: Die DataView oder DataTable ist NULL.");
                return;
            }

            // HashSet zur Speicherung der zu exportierenden Zeilen
            HashSet<DataRow> rowsToExport = new HashSet<DataRow>();

            if (exportAllRows) // Falls "Ja" gewählt wurde, alle Zeilen exportieren
            {
                foreach (DataRow row in independentTable.Rows)
                {
                    rowsToExport.Add(row);
                }
            }
            else // Falls "Nein" gewählt wurde, nur die selektierten Zeilen exportieren
            {
                foreach (var selectedCell in dgv_Results.SelectedCells)
                {
                    if (selectedCell.Item is DataRowView dataRowView)
                    {
                        DataRow row = dataRowView.Row;
                        rowsToExport.Add(row);
                    }
                }
            }

            // Falls keine Zeilen zum Exportieren vorhanden sind, abbrechen
            if (rowsToExport.Count == 0)
            {
                MessageBox.Show("Keine Zeilen zum Exportieren ausgewählt.");
                return;
            }

            // Neue DataTable für die erweiterten Daten mit aufgeteilten Services
            DataTable expandedDataTable = independentTable.Clone(); // Erstellt eine Kopie der Struktur

            // Füge die neuen Spalten für Services, Ports, Status und die Hilfsspalte originRow hinzu
            expandedDataTable.Columns.Add("Services", typeof(string));
            expandedDataTable.Columns.Add("Ports", typeof(string));
            expandedDataTable.Columns.Add("Status", typeof(string));
            expandedDataTable.Columns.Add("isSSDP", typeof(string));
            expandedDataTable.Columns.Add("isAnIPCam", typeof(string));
            expandedDataTable.Columns.Add("LookupEqualReverse", typeof(string));
            //expandedDataTable.Columns.Add("originRow", typeof(int)); // Hilfsspalte zur Nachverfolgung

            foreach (DataRow originalRow in rowsToExport)
            {
                string lastService = ""; // Speichert den letzten bekannten Service-Namen

                foreach (string line in (originalRow["detectedServicePorts"] as string)?.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries) ?? new string[0])
                {
                    // Splitt line into service, ports und status
                    string[] parts = line.Split(new[] { '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    string service = parts.Length > 0 ? parts[0].Trim(':').Replace(":", string.Empty) : "";
                    string port = parts.Length > 1 ? parts[1].Trim() : "";
                    string status = parts.Length > 2 ? parts[2].Trim('(', ')') : "";

                    // Falls die aktuelle Zeile keinen Service-Namen enthält, aber einen Port hat, Service wiederverwenden
                    if (string.IsNullOrWhiteSpace(service) && !string.IsNullOrWhiteSpace(port))
                    {
                        service = lastService;
                    }
                    else
                    {
                        lastService = service; // Speichert den aktuellen Service für die nächste Zeile
                    }

                    //int originRow = independentTable.Rows.IndexOf(originalRow); // Ursprüngliche Zeilennummer

                    // Erstelle eine neue Zeile für expandedDataTable
                    DataRow newRow = expandedDataTable.NewRow();

                    // Kopiere alle Spaltenwerte außer detectedServicePorts
                    foreach (DataColumn col in independentTable.Columns)
                    {
                        if (col.ColumnName != "detectedServicePorts" || col.ColumnName != "ARPStatus" || col.ColumnName != "PingStatus")
                        {

                            var originalValue = originalRow[col.ColumnName];
                            if (originalValue.ToString().Contains("\r"))
                            {
                                originalValue = "\"" + originalRow[col.ColumnName] + "\"";
                            }

                            newRow[col.ColumnName] = originalValue;

                            if (originalRow[col.ColumnName] != DBNull.Value && col.ColumnName.ToLower() == "ssdpstatus")
                            {
                                newRow["isSSDP"] = true;
                            }

                            if (originalRow[col.ColumnName] != DBNull.Value && col.ColumnName.ToLower() == "isipcam" )
                            {
                                newRow["isAnIPCam"] = true;
                            }

                            if (originalRow[col.ColumnName] != DBNull.Value && col.ColumnName.ToLower() == "lookupstatus")
                            {
                                byte[] tada = (byte[])originalRow[col.ColumnName];
                                var green = Properties.Resources.green_dot;
                                var red = Properties.Resources.red_dotTB;

                                if (tada.SequenceEqual(green)) 
                                { 
                                    newRow["LookupEqualReverse"] = true; 
                                }

                                if (tada.SequenceEqual(red)) 
                                {
                                    newRow["LookupEqualReverse"] = false; 
                                }
                            }                            
                        }
                    }

                    // Setze die neuen Werte für Services, Ports, Status
                    newRow["Services"] = service;
                    newRow["Ports"] = port;
                    newRow["Status"] = status;
                    //newRow["originRow"] = originRow;

                    // Füge die Zeile zur neuen Tabelle hinzu
                    expandedDataTable.Rows.Add(newRow);
                }
            }
            expandedDataTable.Columns.Remove("ARPStatus");
            expandedDataTable.Columns.Remove("PingStatus");
            expandedDataTable.Columns.Remove("detectedServicePorts");
            expandedDataTable.Columns.Remove("LookUpStatus");
            ExportToCSV(expandedDataTable);
        }

       

        private void ExportToCSV(DataTable dataTable)
        {
            try
            {
                // Öffne einen Speicherdialog, um den Speicherort zu wählen
                SaveFileDialog saveFileDialog = new SaveFileDialog
                {
                    Filter = "CSV-Dateien (*.csv)|*.csv",
                    DefaultExt = "csv",
                    FileName = "Export.csv",
                    InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop) // Standard: Desktop
                };

                if (saveFileDialog.ShowDialog() == true)
                {
                    string filePath = saveFileDialog.FileName;

                    using (StreamWriter writer = new StreamWriter(filePath, false, Encoding.UTF8))
                    {
                        // Schreibe die Header-Zeile
                        writer.WriteLine(string.Join(";", dataTable.Columns.Cast<DataColumn>().Select(col => col.ColumnName)));

                        // Schreibe die Daten-Zeilen
                        foreach (DataRow row in dataTable.Rows)
                        {
                            writer.WriteLine(string.Join(";", row.ItemArray.Select(field => field?.ToString().Replace(";", ",") ?? "")));
                        }
                    }

                    MessageBox.Show($"CSV-Datei erfolgreich gespeichert:\n{filePath}", "Export abgeschlossen", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Fehler beim CSV-Export: {ex.Message}", "Fehler", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }


















        private void dgv_Results_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if (e.Key == Key.Delete)
            {
                var dataGrid = sender as DataGrid;
                if (dataGrid != null && dataGrid.CurrentCell != null)
                {
                    if ((bool)chk_allowDeleteRow.IsChecked == true)
                    {
                        // Lösche die gesamte Zeile
                        // Hole die DataView aus der ItemsSource des DataGrids
                        DataView dataView = dgv_Results.ItemsSource as DataView;
                        if (dataView != null)
                        {
                            // Erstelle eine Liste der zu löschenden DataRowView-Objekte
                            List<DataRowView> rowsToDelete = new List<DataRowView>();

                            // Füge die ausgewählten Zeilen zur Liste hinzu
                            foreach (var selectedItem in dgv_Results.SelectedItems)
                            {
                                if (selectedItem is DataRowView dataRowView)
                                {
                                    rowsToDelete.Add(dataRowView);
                                }
                            }

                            // Entferne die ausgewählten Zeilen aus der DataView
                            foreach (var row in rowsToDelete)
                            {
                                dataView.Table.Rows.Remove(row.Row);
                            }

                            // Aktualisiere das DataGrid
                            dgv_Results.Items.Refresh();
                        }

                    }
                    else
                    {
                        // Lösche nur den Inhalt der Zelle
                        foreach (var selectedCell in dgv_Results.SelectedCells)
                        {
                            var dataRowView = selectedCell.Item as DataRowView;
                            if (dataRowView != null)
                            {
                                var column = selectedCell.Column as DataGridBoundColumn;
                                if (column != null)
                                {
                                    var bindingPath = (column.Binding as Binding)?.Path.Path;
                                    if (bindingPath != null)
                                    {
                                        // Setze den Wert der DataView-Zelle auf einen leeren String
                                        dataRowView[bindingPath] = string.Empty;
                                    }
                                }
                            }
                        }

                        // Aktualisiere das DataGrid
                        dgv_Results.Items.Refresh();
                    }
                }
                e.Handled = true;
            }
        }

        private void chk_allowDeleteRow_Click(object sender, RoutedEventArgs e)
        {
            if (!(bool)chk_allowDeleteRow.IsChecked)
            {
                dgv_Results.SelectionUnit = DataGridSelectionUnit.Cell;
            }
            else
            {
                dgv_Results.SelectionUnit = DataGridSelectionUnit.FullRow;
            }
        }

        private void mainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            LoadServiceScanSettings();
        }

        private void ScanSelectedIPs_Click(object sender, RoutedEventArgs e)        
        {
            _IPsToScan.Clear();

            // HashSet für eindeutige IP-Adressen
            HashSet<string> selectedIps = new HashSet<string>();

            foreach (var selectedCell in dgv_Results.SelectedCells)
            {
                if (selectedCell.Item is DataRowView rowView)
                {
                    string ipAddress = rowView["IP"].ToString(); // Spaltenname "IP" anpassen
                    if (!string.IsNullOrWhiteSpace(ipAddress))
                    {
                        selectedIps.Add(ipAddress); // Automatisch Duplikate vermeiden
                    }
                }
            }

            foreach (string ip in selectedIps)
            {
                _IPsToScan.Add(new IPToScan { IPorHostname = ip });
            }



            DoWork(true);

            // Speichere die Liste der IP-Adressen im Tag des ContextMenus
            //contextMenu.Tag = selectedIps.ToList();
        }

        private async void SelectedIPFindServicePort_Click(object sender, RoutedEventArgs e)
        {
            _IPsToScan.Clear();

            // HashSet für eindeutige IP-Adressen
            HashSet<string> selectedIps = new HashSet<string>();

            foreach (var selectedCell in dgv_Results.SelectedCells)
            {
                if (selectedCell.Item is DataRowView rowView)
                {
                    string ipAddress = rowView["IP"].ToString(); // Spaltenname "IP" anpassen
                    if (!string.IsNullOrWhiteSpace(ipAddress))
                    {
                        selectedIps.Add(ipAddress); // Automatisch Duplikate vermeiden
                    }
                }
            }

            _IPsToScan.Add(new IPToScan { IPorHostname = selectedIps.ToList()[0] });

            var additionalServicePorts = new Dictionary<ServiceType, List<int>>
            {
                { ServiceType.WebServices, Enumerable.Range(0, 65536).ToList() },
                { ServiceType.FTP, Enumerable.Range(0, 65536).ToList() },
                { ServiceType.SSH, Enumerable.Range(0, 65536).ToList() },
                { ServiceType.RDP, Enumerable.Range(0, 65536).ToList() },

                { ServiceType.UltraVNC, Enumerable.Range(0, 65536).ToList() },
                { ServiceType.TeamViewer, Enumerable.Range(0, 65536).ToList() },
                { ServiceType.BigFixRemote, Enumerable.Range(0, 65536).ToList() },
                { ServiceType.Anydesk, Enumerable.Range(0, 65536).ToList() },
                { ServiceType.Rustdesk, Enumerable.Range(0, 65536).ToList() },

                { ServiceType.MSSQLServer, Enumerable.Range(0, 65536).ToList() },
                { ServiceType.PostgreSQL, Enumerable.Range(0, 65536).ToList() },
                { ServiceType.MariaDB, Enumerable.Range(0, 65536).ToList() },
                { ServiceType.MySQL, Enumerable.Range(0, 65536).ToList() },
                { ServiceType.OracleDB, Enumerable.Range(0, 65536).ToList() },

                { ServiceType.OPCUA, Enumerable.Range(0, 65536).ToList() },
                { ServiceType.ModBus, Enumerable.Range(0, 65536).ToList() },
                { ServiceType.S7, Enumerable.Range(0, 65536).ToList() },
            };

            status_Services_Scan = ScanStatus.running;
            //await scanningMethod_Services.ScanIPsAsync(Services_IPsToScan, new List<ServiceType> { ServiceType.DHCP});





            List<ServiceType> services = new List<ServiceType>();
            // 🌍 Netzwerk-Dienste
            if ((bool)chk_Services_Web.IsChecked) services.Add(ServiceType.WebServices);
            if ((bool)chk_Services_FTP.IsChecked) services.Add(ServiceType.FTP);
            if ((bool)chk_Services_SSH.IsChecked) services.Add(ServiceType.SSH);
            //if ((bool)chk_Services_DNS_TCP.IsChecked) services.Add(ServiceType.DNS_TCP);
            //if ((bool)chk_Services_DNS_UDP.IsChecked) services.Add(ServiceType.DNS_UDP);
            //if ((bool)chk_Services_DHCP.IsChecked) services.Add(ServiceType.DHCP);

            // Remote Apps
            if ((bool)chk_Services_RDP.IsChecked) services.Add(ServiceType.RDP);
            if ((bool)chk_Services_UltraVNC.IsChecked) services.Add(ServiceType.UltraVNC);
            if ((bool)chk_Services_TeamViewer.IsChecked) services.Add(ServiceType.TeamViewer);
            if ((bool)chk_Services_BigFixRemote.IsChecked) services.Add(ServiceType.BigFixRemote);
            if ((bool)chk_Services_AnyDesk.IsChecked) services.Add(ServiceType.Anydesk);
            if ((bool)chk_Services_Rustdesk.IsChecked) services.Add(ServiceType.Rustdesk);

            // Datenbanken
            if ((bool)chk_Services_MSSQL.IsChecked) services.Add(ServiceType.MSSQLServer);
            if ((bool)chk_Services_Postgre.IsChecked) services.Add(ServiceType.PostgreSQL);
            if ((bool)chk_Services_MongoDB.IsChecked) services.Add(ServiceType.MongoDB);
            if ((bool)chk_Services_MariaDB.IsChecked) services.Add(ServiceType.MariaDB);
            if ((bool)chk_Services_MYSQL.IsChecked) services.Add(ServiceType.MySQL);
            if ((bool)chk_Services_OracleDB.IsChecked) services.Add(ServiceType.OracleDB);


            // Industrieprotokolle  
            if ((bool)chk_Services_OPCUA.IsChecked) services.Add(ServiceType.OPCUA);
            if ((bool)chk_Services_ModBus.IsChecked) services.Add(ServiceType.ModBus);
            if ((bool)chk_Services_SiemensS7.IsChecked) services.Add(ServiceType.S7);

            if (services.Count == 0)
            {
                MessageBox.Show("please choos max. one service, because of the duration of thise kind of scan.", "Hint", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            await scanningMethod_Services.FindServicePortAsync(_IPsToScan[0], services[0]);
        }
    }
}