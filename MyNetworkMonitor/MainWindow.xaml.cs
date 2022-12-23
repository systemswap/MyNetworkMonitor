
using DnsClient;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Media;
using static MyNetworkMonitor.SendReceiveDataUDP;
using static System.Net.Mime.MediaTypeNames;

namespace MyNetworkMonitor
{
    // install as Service https://www.youtube.com/watch?v=y64L-3HKuP0

    
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            scanningMethode_SSDP_UPNP = new ScanningMethod_SSDP_UPNP();
            scanningMethode_SSDP_UPNP.SSDP_foundNewDevice += SSDP_foundNewDevice;
            scanningMethode_SSDP_UPNP.SSDP_Scan_Finished += SSDP_Scan_Finished;

            scanningMethode_ARP = new ScanningMethod_ARP();
            scanningMethode_ARP.ARP_A_newDevice += ARP_A_newDevive_Finished;
            scanningMethode_ARP.ARP_Request_Task_Finished += ARP_Request_Task_Finished;
            scanningMethode_ARP.ARP_Request_Finished += ARP_Request_Finished;

            scanningMethods_Ping = new ScanningMethods_Ping();
            scanningMethods_Ping.Ping_Task_Finished += Ping_Task_Finished;
            scanningMethods_Ping.PingFinished += PingFinished_Event;

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

            supportMethods = new SupportMethods();

            dv_resultTable = new DataView(_scannResults.ResultTable);

            //CollectionViewSource cvs = new CollectionViewSource(); 
            //cvs.Source = dv_resultTable;
            //cvs.GroupDescriptions.Add(new PropertyGroupDescription("GroupDescription"));

            dgv_Results.ItemsSource = dv_resultTable;        

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

            DataContext = ipGroupData.IPGroupsDT.DefaultView;

            if (File.Exists(_lastScanResultFile))
            {
                try
                {
                    _scannResults.ResultTable.ReadXml(_lastScanResultFile);
                }
                catch (Exception)
                {
                    //throw;
                }
            }


            if (File.Exists(_portsToScan))
            {
                try
                {
                    _portCollection.TableOfPortsToScan.Rows.Clear();
                    _portCollection.TableOfPortsToScan.ReadXml(_portsToScan);
                }
                catch (Exception)
                {
                    //throw;
                }
            }
            else
            {
                new PortCollection().TableOfPortsToScan.WriteXml(_portsToScan);
                _portCollection.TableOfPortsToScan.ReadXml(_portsToScan);
            }

            dg_PortsToScan.ItemsSource = _portCollection.TableOfPortsToScan.DefaultView;

        }

        PortCollection _portCollection = new PortCollection();
        string _portsToScan = Path.Combine(Environment.CurrentDirectory, @"Settings\portsToScan.xml");
        string _ipGroupsXML = Path.Combine(Environment.CurrentDirectory, @"Settings\ipGroups.xml");
        string _lastScanResultFile = Path.Combine(Environment.CurrentDirectory, @"Settings\lastScanResult.xml");

        IPGroupData ipGroupData = new IPGroupData();


        //List<string> IPsToRefresh = new List<string>();
        int _TimeOut = 250;

        List<IPToScan> _IPsToScan = new List<IPToScan>();
        ScanResults _scannResults = new ScanResults();
        DataView dv_resultTable;

        ScanningMethod_ARP scanningMethode_ARP;
        ScanningMethods_Ping scanningMethods_Ping;
        ScanningMethod_SSDP_UPNP scanningMethode_SSDP_UPNP;
        ScanningMethod_ReverseLookupToHostAndAlieases scanningMethode_ReverseLookupToHostAndAliases;
        ScanningMethod_LookUp scanningMethod_LookUp;
        ScanningMethod_PortsTCP scanningMethode_PortsTCP;
        ScanningMethod_PortsUDP scanningMethode_PortsUDP;

        SupportMethods supportMethods;

        #region ScanStatus
        public enum ScanStatus
        {
            ignored,
            waiting,
            running,
            finished
        }

      
        ScanStatus arp_a_state = ScanStatus.ignored;

        ScanStatus ping_state = ScanStatus.ignored;
        int currentPingCount = 0;
        int CountedPings = 0;

        ScanStatus ssdp_state = ScanStatus.ignored;
        int currentSSDPCount = 0;
        int CountedSSDPs = 0;

        ScanStatus dns_state = ScanStatus.ignored;
        int currentHostnameCount = 0;        
        int CountedHostnames = 0;
        int responsedHostNamesCount = 0;

        ScanStatus Lookup_state = ScanStatus.ignored;
        int currentLookupCount = 0;
        int CountedLookups = 0;
        int responsedLookupDevices = 0;

        ScanStatus arpRequest_state = ScanStatus.ignored;
        int currentARPRequest = 0;        
        int CountedARPRequests = 0;
        int responsedARPRequestCount = 0;

        ScanStatus tcp_port_Scan_state = ScanStatus.ignored;
        int current_TCPPortScan_Count = 0;
        int Counted_TCPPortScans = 0;
        int responsedTCPPortScanDevices = 0;

        ScanStatus udp_port_Scan_state = ScanStatus.ignored;
        int current_UDPPortScan_Count = 0;
        int Counted_UDPListener = 0;

        public void Status()
        {
            lbl_ScanStatus.Content = string.Format($"" +
                $"SSDP Status: {ssdp_state.ToString()} found {currentSSDPCount} from {CountedSSDPs}        " +
                $"ARP-Request: {arpRequest_state.ToString()}  {currentARPRequest} from {CountedARPRequests} found {responsedARPRequestCount}        " +
                $"Ping Status: {ping_state.ToString()} {currentPingCount} of {CountedPings}        " +                
                $"HostNames: {dns_state.ToString()} {currentHostnameCount.ToString()} from {CountedHostnames.ToString()} found {responsedHostNamesCount.ToString()}        " +
                $"NSLookUps: {Lookup_state.ToString()}  {currentLookupCount.ToString()} from {CountedLookups.ToString()} found: {responsedLookupDevices}        " +
                $"TCP Scan: {tcp_port_Scan_state.ToString()} {current_TCPPortScan_Count} from {Counted_TCPPortScans} answerd: {responsedTCPPortScanDevices}         " +
                $"UDP Scan: {udp_port_Scan_state.ToString()} added: {current_UDPPortScan_Count} of {Counted_UDPListener}        " +
                $"arp-a: {arp_a_state.ToString()}");
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
            string myIP = new SupportMethods().GetLocalIPv4(System.Net.NetworkInformation.NetworkInterfaceType.Ethernet);

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
                            if(_entry != null)
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
            currentPingCount = 0;
            CountedPings = 0;

            currentSSDPCount = 0;
            CountedSSDPs = 0;
            
            currentHostnameCount = 0;
            CountedHostnames = 0;
            responsedHostNamesCount = 0;

            currentLookupCount = 0;
            CountedLookups = 0;
            responsedLookupDevices = 0;

            currentARPRequest = 0;
            CountedARPRequests = 0;
            responsedARPRequestCount = 0;

            current_TCPPortScan_Count = 0;
            Counted_TCPPortScans = 0;
            responsedTCPPortScanDevices = 0;

            current_UDPPortScan_Count =0;
            Counted_UDPListener= 0;


            foreach (DataRow row in _scannResults.ResultTable.Rows)
            {
                if (_IPsToScan.Where(i => i.IPorHostname == row["IP"].ToString()).Count() > 0)
                {
                    if((bool)chk_Methodes_ARP_A.IsChecked && !string.IsNullOrEmpty(row["ARPStatus"].ToString())) row["ARPStatus"] = Properties.Resources.gray_dot;


                    if ((bool)chk_Methodes_Ping.IsChecked && !string.IsNullOrEmpty(row["PingStatus"].ToString())) row["PingStatus"] = Properties.Resources.gray_dot;
                    if ((bool)chk_Methodes_Ping.IsChecked) row["ResponseTime"] = string.Empty;

                    if ((bool)chk_Methodes_SSDP.IsChecked && !string.IsNullOrEmpty(row["SSDPStatus"].ToString())) row["SSDPStatus"] = Properties.Resources.gray_dot;

                    if ((bool)chk_Methodes_ScanTCPPorts.IsChecked) row["TCP_Ports"] = null;
                    if ((bool)chk_Methodes_ScanUDPPorts.IsChecked) row["OpenUDP_Ports"] = null;

                    if ((bool)chk_Methodes_ScanHostnames.IsChecked)
                    {
                        row["Domain"] = string.Empty;
                        row["Hostname"] = string.Empty;
                        row["Aliases"] = string.Empty;
                    }

                    if ((bool)chk_Methodes_LookUp.IsChecked && !string.IsNullOrEmpty(row["LookUpStatus"].ToString()))
                    {
                        row["LookUpStatus"] = Properties.Resources.gray_dot;
                        row["LookUpIPs"] = string.Empty;
                    }
                }
            }
            

            /* set the states */
            if ((bool)chk_Methodes_SSDP.IsChecked) ssdp_state = ScanStatus.waiting;
            if ((bool)chk_ARPRequest.IsChecked) arpRequest_state = ScanStatus.waiting;
            if ((bool)chk_Methodes_Ping.IsChecked) ping_state = ScanStatus.waiting;
            if ((bool)chk_Methodes_ScanHostnames.IsChecked) dns_state = ScanStatus.waiting;
            if ((bool)chk_Methodes_LookUp.IsChecked) Lookup_state = ScanStatus.waiting;
            if ((bool)chk_Methodes_ScanTCPPorts.IsChecked) tcp_port_Scan_state = ScanStatus.waiting;
            if ((bool)chk_Methodes_ScanUDPPorts.IsChecked) udp_port_Scan_state = ScanStatus.waiting;
            if ((bool)chk_Methodes_ARP_A.IsChecked) arp_a_state = ScanStatus.waiting;


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


            if ((bool)chk_Methodes_SSDP.IsChecked)
            {
                ssdp_state = ScanStatus.running;
                CountedSSDPs = _IPsToScan.Count;
                Status();
                Task.Run(() => scanningMethode_SSDP_UPNP.ScanForSSDP(_IPsToScan));
            }


            if ((bool)chk_ARPRequest.IsChecked)
            {
                CountedARPRequests = _IPsToScan.Count;
                arpRequest_state = ScanStatus.running;
                Status();

                await Task.Run(() => scanningMethode_ARP.SendARPRequestAsync(_IPsToScan));
            }            


            if ((bool)chk_Methodes_Ping.IsChecked)
            {
                ping_state = ScanStatus.running;
                CountedPings = _IPsToScan.Count;
                Status();
                await scanningMethods_Ping.PingIPsAsync(_IPsToScan, false);
            }


            List<IPToScan> IPsForHostnameScan = new List<IPToScan>();
            if ((bool)chk_Methodes_ScanHostnames.IsChecked)
            {

                if (_scannResults.ResultTable.Rows.Count == 0 || (bool)rb_ScanHostnames_All_IPs.IsChecked || IsSelectiveScan)
                {
                    IPsForHostnameScan = _IPsToScan;
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

                        IPsForHostnameScan.Add(ipToScan);
                    }
                }

                dns_state = ScanStatus.running;
                CountedHostnames = IPsForHostnameScan.Count;
                //CountedHostnames = _IPsToRefresh.Count;
                Status();

                if ((bool)chk_Methodes_LookUp.IsChecked)
                {
                    Lookup_state = ScanStatus.waiting;
                    Status();
                }

                await Task.Run(() => scanningMethode_ReverseLookupToHostAndAliases.GetHost_Aliases(IPsForHostnameScan));
                //await Task.Run(() => scanningMethode_DNS.Get_Host_and_Alias_From_IP(_IPsToRefresh));
            }


            if ((bool)chk_Methodes_LookUp.IsChecked)
            {
                //give some time to insert the results of DNS Hostname into Datatable
                await Task.Run(() => Thread.Sleep(1000));

                List<IPToScan> IPsForLookUp = new List<IPToScan>();
                foreach (IPToScan _ipToScan in IPsForHostnameScan)
                {
                    List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + _ipToScan.IPorHostname + "'").ToList();                    

                    if(rows.Count > 0)
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

                Lookup_state = ScanStatus.running;
                CountedLookups = IPsForLookUp.Count;
                Status();

                Task.Run(() => scanningMethod_LookUp.LookupAsync(IPsForLookUp));
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
                
                tcp_port_Scan_state = ScanStatus.running;
                Counted_TCPPortScans = _IPsForTCPPortScan.Count;
                Status();

                await Task.Run(() => scanningMethode_PortsTCP.ScanTCPPorts(_IPsForTCPPortScan, new TimeSpan(0, 0, 0, 0, _TimeOut)));
            }


            if ((bool)chk_Methodes_ScanUDPPorts.IsChecked)
            {
                udp_port_Scan_state = ScanStatus.running;
                Status();

                Task.Run(() => scanningMethode_PortsUDP.Get_All_UPD_Listener_as_List(_IPsToScan));
            }


            if ((bool)chk_Methodes_ARP_A.IsChecked)
            {
                arp_a_state = ScanStatus.running;
                Status();

                Task.Run(() => scanningMethode_ARP.ARP_A(_IPsToScan));
            }        
        }

        public void InsertIPToScanResult(IPToScan ipToScan)
        {
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
                _scannResults.ResultTable.Rows[rowIndex]["DNSServers"] = string.Join(',', ipToScan.DNSServerList);
                _scannResults.ResultTable.Rows[rowIndex]["GatewayIP"] = ipToScan.GatewayIP;
                _scannResults.ResultTable.Rows[rowIndex]["GatewayPort"] = ipToScan.GatewayPort;

                if (ipToScan.UsedScanMethod == ScanMethod.SSDP) 
                { 
                    _scannResults.ResultTable.Rows[rowIndex]["SSDPStatus"] = ipToScan.SSDPStatus ? Properties.Resources.green_dot : Properties.Resources.red_dot; 
                }

                if (ipToScan.UsedScanMethod == ScanMethod.ARP)
                {
                    _scannResults.ResultTable.Rows[rowIndex]["ARPStatus"] = ipToScan.ARPStatus ? Properties.Resources.green_dot : Properties.Resources.red_dot;
                    _scannResults.ResultTable.Rows[rowIndex]["MAC"] = ipToScan.MAC;
                    _scannResults.ResultTable.Rows[rowIndex]["Vendor"] = ipToScan.Vendor;
                }

                
                
                if (ipToScan.UsedScanMethod == ScanMethod.Ping)
                {
                    _scannResults.ResultTable.Rows[rowIndex]["PingStatus"] = ipToScan.PingStatus ? Properties.Resources.green_dot : Properties.Resources.red_dot;
                    _scannResults.ResultTable.Rows[rowIndex]["ResponseTime"] = ipToScan.ResponseTime;
                }

                if (ipToScan.UsedScanMethod == ScanMethod.ReverseLookup)
                {
                    _scannResults.ResultTable.Rows[rowIndex]["Hostname"] = ipToScan.HostName;
                    _scannResults.ResultTable.Rows[rowIndex]["Domain"] = ipToScan.Domain;
                    _scannResults.ResultTable.Rows[rowIndex]["Aliases"] = string.Join("\r\n", ipToScan.Aliases);
                }

                if (ipToScan.UsedScanMethod == ScanMethod.Lookup)
                {
                    _scannResults.ResultTable.Rows[rowIndex]["LookUpStatus"] = ipToScan.LookUpStatus ? Properties.Resources.green_dot : Properties.Resources.red_dot;
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
                row["DNSServers"] = string.Join(',', ipToScan.DNSServerList);
                row["GatewayIP"] = ipToScan.GatewayIP;
                row["GatewayPort"] = ipToScan.GatewayPort;

                if (ipToScan.UsedScanMethod == ScanMethod.SSDP)
                {
                    row["SSDPStatus"] = ipToScan.SSDPStatus ? Properties.Resources.green_dot : Properties.Resources.red_dot;
                }

                if (ipToScan.UsedScanMethod == ScanMethod.ARP) 
                { 
                    row["ARPStatus"] = ipToScan.ARPStatus ? Properties.Resources.green_dot : Properties.Resources.red_dot;
                    row["MAC"] = ipToScan.MAC;
                    row["Vendor"] = ipToScan.Vendor;
                }

                if (ipToScan.UsedScanMethod == ScanMethod.Ping)
                {
                    row["PingStatus"] = ipToScan.PingStatus ? Properties.Resources.green_dot : Properties.Resources.red_dot;
                }

                if (ipToScan.UsedScanMethod == ScanMethod.Ping)
                {
                    row["ResponseTime"] = ipToScan.ResponseTime;
                }

                if (ipToScan.UsedScanMethod == ScanMethod.ReverseLookup)
                {
                    row["Hostname"] = ipToScan.HostName;
                    row["Aliases"] = string.Join("\r\n", ipToScan.Aliases);
                }

                if (ipToScan.UsedScanMethod == ScanMethod.Lookup)
                {
                    row["LookUpStatus"] = ipToScan.LookUpStatus ? Properties.Resources.green_dot : Properties.Resources.red_dot;
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

                arp_a_state = ScanStatus.finished;
                Status();
            });
        }

        private void Ping_Task_Finished(object? sender, ScanTask_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() => 
            {               
                InsertIPToScanResult(e.ipToScan);

                ++currentPingCount;
                Status();
            });
        }
        private void PingFinished_Event(object? sender, Method_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                ping_state = ScanStatus.finished;
                Status();
            });
        }



        private void SSDP_foundNewDevice(object? sender, ScanTask_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                InsertIPToScanResult(e.ipToScan);

                ++currentSSDPCount;
                Status();
            });
        }
        private void SSDP_Scan_Finished(object? sender, Method_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                ssdp_state = ScanStatus.finished;
                Status();
            }));
        }



        private void ARP_Request_Task_Finished(object? sender, ScanTask_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                ++currentARPRequest;
                Status();

                if (string.IsNullOrEmpty(e.ipToScan.IPorHostname))
                {
                    return;
                }
               
                InsertIPToScanResult(e.ipToScan);

                ++responsedARPRequestCount;
                Status();
            });
        }
        private void ARP_Request_Finished(object? sender, Method_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() => 
            {
                arpRequest_state = ScanStatus.finished;
                Status();
            });
        }



        private void DNS_GetHostAliases_Task_Finished(object? sender, ScanTask_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                ++currentHostnameCount;
                Status();

                if (e == null || string.IsNullOrEmpty(e.ipToScan.HostName))
                {
                    return;
                }

                InsertIPToScanResult(e.ipToScan);

                ++responsedHostNamesCount;
                Status();
            });
        }
        private void DNS_GetHostAndAliasFromIP_Finished(object? sender, Method_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                dns_state = ScanStatus.finished;
                Status();
            });
        }



        private void Lookup_Task_Finished(object? sender, ScanTask_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                ++currentLookupCount;
                Status();


                InsertIPToScanResult(e.ipToScan);


                ++responsedLookupDevices;
                Status();
            });
        }
        private void Lookup_Finished(object? sender, Method_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() => 
            {
                Lookup_state = ScanStatus.finished;
                Status();
            });
        }



        private void TcpPortScan_Task_Finished(object? sender, ScanTask_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                ++current_TCPPortScan_Count;
                Status();

                if (e == null)
                {
                    return;
                }
               

                InsertIPToScanResult(e.ipToScan);


                ++responsedTCPPortScanDevices;
                Status();
            });
        }
        private void TcpPortScan_Finished(object? sender, Method_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                tcp_port_Scan_state = ScanStatus.finished;
                Status();
            });
        }



        private void UDPPortScan_Task_Finished(object? sender, ScanTask_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {                
                InsertIPToScanResult(e.ipToScan);

                ++current_UDPPortScan_Count;
                Status();
            });
        }
        private void UDPPortScan_Finished(object? sender, Method_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                udp_port_Scan_state = ScanStatus.finished;
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
            if ((bool)chk_SaveLastScanResult.IsChecked)
            {
                foreach (DataRow row in _scannResults.ResultTable.Rows)
                {
                    if (!string.IsNullOrEmpty(row["SSDPStatus"].ToString())) row["SSDPStatus"] = Properties.Resources.gray_dot;
                    if (!string.IsNullOrEmpty(row["ARPStatus"].ToString())) row["ARPStatus"] = Properties.Resources.gray_dot;
                    if (!string.IsNullOrEmpty(row["PingStatus"].ToString())) row["PingStatus"] = Properties.Resources.gray_dot;

                    if (!string.IsNullOrEmpty(row["LookUpStatus"].ToString()))
                    {
                        byte[] greenDot = Properties.Resources.green_dot;
                        byte[] cellValue = (byte[])row["LookUpStatus"];
                        bool bla = greenDot.SequenceEqual(cellValue);
                        if (bla) row["LookUpStatus"] = Properties.Resources.gray_dot;
                    }
                }
                _scannResults.ResultTable.WriteXml(_lastScanResultFile, XmlWriteMode.WriteSchema);
            }
        }

        private void bt_SavePortsToScan_Click(object sender, RoutedEventArgs e)
        {
            DataView dv = _portCollection.TableOfPortsToScan.DefaultView;
            dv.Sort = "Ports asc";            
            DataTable sortedtable1 = dv.ToTable();
            sortedtable1.WriteXml(_portsToScan, XmlWriteMode.WriteSchema);
        }
    }
}
