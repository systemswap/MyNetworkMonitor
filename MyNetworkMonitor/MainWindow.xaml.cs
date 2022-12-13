
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
using static MyNetworkMonitor.SendReceiveDataUDP;
using static System.Net.Mime.MediaTypeNames;

namespace MyNetworkMonitor
{
    // install as Service https://www.youtube.com/watch?v=y64L-3HKuP0

    [Serializable]
    public class IPToRefresh
    {
        public IPToRefresh() { }

        private string _IPGroupDescription = string.Empty;
        public string IPGroupDescription { get { return _IPGroupDescription; } set { _IPGroupDescription = value; } }


        private string _DeviceDescription = string.Empty;
        public string DeviceDescription { get { return _DeviceDescription; } set { _DeviceDescription = value; } }


        private string _IP = string.Empty;
        public string IP { get { return _IP; } set { _IP = value; } }

        private string _Hostname = string.Empty;
        public string Hostname { get { return _Hostname; } set { _Hostname = value; } }

        private List<int> _TCPPorts = new List<int>();
        public List<int> TCPPorts { get { return _TCPPorts; } set { _TCPPorts = value; } }


        private List<int> _UDPPorts = new List<int>();
        public List<int> UDPPorts { get { return _UDPPorts; } set { _UDPPorts = value; } }



        private List<string> _DNSServer = new List<string>();
        public List<string> DNSServer { get { return _DNSServer; } set { _DNSServer = value; } }


        private int _TimeOut = 250;
        public int TimeOut { get { return _TimeOut; } set { _TimeOut = value; } }
    }

    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            //Satellit_SocketServer server = new Satellit_SocketServer();
            //Satellit_SocketClient clt = new Satellit_SocketClient();

            //Task.Run(() => server.StartServer());
            //clt.StartClient();

            //server.StopServer();



            scanningMethode_ARP = new ScanningMethod_ARP();
            scanningMethode_ARP.ARP_A_newDevice += ARP_A_Finished;
            scanningMethode_ARP.ARP_Request_Task_Finished += ARP_Request_Task_Finished;
            scanningMethode_ARP.ARP_Request_Finished += ARP_Request_Finished;

            scanningMethods_Ping = new ScanningMethods_Ping();
            scanningMethods_Ping.Ping_Task_Finished += Ping_Task_Finished;
            scanningMethods_Ping.PingFinished += PingFinished_Event;

            scanningMethode_SSDP_UPNP = new ScanningMethod_SSDP_UPNP();
            scanningMethode_SSDP_UPNP.SSDP_NewDevice += SSDP_NewDevice;
            scanningMethode_SSDP_UPNP.SSDP_Scan_Finished += SSDP_Scan_Finished;

            scanningMethode_DNS = new ScanningMethod_DNS();
            scanningMethode_DNS.GetHostAndAliasFromIP_Task_Finished += DNS_GetHostAndAliasFromIP_Task_Finished;
            scanningMethode_DNS.GetHostAndAliasFromIP_Finished += DNS_GetHostAndAliasFromIP_Finished;

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
        }


        string _ipGroupsXML = Path.Combine(Environment.CurrentDirectory, @"Settings\ipGroups.xml");
        IPGroupData ipGroupData = new IPGroupData();


        //List<string> IPsToRefresh = new List<string>();
        int _TimeOut = 250;

        List<IPToRefresh> _IPsToRefresh = new List<IPToRefresh>();
        ScanResults _scannResults = new ScanResults();
        DataView dv_resultTable;

        ScanningMethod_ARP scanningMethode_ARP;
        ScanningMethods_Ping scanningMethods_Ping;
        ScanningMethod_SSDP_UPNP scanningMethode_SSDP_UPNP;
        ScanningMethod_DNS scanningMethode_DNS;
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

        ScanStatus reverseLookup_state = ScanStatus.ignored;
        int currentReverseLookupCount = 0;
        int CountedReverseLookups = 0;
        int responsedReverseLookupDevices = 0;

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
                $"Hostnames: {dns_state.ToString()} {currentHostnameCount.ToString()} from {CountedHostnames.ToString()} found {responsedHostNamesCount.ToString()}        " +
                $"Reverse Lookups: {reverseLookup_state.ToString()}  {currentReverseLookupCount.ToString()} from {CountedReverseLookups.ToString()} found: {responsedReverseLookupDevices}        " +
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

            if (e.PropertyName == "GatewayIP")
            {
                e.Column.Visibility = Visibility.Hidden;                
            }
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

            if (e.PropertyName == "ReverseLookUpStatus")
            {
                // replace text column with image column
                e.Column = new DataGridTemplateColumn
                {
                    // searching for predefined tenplate in Resources
                    CellTemplate = (sender as DataGrid).Resources["ReverseLookUpStatus"] as DataTemplate,
                    HeaderTemplate = e.Column.HeaderTemplate,
                    Header = e.Column.Header
                };
            }
        }

      

        private void bt_ScanIP_Click(object sender, RoutedEventArgs e)
        {
            _IPsToRefresh.Clear();
            List<int> TCPPorts = new List<int>();

            if ((bool)chk_Methodes_ScanTCPPorts.IsChecked && !(bool)chk_allTCPPorts.IsChecked)
            {
                TCPPorts.AddRange(new PortCollection().TCPPorts);

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
                    IPToRefresh toRefresh = new IPToRefresh();
                    toRefresh.IPGroupDescription = "Custom";
                    toRefresh.DeviceDescription = "Custom";
                    toRefresh.IP = IP_or_Hostname;
                    toRefresh.Hostname = string.Empty;
                    toRefresh.TCPPorts = TCPPorts;
                    toRefresh.UDPPorts = null;
                    toRefresh.DNSServer = null;
                    toRefresh.TimeOut = _TimeOut;

                    _IPsToRefresh.Add(toRefresh);
                }
                else
                {
                    IPHostEntry _entry = Task.Run(() => scanningMethod_LookUp.nsLookup(IP_or_Hostname)).Result;
                    if (_entry != null)
                    {
                        foreach (IPAddress address in _entry.AddressList)
                        {
                            IPToRefresh toRefresh = new IPToRefresh();
                            toRefresh.IPGroupDescription = "Custom";
                            toRefresh.DeviceDescription = "Custom";
                            toRefresh.IP = address.ToString();
                            toRefresh.Hostname = string.Empty;
                            toRefresh.TCPPorts = TCPPorts;
                            toRefresh.UDPPorts = null;
                            toRefresh.DNSServer = null;
                            toRefresh.TimeOut = _TimeOut;

                            _IPsToRefresh.Add(toRefresh);
                        }
                    }
                }
            }
            else
            {
                foreach (DataRowView row in dgv_Results.SelectedItems)
                {
                    if (_IPsToRefresh.Where(i => i.IP == row.Row["IP"].ToString()).Count() == 0)
                    {
                        IPToRefresh toRefresh = new IPToRefresh();
                        toRefresh.IPGroupDescription = row.Row["IPGroupDescription"].ToString();
                        toRefresh.DeviceDescription = row.Row["DeviceDescription"].ToString();
                        toRefresh.IP = row.Row["IP"].ToString();
                        toRefresh.Hostname = row.Row["Hostname"].ToString();
                        toRefresh.TCPPorts = TCPPorts;
                        toRefresh.UDPPorts = null;
                        toRefresh.DNSServer = null;
                        toRefresh.TimeOut = _TimeOut;

                        _IPsToRefresh.Add(toRefresh);
                    }
                }
            } 
            DoWork(true);
        }

       
        private void bt_Scan_IP_Ranges_Click(object sender, RoutedEventArgs e)
        {
            _IPsToRefresh.Clear();

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
                TCPPorts.AddRange(new PortCollection().TCPPorts);
            }
            else
            {
                TCPPorts.AddRange(Enumerable.Range(1, 65536));
            }


            foreach (DataRow row in ipGroupData.IPGroupsDT.Rows)
            {
                if ((bool)row["IsActive"])
                {
                    

                    if (String.IsNullOrEmpty(row["LastIP"].ToString()))
                    {
                        string IP_or_Hostname = row["FirstIP"].ToString();
                        if (supportMethods.Is_Valid_IP(IP_or_Hostname))
                        {
                            IPToRefresh toRefresh = new IPToRefresh();
                            toRefresh.IPGroupDescription = row["IPGroupDescription"].ToString();
                            toRefresh.DeviceDescription = row["DeviceDescription"].ToString();
                            toRefresh.IP = IP_or_Hostname;
                            toRefresh.Hostname = string.Empty;
                            toRefresh.TCPPorts = TCPPorts;
                            toRefresh.UDPPorts = null;
                            toRefresh.DNSServer = row["DNSServer"].ToString().Split(',').ToList();
                            toRefresh.TimeOut = _TimeOut;

                            _IPsToRefresh.Add(toRefresh);
                        }
                        else
                        {
                            IPHostEntry _entry = Task.Run(() => scanningMethod_LookUp.nsLookup(IP_or_Hostname)).Result;
                            if(_entry != null)
                            {
                                foreach (IPAddress address in _entry.AddressList)
                                {
                                    IPToRefresh toRefresh = new IPToRefresh();
                                    toRefresh.IPGroupDescription = row["IPGroupDescription"].ToString();
                                    toRefresh.DeviceDescription = row["DeviceDescription"].ToString();
                                    toRefresh.IP = address.ToString();
                                    toRefresh.Hostname = string.Empty;
                                    toRefresh.TCPPorts = TCPPorts;
                                    toRefresh.UDPPorts = null;
                                    toRefresh.DNSServer = row["DNSServer"].ToString().Split(',').ToList();
                                    toRefresh.TimeOut = _TimeOut;

                                    _IPsToRefresh.Add(toRefresh);
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

                            IPToRefresh toRefresh = new IPToRefresh();
                            toRefresh.IPGroupDescription = row["IPGroupDescription"].ToString();
                            toRefresh.DeviceDescription = row["DeviceDescription"].ToString();
                            toRefresh.IP = ip;
                            toRefresh.Hostname = string.Empty;
                            toRefresh.TCPPorts = new PortCollection().TCPPorts;
                            toRefresh.UDPPorts = new PortCollection().UDPPorts;
                            toRefresh.DNSServer = row["DNSServer"].ToString().Split(',').ToList();
                            toRefresh.TimeOut = _TimeOut;

                            _IPsToRefresh.Add(toRefresh);
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

            currentReverseLookupCount = 0;
            CountedReverseLookups = 0;
            responsedReverseLookupDevices = 0;

            currentARPRequest = 0;
            CountedARPRequests = 0;
            responsedARPRequestCount = 0;

            current_TCPPortScan_Count = 0;
            Counted_TCPPortScans = 0;
            responsedTCPPortScanDevices = 0;

            current_UDPPortScan_Count =0;
            Counted_UDPListener= 0;


            //if (TCP_Ports == null) TCP_Ports = new PortCollection().TCPPorts;
            //if (Udp_Ports == null) Udp_Ports = new PortCollection().UDPPorts;


            foreach (DataRow row in _scannResults.ResultTable.Rows)
            {

                if ((_IPsToRefresh.Where(i => i.IP == row["IP"].ToString()).Count() > 0 && (bool)chk_Methodes_ARP_A.IsChecked) || ClearTable) row["ARPStatus"] = null;


                if ((_IPsToRefresh.Where(i => i.IP == row["IP"].ToString()).Count() > 0 && (bool)chk_Methodes_Ping.IsChecked) || ClearTable) row["PingStatus"] = null;
                if ((_IPsToRefresh.Where(i => i.IP == row["IP"].ToString()).Count() > 0 && (bool)chk_Methodes_Ping.IsChecked) || ClearTable) row["ResponseTime"] = string.Empty;

                if ((_IPsToRefresh.Where(i => i.IP == row["IP"].ToString()).Count() > 0 && (bool)chk_Methodes_SSDP.IsChecked) || ClearTable) row["SSDPStatus"] = null;

                if ((_IPsToRefresh.Where(i => i.IP == row["IP"].ToString()).Count() > 0 && (bool)chk_Methodes_ScanTCPPorts.IsChecked) || ClearTable) row["TCP_Ports"] = null;
                if ((_IPsToRefresh.Where(i => i.IP == row["IP"].ToString()).Count() > 0 && (bool)chk_Methodes_ScanUDPPorts.IsChecked) || ClearTable) row["OpenUDP_Ports"] = null;


            
                if ((_IPsToRefresh.Where(i => i.IP == row["IP"].ToString()).Count() > 0 && (bool)chk_Methodes_ScanHostnames.IsChecked) || ClearTable)
                {
                    row["Hostname"] = string.Empty;
                    row["Aliases"] = string.Empty;
                }


                if ((_IPsToRefresh.Where(i => i.IP == row["IP"].ToString()).Count() > 0 && (bool)chk_Methodes_ReverseLookUp.IsChecked) || ClearTable)
                {
                    row["ReverseLookUpStatus"] = null;
                    row["ReverseLookUpIPs"] = string.Empty;
                }
            }
            

            /* set the states */
            if ((bool)chk_Methodes_SSDP.IsChecked) ssdp_state = ScanStatus.waiting;
            if ((bool)chk_ARPRequest.IsChecked) arpRequest_state = ScanStatus.waiting;
            if ((bool)chk_Methodes_Ping.IsChecked) ping_state = ScanStatus.waiting;
            if ((bool)chk_Methodes_ScanHostnames.IsChecked) dns_state = ScanStatus.waiting;
            if ((bool)chk_Methodes_ReverseLookUp.IsChecked) reverseLookup_state = ScanStatus.waiting;
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
                CountedSSDPs = _IPsToRefresh.Count;
                Status();
                Task.Run(() => scanningMethode_SSDP_UPNP.ScanForSSDP());
            }


            if ((bool)chk_ARPRequest.IsChecked)
            {
                CountedARPRequests = _IPsToRefresh.Count;
                arpRequest_state = ScanStatus.running;
                Status();

                await Task.Run(() => scanningMethode_ARP.SendARPRequestAsync(_IPsToRefresh));
            }            


            if ((bool)chk_Methodes_Ping.IsChecked)
            {
                ping_state = ScanStatus.running;
                CountedPings = _IPsToRefresh.Count;
                Status();
                await scanningMethods_Ping.PingIPsAsync(_IPsToRefresh, false);
            }


            List<IPToRefresh> IPsForHostnameScan = new List<IPToRefresh>();
            if ((bool)chk_Methodes_ScanHostnames.IsChecked)
            {

                if (_scannResults.ResultTable.Rows.Count == 0 || (bool)rb_ScanHostnames_All_IPs.IsChecked || IsSelectiveScan)
                {
                    IPsForHostnameScan = _IPsToRefresh;
                }
                else
                {
                    foreach (DataRow row in _scannResults.ResultTable.Rows)
                    {
                        IPToRefresh toRefresh = new IPToRefresh();
                        toRefresh.IPGroupDescription = row["IPGroupDescription"].ToString();
                        toRefresh.DeviceDescription = row["DeviceDescription"].ToString();
                        toRefresh.IP = row["ip"].ToString();
                        toRefresh.Hostname = string.Empty;
                        toRefresh.TCPPorts = new PortCollection().TCPPorts;
                        toRefresh.UDPPorts = new PortCollection().UDPPorts;
                        toRefresh.DNSServer = row["DNSServer"].ToString().Split(',').ToList();
                        toRefresh.TimeOut = _TimeOut;

                        IPsForHostnameScan.Add(toRefresh);
                    }
                }

                dns_state = ScanStatus.running;
                CountedHostnames = IPsForHostnameScan.Count;
                //CountedHostnames = _IPsToRefresh.Count;
                Status();

                if ((bool)chk_Methodes_ReverseLookUp.IsChecked)
                {
                    reverseLookup_state = ScanStatus.waiting;
                    Status();
                }

                await Task.Run(() => scanningMethode_DNS.Get_Host_and_Alias_From_IP(IPsForHostnameScan));
                //await Task.Run(() => scanningMethode_DNS.Get_Host_and_Alias_From_IP(_IPsToRefresh));
            }


            if ((bool)chk_Methodes_ReverseLookUp.IsChecked)
            {
                //give some time to insert the results of DNS Hostname into Datatable
                await Task.Run(() => Thread.Sleep(1000));

                List<IPToRefresh> IPsForReverseLookUp = new List<IPToRefresh>();
                foreach (IPToRefresh ip in IPsForHostnameScan)
                {
                    List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + ip.IP + "'").ToList();                    

                    if(rows.Count > 0)
                    {
                        int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);

                        if (!string.IsNullOrEmpty(_scannResults.ResultTable.Rows[rowIndex]["Hostname"].ToString()))
                        {
                            IPToRefresh toRefresh = new IPToRefresh();
                            toRefresh.IPGroupDescription = _scannResults.ResultTable.Rows[rowIndex]["IPGroupDescription"].ToString();
                            toRefresh.DeviceDescription = _scannResults.ResultTable.Rows[rowIndex]["DeviceDescription"].ToString();
                            toRefresh.IP = ip.IP;
                            toRefresh.Hostname = _scannResults.ResultTable.Rows[rowIndex]["Hostname"].ToString();
                            toRefresh.DNSServer = _scannResults.ResultTable.Rows[rowIndex]["DNSServer"].ToString().Split(',').ToList();

                            IPsForReverseLookUp.Add(toRefresh);
                        }
                    }
                }

                reverseLookup_state = ScanStatus.running;
                CountedReverseLookups = IPsForReverseLookUp.Count;
                //CountedReverseLookups = _IPsToRefresh.Count;
                Status();

                scanningMethod_LookUp.LookupAsync(IPsForReverseLookUp);
            }


            if ((bool)chk_Methodes_ScanTCPPorts.IsChecked)
            {
                tcp_port_Scan_state = ScanStatus.running;
                Counted_TCPPortScans = _IPsToRefresh.Count;
                Status();

                Task.Run(() => scanningMethode_PortsTCP.ScanTCPPorts(_IPsToRefresh, new TimeSpan(0, 0, 0, 0, _TimeOut)));
            }


            if ((bool)chk_Methodes_ScanUDPPorts.IsChecked)
            {
                udp_port_Scan_state = ScanStatus.running;
                Status();

                Task.Run(() => scanningMethode_PortsUDP.Get_All_UPD_Listener_as_List());
            }


            if ((bool)chk_Methodes_ARP_A.IsChecked)
            {
                arp_a_state = ScanStatus.running;
                Status();

                Task.Run(() => scanningMethode_ARP.ARP_A());
            }        
        }

        private void ARP_A_Finished(object? sender, ARP_A_newDevice_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + e.IP + "'").ToList();

                if (rows.Count == 0)
                {
                    DataRow row = _scannResults.ResultTable.NewRow();

                    row["ARPStatus"] = e.ARPStatus ? Properties.Resources.green_dot : Properties.Resources.red_dot;
                    row["IP"] = e.IP;
                    row["MAC"] = e.MAC;
                    row["Vendor"] = e.Vendor;
                    _scannResults.ResultTable.Rows.Add(row);
                }
                else
                {
                    int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);
                    _scannResults.ResultTable.Rows[rowIndex]["ARPStatus"] = e.ARPStatus ? Properties.Resources.green_dot : Properties.Resources.red_dot;
                    _scannResults.ResultTable.Rows[rowIndex]["IP"] = e.IP;
                    _scannResults.ResultTable.Rows[rowIndex]["MAC"] = e.MAC;
                    _scannResults.ResultTable.Rows[rowIndex]["Vendor"] = e.Vendor;
                }

                arp_a_state = ScanStatus.finished;
                Status();
            });
        }



        private void Ping_Task_Finished(object? sender, Ping_Task_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() => 
            {
                List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + e.IP + "'").ToList();

                if (rows.Count == 0)
                {
                    if (!string.IsNullOrEmpty(e.IP)) {
                        DataRow row = _scannResults.ResultTable.NewRow();
                        row["IPGroupDescription"] = e.IPGroupDescription;
                        row["DeviceDescription"] = e.DeviceDescription;
                        row["PingStatus"] = e.PingStatus ? Properties.Resources.green_dot : Properties.Resources.red_dot;
                        row["IP"] = e.IP;
                        row["ResponseTime"] = e.ResponseTime;

                        _scannResults.ResultTable.Rows.Add(row);
                    } 
                }
                else
                {
                    int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);
                    _scannResults.ResultTable.Rows[rowIndex]["IPGroupDescription"] = e.IPGroupDescription;
                    _scannResults.ResultTable.Rows[rowIndex]["DeviceDescription"] = e.DeviceDescription;
                    _scannResults.ResultTable.Rows[rowIndex]["IP"] = e.IP;
                    _scannResults.ResultTable.Rows[rowIndex]["PingStatus"] = e.PingStatus ? Properties.Resources.green_dot : Properties.Resources.red_dot;                    
                    _scannResults.ResultTable.Rows[rowIndex]["ResponseTime"] = e.ResponseTime;
                }

                ++currentPingCount;
                Status();
            });
        }
        private void PingFinished_Event(object? sender, PingScanFinishedEventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                ping_state = ScanStatus.finished;
                Status();
            });
        }



        private void SSDP_NewDevice(object? sender, SSDP_Device_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + e.IP + "'").ToList();

                if (rows.Count == 0)
                {
                    DataRow row = _scannResults.ResultTable.NewRow();

                    //row["SendAlert"] = false;
                    row["SSDPStatus"] = Properties.Resources.green_dot;
                    row["IP"] = e.IP;
                    //row["ResponseTime"] = "";

                    _scannResults.ResultTable.Rows.Add(row);                    
                }
                else
                {
                    int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);
                    _scannResults.ResultTable.Rows[rowIndex]["SSDPStatus"] = Properties.Resources.green_dot;                    
                }

                ++currentSSDPCount;
                Status();
            });
        }
        private void SSDP_Scan_Finished(object? sender, SSDP_Scan_FinishedEventArgs e)
        {
            Dispatcher.BeginInvoke(new Action(() =>
            {
                ssdp_state = ScanStatus.finished;
                Status();
            }));
        }



        private void ARP_Request_Task_Finished(object? sender, ARP_Request_Task_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                ++currentARPRequest;
                Status();

                if (string.IsNullOrEmpty(e.IP))
                {
                    return;
                }

                List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + e.IP + "'").ToList();
                if (rows.ToList().Count == 0)
                {
                    DataRow row = _scannResults.ResultTable.NewRow();
                    row["IPGroupDescription"] = e.IPGroupDescription;
                    row["DeviceDescription"] = e.DeviceDescription;
                    row["IP"] = e.IP;
                    row["ARPStatus"] = Properties.Resources.green_dot;
                    row["Mac"] = e.MAC;
                    row["Vendor"] = e.Vendor;
                    _scannResults.ResultTable.Rows.Add(row);
                    ++responsedARPRequestCount;
                }
                else
                {
                    int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);
                    _scannResults.ResultTable.Rows[rowIndex]["IPGroupDescription"] = e.IPGroupDescription;
                    _scannResults.ResultTable.Rows[rowIndex]["DeviceDescription"] = e.DeviceDescription;
                    _scannResults.ResultTable.Rows[rowIndex]["ARPStatus"] = Properties.Resources.green_dot;
                    _scannResults.ResultTable.Rows[rowIndex]["Mac"] = e.MAC;
                    _scannResults.ResultTable.Rows[rowIndex]["Vendor"] = e.Vendor;
                    ++responsedARPRequestCount;
                }
                
                Status();
            });
        }
        private void ARP_Request_Finished(object? sender, ARP_Request_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() => 
            {
                arpRequest_state = ScanStatus.finished;
                Status();
            });
        }



        private void DNS_GetHostAndAliasFromIP_Task_Finished(object? sender, GetHostAndAliasFromIP_Task_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                ++currentHostnameCount;
                Status();

                if (e == null || string.IsNullOrEmpty(e.Hostname))
                {
                    return;
                }

                List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + e.IP + "'").ToList();
                if (rows.ToList().Count == 0)
                {
                    DataRow row = _scannResults.ResultTable.NewRow();
                    row["IPGroupDescription"] = e.IPGroupDescription;
                    row["DeviceDescription"] = e.DeviceDescription;
                    row["IP"] = e.IP;
                    row["Hostname"] = e.Hostname;
                    row["Aliases"] = string.Join("\r\n", e.Aliases);
                    _scannResults.ResultTable.Rows.Add(row);
                    ++responsedHostNamesCount;
                }
                else
                {
                    int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);
                    _scannResults.ResultTable.Rows[rowIndex]["IPGroupDescription"] = e.IPGroupDescription;
                    _scannResults.ResultTable.Rows[rowIndex]["DeviceDescription"] = e.DeviceDescription;
                    _scannResults.ResultTable.Rows[rowIndex]["Hostname"] = e.Hostname;
                    _scannResults.ResultTable.Rows[rowIndex]["Aliases"] = string.Join("\r\n", e.Aliases);
                    ++responsedHostNamesCount;
                }

                Status();
            });
        }
        private void DNS_GetHostAndAliasFromIP_Finished(object? sender, GetHostAndAliasFromIP_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                dns_state = ScanStatus.finished;
                Status();
            });
        }



        private void Lookup_Task_Finished(object? sender, Lookup_Task_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                ++currentReverseLookupCount;
                Status();

                List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + e.IP + "'").ToList();

                if (rows.ToList().Count == 0)
                {
                    DataRow row = _scannResults.ResultTable.NewRow();
                    row["IP"] = e.IP;                    
                    row["ReverseLookUpStatus"] = e.LookUpStatus ? Properties.Resources.green_dot: Properties.Resources.red_dot;
                    row["ReverseLookUpIPs"] = e.LookUpIPs;
                    _scannResults.ResultTable.Rows.Add(row);
                    ++responsedReverseLookupDevices;
                }
                else
                {
                    int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);                    
                    _scannResults.ResultTable.Rows[rowIndex]["ReverseLookUpStatus"] = e.LookUpStatus ? Properties.Resources.green_dot : Properties.Resources.red_dot;
                    _scannResults.ResultTable.Rows[rowIndex]["ReverseLookUpIPs"] = e.LookUpIPs;
                    ++responsedReverseLookupDevices;
                }
                Status();
            });
        }
        private void Lookup_Finished(object? sender, Lookup_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() => 
            {
                reverseLookup_state = ScanStatus.finished;
                Status();
            });
        }



        private void TcpPortScan_Task_Finished(object? sender, ScanningMethod_PortsTCP.TcpPortScan_Task_FinishedEventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                ++current_TCPPortScan_Count;
                Status();

                if (e.ScannedPorts == null)
                {
                    return;
                }
                

                List<string> ports= new List<string>();
                if(e.ScannedPorts.openPorts.Count > 0) ports.Add(string.Format($"Open: {string.Join("; ", e.ScannedPorts.openPorts)}"));
                if (e.ScannedPorts.FirewallBlockedPorts.Count > 0) ports.Add(string.Format($"ACL blocked: {string.Join("; ", e.ScannedPorts.FirewallBlockedPorts)}"));

                DataRow[] rows = _scannResults.ResultTable.Select("IP = '" + e.ScannedPorts.IP + "'");
                if (rows.ToList().Count > 0)
                {
                    int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);
                    _scannResults.ResultTable.Rows[rowIndex]["IPGroupDescription"] = e.ScannedPorts.IPGroupDescription;
                    _scannResults.ResultTable.Rows[rowIndex]["DeviceDescription"] = e.ScannedPorts.DeviceDescription;
                    _scannResults.ResultTable.Rows[rowIndex]["TCP_Ports"] = string.Join("\r\n", ports);
                    ++responsedTCPPortScanDevices;
                    Status();
                }
                else
                {
                    DataRow row = _scannResults.ResultTable.NewRow();
                    row["IPGroupDescription"] = e.ScannedPorts.IPGroupDescription;
                    row["DeviceDescription"] = e.ScannedPorts.DeviceDescription;
                    row["IP"] = e.ScannedPorts.IP;
                    row["TCP_Ports"] = string.Join("\r\n", ports);
                    _scannResults.ResultTable.Rows.Add(row);
                    ++responsedTCPPortScanDevices;
                    Status();
                }
            });
        }
        private void TcpPortScan_Finished(object? sender, ScanningMethod_PortsTCP.TcpPortScan_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                tcp_port_Scan_state = ScanStatus.finished;
                Status();
            });
        }



        private void UDPPortScan_Task_Finished(object? sender, UDPPortScan_Task_FinishedEventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                DataRow[] rows = _scannResults.ResultTable.Select("IP = '" + e.OpenPorts.IP + "'");
                if (rows.ToList().Count > 0)
                {
                    int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);
                    _scannResults.ResultTable.Rows[rowIndex]["OpenUDP_Ports"] = string.Join("; ", e.OpenPorts.Ports);
                    ++current_UDPPortScan_Count;
                }
                else
                {
                    //use if you would like to see all UDP Listener incl.IPv6
                    DataRow row = _scannResults.ResultTable.NewRow();
                    row["IP"] = e.OpenPorts.IP;
                    row["OpenUDP_Ports"] = string.Join("; ", e.OpenPorts.Ports);
                    _scannResults.ResultTable.Rows.Add(row);
                    ++current_UDPPortScan_Count;
                }

                
                Status();
            });
        }
        private void UDPPortScan_Finished(object? sender, UDPPortScan_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                udp_port_Scan_state = ScanStatus.finished;
                Counted_UDPListener = e.UDPListener;
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
    }
}
