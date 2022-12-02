
using System;
using System.Collections.Generic;
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
using static MyNetworkMonitor.SendReceiveDataUDP;
using static System.Net.Mime.MediaTypeNames;

namespace MyNetworkMonitor
{
    // install as Service https://www.youtube.com/watch?v=y64L-3HKuP0

    public class IPsToRefresh
    {
        public IPsToRefresh() { }

        public IPsToRefresh(string IP, string GroupDescription, string DeviceDescription, List<int> TCPPorts, List<int> UDPPorts, List<string> DNSServer, int timeOut)
        {
            _IP = IP;
            _GroupDescription = GroupDescription;
            _DeviceDescription = DeviceDescription;
            _TCPPorts = TCPPorts;
            _UDPPorts = UDPPorts;
            _DNSServer = DNSServer;
            _TimeOut = timeOut;
        }
        private string _IP, _GroupDescription, _DeviceDescription;
        private List<int> _TCPPorts, _UDPPorts;
        private List<string> _DNSServer = new List<string>();
        private int _TimeOut = 250;

        public string IP { get { return _IP; } set { _IP = value; } }
        public string GroupDescription { get { return _GroupDescription; } set { _GroupDescription = value; } }
        public string DeviceDescription { get { return _DeviceDescription; } set { _DeviceDescription = value; } }
        public List<int> TCPPorts { get { return _TCPPorts; } set { _TCPPorts = value; } }
        public List<int> UDPPorts { get { return _UDPPorts; } set { _UDPPorts = value; } }
        public List<string> DNSServer { get { return _DNSServer; } set { _DNSServer = value; } }
        public int TimeOut { get { return _TimeOut; } set { _TimeOut = value; } }
    }

    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

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

            scanningMethod_ReverseLookUp = new ScanningMethod_ReverseLookUp();
            scanningMethod_ReverseLookUp.ReverseLookup_Task_Finished += ReverseLookup_Task_Finished;
            scanningMethod_ReverseLookUp.ReverseLookup_Finished += ReverseLookup_Finished;

            scanningMethode_PortsTCP = new ScanningMethod_PortsTCP();
            scanningMethode_PortsTCP.TcpPortScan_Task_Finished += TcpPortScan_Task_Finished;
            scanningMethode_PortsTCP.TcpPortScan_Finished += TcpPortScan_Finished;

            scanningMethode_PortsUDP = new ScanningMethod_PortsUDP();
            scanningMethode_PortsUDP.UDPPortScan_Task_Finished += UDPPortScan_Task_Finished;
            scanningMethode_PortsUDP.UDPPortScan_Finished += UDPPortScan_Finished;

            supportMethods = new SupportMethods();

            dv_resultTable = new DataView(_scannResults.ResultTable);
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

        List<IPsToRefresh> _IPsToRefresh = new List<IPsToRefresh>();
        ScanResults _scannResults = new ScanResults();
        DataView dv_resultTable;

        ScanningMethod_ARP scanningMethode_ARP;
        ScanningMethods_Ping scanningMethods_Ping;
        ScanningMethod_SSDP_UPNP scanningMethode_SSDP_UPNP;
        ScanningMethod_DNS scanningMethode_DNS;
        ScanningMethod_ReverseLookUp scanningMethod_ReverseLookUp;
        ScanningMethod_PortsTCP scanningMethode_PortsTCP;
        ScanningMethod_PortsUDP scanningMethode_PortsUDP;

        SupportMethods supportMethods;

        #region ScanStatus
        public enum ScanStatus
        {
            ignored,
            running,
            finished
        }

        ScanStatus arp_status = ScanStatus.ignored;

        ScanStatus ping_status = ScanStatus.ignored;
        int currentPingCount = 0;
        int CountedPings = 0;

        ScanStatus ssdp_status = ScanStatus.ignored;
        int currentSSDPCount = 0;
        int CountedSSDPs = 0;

        ScanStatus dns_status = ScanStatus.ignored;
        int currentHostnameCount = 0;
        int CountedHostnames = 0;

        ScanStatus reverseLookup_status = ScanStatus.ignored;
        int currentReverseLookupCount = 0;
        int CountedReverseLookups = 0;

        ScanStatus vendor_status = ScanStatus.ignored;
        int currentVendorCount = 0;
        int CountedVendors = 0;

        ScanStatus tcp_port_Scan_status = ScanStatus.ignored;
        int current_TCPPortScan_Count = 0;
        int Counted_TCPPortScans = 0;

        ScanStatus udp_port_Scan_status = ScanStatus.ignored;
        int current_UDPPortScan_Count = 0;
        int Counted_UDPListener = 0;

        public void Status()
        {
            lbl_ScanStatus.Content = string.Format($" arp-a: {arp_status.ToString()}            Ping Status: {ping_status.ToString()} {currentPingCount} of {CountedPings}             SSDP Status: {ssdp_status.ToString()} found {currentSSDPCount} from {CountedSSDPs}             Hostnames: {dns_status.ToString()} found {currentHostnameCount.ToString()} from {CountedHostnames.ToString()}             Reverse Lookups: {reverseLookup_status.ToString()} found  {currentReverseLookupCount.ToString()} from {CountedReverseLookups.ToString()}             Mac: {vendor_status.ToString()} found {currentVendorCount} from {CountedVendors}             TCP Scan: {tcp_port_Scan_status.ToString()} {current_TCPPortScan_Count} from {Counted_TCPPortScans}             UDP Scan: {udp_port_Scan_status.ToString()} added: {current_UDPPortScan_Count} of {Counted_UDPListener}");
        }
        #endregion

        private void dgv_IPRanges_OnAutoGeneratingColumn(object sender, DataGridAutoGeneratingColumnEventArgs e)
        {
            if (e.PropertyName == "GroupDescription")
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

            if ((bool)chk_Methodes_ScanTCPPorts.IsChecked)
            {
                TCPPorts.AddRange(new PortCollection().TCPPorts);

                //Additional Ports from Customer
                if (!string.IsNullOrEmpty(tb_TCPPorts.Text))
                {
                    TCPPorts.AddRange(tb_TCPPorts.Text.Split(',')?.Select(Int32.Parse)?.ToList());
                }
            }
           

            if (!string.IsNullOrEmpty(tb_IP_Address.Text))
            {

                _IPsToRefresh.Add(new IPsToRefresh(tb_IP_Address.Text, "Custom", "Custom", TCPPorts, null, null, _TimeOut));
            }
            else
            {
                foreach (DataRowView row in dgv_Results.SelectedItems)
                {
                    if (_IPsToRefresh.Where(i => i.IP == row.Row["IP"].ToString()).Count() == 0) _IPsToRefresh.Add(new IPsToRefresh(row.Row["IP"].ToString(), string.Empty, string.Empty, TCPPorts, null, null, _TimeOut));
                }
            } 
            DoWork();
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

            foreach (DataRow row in ipGroupData.IPGroupsDT.Rows)
            {
                if ((bool)row["IsActive"])
                {
                    //if first ip is string than add Hostname

                    if (String.IsNullOrEmpty(row["LastIP"].ToString()))
                    {
                        _IPsToRefresh.Add(new IPsToRefresh(row["FirstIP"].ToString(), row["GroupDescription"].ToString(), row["DeviceDescription"].ToString(), new PortCollection().TCPPorts, new PortCollection().UDPPorts, row["DNSServer"].ToString().Split(',').ToList(), _TimeOut));
                    }
                    else
                    {
                        string[] FirstIP = row["FirstIP"].ToString().Split('.');
                        int LastIP = Convert.ToInt16(row["LastIP"]);

                        for (int i = Convert.ToInt16(FirstIP[3]); i <= LastIP; i++)
                        {
                            string ip = string.Format($"{FirstIP[0]}.{FirstIP[1]}.{FirstIP[2]}.{i}");
                            _IPsToRefresh.Add(new IPsToRefresh(ip, row["GroupDescription"].ToString(), row["DeviceDescription"].ToString(), new PortCollection().TCPPorts, new PortCollection().UDPPorts, row["DNSServer"].ToString().Split(',').ToList(), _TimeOut));
                        }
                    }
                }                    
            }
            DoWork();
        }

        
        public async void DoWork(bool ClearTable = false)
        {
            currentPingCount = 0;
            CountedPings = 0;

            currentSSDPCount = 0;
            CountedSSDPs = 0;
            
            currentHostnameCount = 0;
            CountedHostnames = 0;

            currentReverseLookupCount = 0;
            CountedReverseLookups = 0;

            currentVendorCount = 0;
            CountedVendors = 0;

            current_TCPPortScan_Count = 0;
            Counted_TCPPortScans = 0;

            current_UDPPortScan_Count=0;
            Counted_UDPListener= 0;

            //if (TCP_Ports == null) TCP_Ports = new PortCollection().TCPPorts;
            //if (Udp_Ports == null) Udp_Ports = new PortCollection().UDPPorts;


            foreach (DataRow row in _scannResults.ResultTable.Rows)
            {

                //if ((IPsToScan.Contains(row["IP"]) && (bool)chk_Methodes_ARP.IsChecked) || ClearTable) row["ARPStatus"] = null;

                //if ((IPsToScan.Contains(row["IP"]) && (bool)chk_Methodes_Ping.IsChecked) || ClearTable) row["PingStatus"] = null;
                //if ((IPsToScan.Contains(row["IP"]) && (bool)chk_Methodes_Ping.IsChecked) || ClearTable) row["ResponseTime"] = string.Empty;

                //if ((IPsToScan.Contains(row["IP"]) && (bool)chk_Methodes_SSDP.IsChecked) || ClearTable) row["SSDPStatus"] = null;

                //if ((IPsToScan.Contains(row["IP"]) && (bool)chk_Methodes_ScanTCPPorts.IsChecked) || ClearTable) row["OpenTCP_Ports"] = null;
                //if ((IPsToScan.Contains(row["IP"]) && (bool)chk_Methodes_ScanUDPPorts.IsChecked) || ClearTable) row["OpenUDP_Ports"] = null;

                if ((_IPsToRefresh.Where(i => i.IP == row["IP"].ToString()).Count() == 0 && (bool)chk_Methodes_ARP.IsChecked) || ClearTable) row["ARPStatus"] = null;


                if ((_IPsToRefresh.Where(i => i.IP == row["IP"].ToString()).Count() == 0 && (bool)chk_Methodes_Ping.IsChecked) || ClearTable) row["PingStatus"] = null;
                if ((_IPsToRefresh.Where(i => i.IP == row["IP"].ToString()).Count() == 0 && (bool)chk_Methodes_Ping.IsChecked) || ClearTable) row["ResponseTime"] = string.Empty;

                if ((_IPsToRefresh.Where(i => i.IP == row["IP"].ToString()).Count() == 0 && (bool)chk_Methodes_SSDP.IsChecked) || ClearTable) row["SSDPStatus"] = null;

                if ((_IPsToRefresh.Where(i => i.IP == row["IP"].ToString()).Count() == 0 && (bool)chk_Methodes_ScanTCPPorts.IsChecked) || ClearTable) row["OpenTCP_Ports"] = null;
                if ((_IPsToRefresh.Where(i => i.IP == row["IP"].ToString()).Count() == 0 && (bool)chk_Methodes_ScanUDPPorts.IsChecked) || ClearTable) row["OpenUDP_Ports"] = null;



                //if ((IPsToScan.Contains(row["IP"]) && (bool)chk_Methodes_RefreshHostnames.IsChecked) || ClearTable)
                if ((_IPsToRefresh.Where(i => i.IP == row["IP"].ToString()).Count() == 0 && (bool)chk_Methodes_RefreshHostnames.IsChecked) || ClearTable)
                {
                    row["Hostname"] = string.Empty;
                    row["Aliases"] = string.Empty;
                }


                //if (IPsToScan.Contains(row["IP"]) && (bool)chk_Methodes_Refresh_ReverseNSLookUp .IsChecked || ClearTable)
                if ((_IPsToRefresh.Where(i => i.IP == row["IP"].ToString()).Count() == 0 && (bool)chk_Methodes_Refresh_ReverseNSLookUp.IsChecked) || ClearTable)
                {
                    row["ReverseLookUpStatus"] = null;
                    row["ReverseLookUpIPs"] = string.Empty;
                }
            }

            if ((bool)chk_Methodes_ARP.IsChecked)
            {
                arp_status = ScanStatus.running;
                Status();
                await Task.Run(() => scanningMethode_ARP.ARP_A());
            }
            if ((bool)chk_Methodes_Ping.IsChecked)
            {
                ping_status= ScanStatus.running;
                CountedPings = _IPsToRefresh.Count;
                Status();
                scanningMethods_Ping.PingIPsAsync(_IPsToRefresh, false);
            }
            if ((bool)chk_Methodes_SSDP.IsChecked)
            {
                ssdp_status= ScanStatus.running;
                CountedSSDPs = _IPsToRefresh.Count;
                Status();
                Task.Run(() => scanningMethode_SSDP_UPNP.ScanForSSDP());
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

                arp_status = ScanStatus.finished;
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

                        row["PingStatus"] = e.PingStatus ? Properties.Resources.green_dot : Properties.Resources.red_dot;
                        row["IP"] = e.IP;
                        row["ResponseTime"] = e.ResponseTime;

                        _scannResults.ResultTable.Rows.Add(row);
                    } 
                }
                else
                {
                    int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);
                    _scannResults.ResultTable.Rows[rowIndex]["PingStatus"] = e.PingStatus ? Properties.Resources.green_dot : Properties.Resources.red_dot;
                    _scannResults.ResultTable.Rows[rowIndex]["IP"] = e.IP;
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
                ping_status = ScanStatus.finished;
                Status();


                List<string> IPs = null;
                
                if(_scannResults.ResultTable.Rows.Count > 0)
                { 
                    IPs = _scannResults.ResultTable.AsEnumerable().Select(p => p.Field<string>("IP")).ToList();
                }
                else
                {
                    IPs = _IPsToRefresh.Select(i => i.IP).ToList();
                }

                if ((bool)chk_Methodes_RefreshHostnames.IsChecked)
                {
                    dns_status = ScanStatus.running;
                    Status();
                    Task.Run(() => scanningMethode_DNS.Get_Host_and_Alias_From_IP(IPs));
                }

                if ((bool)chk_Methodes_Refresh_MacVendor.IsChecked)
                {
                    Task.Run(() => scanningMethode_ARP.SendARPRequestAsync(IPs));
                }
               
                if ((bool)chk_Methodes_ScanTCPPorts.IsChecked)
                {
                    tcp_port_Scan_status = ScanStatus.running;
                    Counted_TCPPortScans = IPs.Count;
                    Status();
                    Task.Run(() => scanningMethode_PortsTCP.ScanTCPPorts(IPs, new TimeSpan(0, 0, 0, 0, _TimeOut)));
                }
                                
                if ((bool)chk_Methodes_ScanUDPPorts.IsChecked)
                {
                    udp_port_Scan_status = ScanStatus.running;
                    Counted_UDPListener = IPs.Count;
                    Status();
                    //Task.Run(() => scanningMethode_PortsUDP.ScanUDPPorts(IPs));

                    List<OpenPorts> devicePorts = Task.Run(() => scanningMethode_PortsUDP.Get_All_UPD_Listener_as_List()).Result;                    
                }
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
                ssdp_status = ScanStatus.finished;
                Status();
            }));
        }



        private void ARP_Request_Task_Finished(object? sender, ARP_Request_Task_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + e.IP + "'").ToList();
                if (rows.ToList().Count == 0)
                {
                    DataRow row = _scannResults.ResultTable.NewRow();
                    row["IP"] = e.IP;
                    row["Mac"] = e.MAC;
                    row["Vendor"] = e.Vendor;
                }
                else
                {
                    int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);
                    _scannResults.ResultTable.Rows[rowIndex]["Mac"] = e.MAC;
                    _scannResults.ResultTable.Rows[rowIndex]["Vendor"] = e.Vendor;
                }
            });

            ++currentVendorCount;
            Status();
        }
        private void ARP_Request_Finished(object? sender, ARP_Request_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() => 
            {
                vendor_status = ScanStatus.finished;
                Status();
            });
        }



        private void DNS_GetHostAndAliasFromIP_Task_Finished(object? sender, GetHostAndAliasFromIP_Task_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + e.IP + "'").ToList();
                if (rows.ToList().Count == 0)
                {
                    _scannResults.ResultTable.Rows.Add(e.ResultRow.ItemArray);
                }
                else
                {
                    int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);
                    _scannResults.ResultTable.Rows[rowIndex]["Hostname"] = e.Hostname;
                    _scannResults.ResultTable.Rows[rowIndex]["Aliases"] = string.Join("\r\n", e.Aliases);
                }

                ++currentHostnameCount;
                CountedHostnames = e.CountedHostnames;
                Status();
            });
        }
        private void DNS_GetHostAndAliasFromIP_Finished(object? sender, GetHostAndAliasFromIP_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                dns_status = ScanStatus.finished;
                Status();

                if ((bool)chk_Methodes_Refresh_ReverseNSLookUp.IsChecked)
                {
                    scanningMethod_ReverseLookUp.ReverseLookupAsync(_scannResults.ResultTable.AsEnumerable().ToDictionary<DataRow, string, string>(row => row["IP"].ToString(), row => row["Hostname"].ToString()));
                }
            });
        }



        private void ReverseLookup_Task_Finished(object? sender, ReverseLookup_Task_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + e.IP + "'").ToList();

                if (rows.ToList().Count == 0)
                {
                    DataRow row = _scannResults.ResultTable.NewRow();
                    row["IP"] = e.IP;                    
                    row["ReverseLookUpStatus"] = e.ReverseLookUpStatus ? Properties.Resources.green_dot: Properties.Resources.red_dot;
                    row["ReverseLookUpIPs"] = e.ReverseLookUpIPs;
                    _scannResults.ResultTable.Rows.Add(row);
                }
                else
                {
                    int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);                    
                    _scannResults.ResultTable.Rows[rowIndex]["ReverseLookUpStatus"] = e.ReverseLookUpStatus ? Properties.Resources.green_dot : Properties.Resources.red_dot;
                    _scannResults.ResultTable.Rows[rowIndex]["ReverseLookUpIPs"] = e.ReverseLookUpIPs;
                }

                ++currentReverseLookupCount;
                Status();
            });
        }
        private void ReverseLookup_Finished(object? sender, ReverseLookup_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() => 
            {
                reverseLookup_status = ScanStatus.finished;
                Status();
            });
        }



        private void TcpPortScan_Task_Finished(object? sender, ScanningMethod_PortsTCP.TcpPortScan_Task_FinishedEventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                DataRow[] rows = _scannResults.ResultTable.Select("IP = '" + e.OpenPorts.IP + "'");
                if (rows.ToList().Count > 0)
                {
                    int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);
                    _scannResults.ResultTable.Rows[rowIndex]["OpenTCP_Ports"] = string.Join("; ", e.OpenPorts.openPorts);
                }
                else
                {
                    DataRow row = _scannResults.ResultTable.NewRow();
                    row["IP"] = e.OpenPorts.IP;
                    row["OpenTCP_Ports"] = string.Join("; ", e.OpenPorts.openPorts);
                    _scannResults.ResultTable.Rows.Add(row);
                }

                ++current_TCPPortScan_Count;
                Status();
            });
        }
        private void TcpPortScan_Finished(object? sender, ScanningMethod_PortsTCP.TcpPortScan_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                tcp_port_Scan_status = ScanStatus.finished;
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
                    //use ich you would like to see all UDP Listener incl. IPv6
                    //DataRow row = _scannResults.ResultTable.NewRow();
                    //row["IP"] = e.OpenPorts.IP;
                    //row["OpenUDP_Ports"] = string.Join("; ", e.OpenPorts.Ports);
                    //_scannResults.ResultTable.Rows.Add(row);
                    //++current_UDPPortScan_Count;
                }

                
                Status();
            });
        }
        private void UDPPortScan_Finished(object? sender, UDPPortScan_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                udp_port_Scan_status = ScanStatus.finished;
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
    }
}
