
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace MyNetworkMonitor
{
    // install as Service https://www.youtube.com/watch?v=y64L-3HKuP0

    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            scanningMethode_ARP = new ScanningMethode_ARP();
            scanningMethods_Ping = new ScanningMethods_Ping();
            scanningMethode_SSDP_UPNP = new ScanningMethode_SSDP_UPNP();
            scanningMethode_DNS = new ScanningMethode_DNS();
            scanningMethod_ReverseLookUp = new ScanningMethod_ReverseLookUp();
            scanningMethode_Ports = new ScanningMethode_Sockets_Ports();

            supportMethods = new SupportMethods();

            dgv_Results.ItemsSource = _scannResults.ResultTable.DefaultView;
        }



        ScanResults _scannResults = new ScanResults();

        ScanningMethode_ARP scanningMethode_ARP;
        ScanningMethods_Ping scanningMethods_Ping;
        ScanningMethode_SSDP_UPNP scanningMethode_SSDP_UPNP;
        ScanningMethode_DNS scanningMethode_DNS;
        ScanningMethod_ReverseLookUp scanningMethod_ReverseLookUp;
        ScanningMethode_Sockets_Ports scanningMethode_Ports;

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

        ScanStatus port_status = ScanStatus.ignored;
        int current_PortScan_Count = 0;
        int Counted_PortScans = 0;


        public void Status()
        {
            lbl_ScanStatus.Content = string.Format($"ARP: {arp_status.ToString()}   Ping: {ping_status.ToString()} {currentPingCount}/{CountedPings}   SSDP: {ssdp_status.ToString()} {currentSSDPCount}/{CountedSSDPs}   Hostnames: {dns_status.ToString()} {currentHostnameCount.ToString()}/{CountedHostnames.ToString()}   Reverse Lookups: {reverseLookup_status.ToString()} {currentReverseLookupCount.ToString()}/{CountedReverseLookups.ToString()}   Mac: {vendor_status.ToString()} {currentVendorCount}/{CountedVendors}   Port:{port_status.ToString()} Scanned IP: {current_PortScan_Count}/{Counted_PortScans}");
        }
        #endregion

        private void dgv_Devices_OnAutoGeneratingColumn(object sender, DataGridAutoGeneratingColumnEventArgs e)
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

        private void bt_Scan_IP_Ranges_Click(object sender, RoutedEventArgs e)
        {
            DoWork();
        }


        public void DoWork()
        {
            scanningMethode_ARP.ARP_A_Finished += ARP_A_Finished;

            scanningMethods_Ping.Ping_Task_Finished += Ping_Task_Finished;
            scanningMethods_Ping.PingFinished += PingFinished_Event;

            scanningMethode_SSDP_UPNP.SSDP_NewDevice += SSDP_NewDevice;
            scanningMethode_SSDP_UPNP.SSDP_Scan_Finished += SSDP_Scan_Finished;

            scanningMethode_DNS.GetHostAndAliasFromIP_Task_Finished += DNS_GetHostAndAliasFromIP_Task_Finished;
            scanningMethode_DNS.GetHostAndAliasFromIP_Finished += DNS_GetHostAndAliasFromIP_Finished;

            scanningMethode_ARP.ARP_Request_Task_Finished += ARP_Request_Task_Finished;
            scanningMethode_ARP.ARP_Request_Finished += ARP_Request_Finished;

            scanningMethod_ReverseLookUp.ReverseLookup_Task_Finished += ReverseLookup_Task_Finished;
            scanningMethod_ReverseLookUp.ReverseLookup_Finished += ReverseLookup_Finished;

            scanningMethode_Ports.TcpPortScan_Task_Finished += TcpPortScan_Task_Finished;
            scanningMethode_Ports.TcpPortScan_Finished += TcpPortScan_Finished;



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

            current_PortScan_Count = 0;
            Counted_PortScans = 0;



            List<string> IPs = new List<string>();

            string myIP = new SupportMethods().GetLocalIPv4(System.Net.NetworkInformation.NetworkInterfaceType.Ethernet);

            myIP = "192.168.178.1";
            //myIP = "10.126.75.1";
            //myIP = "172.27.6.25";
            myIP = String.Join(".", myIP.Split(".")[0], myIP.Split(".")[1], myIP.Split(".")[2], "{0}");

            for (int i = 2; i < 254; i++)
            {
                IPs.Add(string.Format(myIP, i));
            }


            foreach (DataRow row in _scannResults.ResultTable.Rows)
            {
                if ((bool)chk_Methodes_ARP.IsChecked) row["ARPStatus"] = null;
                if ((bool)chk_Methodes_Ping.IsChecked) row["PingStatus"] = null;
                if ((bool)chk_Methodes_SSDP.IsChecked) row["SSDPStatus"] = null;

                row["ResponseTime"] = string.Empty;

                if ((bool)chk_Methodes_RefreshHostnames.IsChecked)
                {
                    row["Hostname"] = string.Empty;
                    row["Aliases"] = string.Empty;
                }


                if ((bool)chk_Methodes_Refresh_ReverseNSLookUp.IsChecked)
                {
                    row["ReverseLookUpStatus"] = null;
                    row["ReverseLookUpIPs"] = string.Empty;
                }
            }

            if ((bool)chk_Methodes_ARP.IsChecked)
            {
                arp_status = ScanStatus.running;
                Status();
                scanningMethode_ARP.ARP_A(_scannResults);
            }
            if ((bool)chk_Methodes_Ping.IsChecked)
            {
                ping_status= ScanStatus.running;
                CountedPings = IPs.Count;
                Status();
                scanningMethods_Ping.PingIPsAsync(IPs, null, 1000, false);
            }
            if ((bool)chk_Methodes_SSDP.IsChecked)
            {
                ssdp_status= ScanStatus.running;
                CountedSSDPs = IPs.Count;
                Status();
                Task.Run(() => scanningMethode_SSDP_UPNP.ScanForSSDP());
            }
            //if ((bool)chk_Methodes_Ports.IsChecked)
            //{                   
            //    port_status= ScanStatus.running;
            //    Counted_PortScans= IPs.Count;
            //    Status();
            //    Task.Run(() => scanningMethode_Ports.ScanTCPPorts(IPs));
            //}
        }

        private void ARP_A_Finished(object? sender, ARP_A_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
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

                List<string> IPs = _scannResults.ResultTable.AsEnumerable().Select(p => p.Field<string>("IP")).ToList();

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
                if ((bool)chk_Methodes_Ports.IsChecked)
                {
                    port_status = ScanStatus.running;
                    Counted_PortScans = IPs.Count;
                    Status();
                    Task.Run(() => scanningMethode_Ports.ScanTCPPorts(IPs));
                }
            });
        }



        private void SSDP_NewDevice(object? sender, SSDP_Device_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + e.IP + "'").ToList();

                if (rows.Count() == 0)
                {
                    DataRow row = _scannResults.ResultTable.NewRow();

                    row["SendAlert"] = false;
                    row["SSDPStatus"] = Properties.Resources.green_dot;
                    row["IP"] = e.IP;
                    row["ResponseTime"] = "";

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
                    _scannResults.ResultTable.Rows.Add(e.ResultRow);
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



        private void TcpPortScan_Task_Finished(object? sender, TcpPortScan_Task_FinishedEventArgs e)
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

                ++current_PortScan_Count;
                Status();
            });
        }
        private void TcpPortScan_Finished(object? sender, TcpPortScan_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                port_status = ScanStatus.finished;
                Status();
            });
        }
    }
}
