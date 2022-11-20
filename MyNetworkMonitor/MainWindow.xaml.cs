
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net;
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

            scanningMethode_ARP = new ScanningMethode_ARP(_scannResults);
            scanningMethods_Ping = new ScanningMethods_Ping(_scannResults);
            scanningMethode_SSDP_UPNP = new ScanningMethode_SSDP_UPNP(_scannResults);
            scanningMethod_ReverseLookUp = new ScanningMethod_ReverseLookUp(_scannResults);
            scanningMethode_DNS = new ScanningMethode_DNS(_scannResults);

            supportMethods = new SupportMethods();

            dgv_Results.ItemsSource = _scannResults.ResultTable.DefaultView;
        }

        ScanResults _scannResults = new ScanResults();

        ScanningMethode_ARP scanningMethode_ARP;
        ScanningMethods_Ping scanningMethods_Ping;
        ScanningMethode_SSDP_UPNP scanningMethode_SSDP_UPNP;
        ScanningMethode_DNS scanningMethode_DNS;

        SupportMethods supportMethods;

        ScanningMethod_ReverseLookUp scanningMethod_ReverseLookUp;

        private void dgv_Devices_OnAutoGeneratingColumn(object sender, DataGridAutoGeneratingColumnEventArgs e)
        {
            if (e.PropertyName == "ARP")
            {
                // replace text column with image column
                e.Column = new DataGridTemplateColumn
                {
                    // searching for predefined tenplate in Resources
                    CellTemplate = (sender as DataGrid).Resources["ARP"] as DataTemplate,
                    HeaderTemplate = e.Column.HeaderTemplate,
                    Header = e.Column.Header
                };
            }

            if (e.PropertyName == "Ping")
            {
                // replace text column with image column
                e.Column = new DataGridTemplateColumn
                {
                    // searching for predefined tenplate in Resources
                    CellTemplate = (sender as DataGrid).Resources["Ping"] as DataTemplate,
                    HeaderTemplate = e.Column.HeaderTemplate,
                    Header = e.Column.Header
                };
            }

            if (e.PropertyName == "SSDP")
            {
                // replace text column with image column
                e.Column = new DataGridTemplateColumn
                {
                    // searching for predefined tenplate in Resources
                    CellTemplate = (sender as DataGrid).Resources["SSDP"] as DataTemplate,
                    HeaderTemplate = e.Column.HeaderTemplate,
                    Header = e.Column.Header
                };
            }

            if (e.PropertyName == "ReverseLookUp")
            {
                // replace text column with image column
                e.Column = new DataGridTemplateColumn
                {
                    // searching for predefined tenplate in Resources
                    CellTemplate = (sender as DataGrid).Resources["ReverseLookUp"] as DataTemplate,
                    HeaderTemplate = e.Column.HeaderTemplate,
                    Header = e.Column.Header
                };
            }
        }

        private void bt_Scan_IP_Ranges_Click(object sender, RoutedEventArgs e)
        {
            scanningMethods_Ping.CustomEvent_PingProgress += ScanningMethods_CustomEvent_PingProgress;
            scanningMethods_Ping.CustomEvent_PingFinished += ScanningMethods_CustomEvent_PingFinished;

            scanningMethode_DNS.CustomEvent_Finished_DNS_Query += ScanningMethode_DNS_CustomEvent_Finished_DNS_Query;

            string myIP = new SupportMethods().GetLocalIPv4(System.Net.NetworkInformation.NetworkInterfaceType.Ethernet);

            myIP = "192.168.178.1";
            myIP = String.Join(".", myIP.Split(".")[0], myIP.Split(".")[1], myIP.Split(".")[2], "{0}");

            List<string> IPs = new List<string>();

            for (int i = 1; i < 255; i++)
            {
                IPs.Add(string.Format(myIP, i));
            }

            if ((bool)chk_Methodes_ARP.IsChecked)
            {
                scanningMethode_ARP.ARP_A();
            }
            if ((bool)chk_Methodes_Ping.IsChecked)
            {
                scanningMethods_Ping.PingIPsAsync(IPs, null, 1000, false);
            }
            if ((bool)chk_Methodes_SSDP.IsChecked)
            {
                scanningMethode_SSDP_UPNP.ScanForSSDP();
            }
            if ((bool)chk_Methodes_Ports.IsChecked)
            {

            }
        }

        private void ScanningMethode_DNS_CustomEvent_Finished_DNS_Query(object? sender, Finished_DNS_Query_EventArgs e)
        {
            if ((bool)chk_Methodes_ReverseNSLookUp.IsChecked)
            {
                scanningMethod_ReverseLookUp.HostToIP();
            }
        }

        private void ScanningMethods_CustomEvent_PingProgress(object? sender, PingProgressEventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                //dt.Rows.Add(e.PingResultsRow);
            });
        }

        private void ScanningMethods_CustomEvent_PingFinished(object? sender, PingFinishedEventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                //dgv_Results.ItemsSource = e.PingResults.DefaultView;
            });
            MacFromIP();
            Hostname_And_Aliases_From_IP();
        }

        public void Hostname_And_Aliases_From_IP()
        {
            if (_scannResults.ResultTable.Rows.Count > 0)
            {
                scanningMethode_DNS.Get_Host_and_Alias_From_IP(_scannResults.ResultTable.AsEnumerable().Select(p => p.Field<string>("IP")).ToList());
            }
        }

        public void MacFromIP()
        {
            if (_scannResults.ResultTable.Rows.Count > 0)
            {
                foreach (DataRow row in _scannResults.ResultTable.Rows)
                {
                    if (string.IsNullOrEmpty(row["MAC"].ToString()))
                    {
                        string mac = scanningMethode_ARP.SendArpRequest(IPAddress.Parse(row["IP"].ToString()));
                        row["MAC"] = mac;

                        if (!string.IsNullOrEmpty(mac))
                        {
                            row["Vendor"] = supportMethods.GetVendorFromMac(mac).ToList()[0];
                        }
                    }
                }
            }
        }

      
    }    
}
