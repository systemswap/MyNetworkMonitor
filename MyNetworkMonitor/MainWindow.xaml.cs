
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net;
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

            scanningMethode_ARP = new ScanningMethode_ARP(_scannResults);
            scanningMethods_Ping = new ScanningMethods_Ping(_scannResults);
            scanningMethode_SSDP_UPNP = new ScanningMethode_SSDP_UPNP(_scannResults);
            scanningMethode_DNS = new ScanningMethode_DNS(_scannResults);
            scanningMethod_ReverseLookUp = new ScanningMethod_ReverseLookUp(_scannResults);

            supportMethods = new SupportMethods();

            dgv_Results.ItemsSource = _scannResults.ResultTable.DefaultView;
        }

        ScanResults _scannResults = new ScanResults();

        ScanningMethode_ARP scanningMethode_ARP;
        ScanningMethods_Ping scanningMethods_Ping;
        ScanningMethode_SSDP_UPNP scanningMethode_SSDP_UPNP;
        ScanningMethode_DNS scanningMethode_DNS;
        ScanningMethod_ReverseLookUp scanningMethod_ReverseLookUp;

        SupportMethods supportMethods;

        

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

        private async void bt_Scan_IP_Ranges_Click(object sender, RoutedEventArgs e)
        {
            await Task.Run(() => DoWork());
        }

        private void ScanningMethode_DNS_CustomEvent_Finished_DNS_Query(object? sender, DNS_Finished_EventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                
            });

            if ((bool)chk_Methodes_Refresh_ReverseNSLookUp.IsChecked)
            {
                scanningMethod_ReverseLookUp.ReverseLookupAsync();
            }
        }

        private async void ScanningMethods_CustomEvent_PingFinished(object? sender, PingFinishedEventArgs e)
        {
            Dispatcher.BeginInvoke(() =>
            {
                //dgv_Results.ItemsSource = e.PingResults.DefaultView;
            });

            if((bool)chk_Methodes_RefreshHostnames.IsChecked) await scanningMethode_DNS.Get_Host_and_Alias_From_IP(_scannResults.ResultTable.AsEnumerable().Select(p => p.Field<string>("IP")).ToList());

            if ((bool)chk_Methodes_Refresh_MacVendor.IsChecked) await scanningMethode_ARP.SendARPRequestAsync(_scannResults.ResultTable.AsEnumerable().Select(p => p.Field<string>("IP")).ToList());
        }



        public async Task DoWork()
        {
            scanningMethods_Ping.CustomEvent_PingFinished += ScanningMethods_CustomEvent_PingFinished;
            scanningMethode_DNS.CustomEvent_DNS_Finished += ScanningMethode_DNS_CustomEvent_Finished_DNS_Query;

            string myIP = new SupportMethods().GetLocalIPv4(System.Net.NetworkInformation.NetworkInterfaceType.Ethernet);

            //myIP = "192.168.178.1";
            myIP = "10.126.75.1";
            myIP = String.Join(".", myIP.Split(".")[0], myIP.Split(".")[1], myIP.Split(".")[2], "{0}");

            List<string> IPs = new List<string>();

            Dispatcher.BeginInvoke(() =>
            {
                foreach (DataRow row in _scannResults.ResultTable.Rows)
            {
                if ((bool)chk_Methodes_ARP.IsChecked) row["ARP"] = null;
                if ((bool)chk_Methodes_Ping.IsChecked) row["Ping"] = null;
                if ((bool)chk_Methodes_SSDP.IsChecked) row["SSDP"] = null;

                row["ResponseTime"] = string.Empty;

                if ((bool)chk_Methodes_RefreshHostnames.IsChecked)
                {
                    row["Hostname"] = string.Empty;
                    row["Aliases"] = string.Empty;
                }


                if ((bool)chk_Methodes_Refresh_ReverseNSLookUp.IsChecked)
                {
                    row["ReverseLookUp"] = null;
                    row["ReverseLookUpIPs"] = string.Empty;
                }
            }

            for (int i = 2; i < 100; i++)
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
            });
        }
    }    
}
