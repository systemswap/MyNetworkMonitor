using SharpPcap;
using System;
using System.Collections.Generic;
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

            scanningMethods_Ping = new ScanningMethods_Ping(_scannResults);
            scanningMethode_SSDP_UPNP = new ScanningMethode_SSDP_UPNP(_scannResults);
            scanningMethod_ReverseLookUp = new ScanningMethod_ReverseLookUp(_scannResults);


            dgv_Results.ItemsSource = _scannResults.ResultTable.DefaultView;
        }

        ScanResults _scannResults = new ScanResults();
        ScanningMethods_Ping scanningMethods_Ping;
        ScanningMethode_SSDP_UPNP scanningMethode_SSDP_UPNP;

        ScanningMethod_ReverseLookUp scanningMethod_ReverseLookUp;

        private void dgv_Devices_OnAutoGeneratingColumn(object sender, DataGridAutoGeneratingColumnEventArgs e)
        {
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

            }
            if ((bool)chk_Methodes_Ping.IsChecked)
            {
                scanningMethods_Ping.PingIPsAsync(IPs, null, 100, false);
            }
            if ((bool)chk_Methodes_SSDP.IsChecked)
            {
                scanningMethode_SSDP_UPNP.ScanForSSDP();
            }
            if ((bool)chk_Methodes_Ports.IsChecked)
            {

            }
            if ((bool)chk_Methodes_ReverseNSLookUp.IsChecked && ((bool)chk_Methodes_ARP.IsChecked || (bool)chk_Methodes_Ping.IsChecked || (bool)chk_Methodes_SSDP.IsChecked))
            {
                scanningMethod_ReverseLookUp.HostToIP();
            }

            var bla = IPInfo.GetIPInfo();
           
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
                dgv_Results.ItemsSource = e.PingResults.DefaultView;
            });
        }

        private async void Button_Click(object sender, RoutedEventArgs e)
        {
           
        }
    }    
}
