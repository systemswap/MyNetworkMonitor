using Rssdp;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace MyNetworkMonitor
{
    // install as Service https://www.youtube.com/watch?v=y64L-3HKuP0

    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();

            dgv_Results.ItemsSource = scanningMethods.NetworkResultsTable.DefaultView;
        }

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
        }

        ScanningMethods_Ping scanningMethods = new ScanningMethods_Ping();


        private void bt_Scan_IP_Ranges_Click(object sender, RoutedEventArgs e)
        {
            scanningMethods.CustomEvent_PingProgress += ScanningMethods_CustomEvent_PingProgress;
            scanningMethods.CustomEvent_PingFinished += ScanningMethods_CustomEvent_PingFinished;

            string myIP = scanningMethods.GetLocalIPv4(System.Net.NetworkInformation.NetworkInterfaceType.Ethernet);

            myIP = "192.168.178.1";
            myIP = String.Join(".", myIP.Split(".")[0], myIP.Split(".")[1], myIP.Split(".")[2], "{0}");

            List<string> IPs = new List<string>();

            for (int i = 1; i < 255; i++)
            {
                IPs.Add(string.Format(myIP, i));
            }

            scanningMethods.PingIPsAsync(IPs, null, 100, false);
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
            //https://blog.noser.com/geraetesuche-mit-ssdp-in-net-im-lokalen-netzwerk/

            //var ipAddresses = scanningMethods.NetworkResultsTable.AsEnumerable().Select(r => r.Field<string>("IPs")).ToList();

            //foreach (var netIf in NetworkInterface.GetAllNetworkInterfaces())
            //{
            //    if (netIf.NetworkInterfaceType.Equals(NetworkInterfaceType.Ethernet) &&
            //        netIf.OperationalStatus.Equals(OperationalStatus.Up) &&
            //        !netIf.Name.Contains("vEthernet"))
            //    {
            //        foreach (var ip in netIf.GetIPProperties().UnicastAddresses)
            //        {
            //            if (ip.Address.AddressFamily.Equals(AddressFamily.InterNetwork))
            //            {
            //                var ipAddress = ip.Address.ToString();
            //                Console.WriteLine($"{netIf.Name}: {ipAddress}'");
            //                ipAddresses.Add(ipAddress);
            //            }
            //        }
            //    }
            //}

            var searchTarget = "urn:schemas-upnp-org:device:WANDevice:1";
            var devices = new ConcurrentBag<Discovered​Ssdp​Device>();

                using (var deviceLocator = new SsdpDeviceLocator())
                {
                    var foundDevices =  await deviceLocator.SearchAsync();

                    foreach (var foundDevice in foundDevices)
                    {
                        if(scanningMethods.NetworkResultsTable.AsEnumerable().Where(c => c.Field<string>("IP").Equals(foundDevice.DescriptionLocation.Host)).Count() == 0)
                        {
                            DataRow row = scanningMethods.NetworkResultsTable.NewRow();

                            row["SendAlert"] = false;
                            row["SSDP"] = Properties.Resources.green_dot;
                            row["IP"] = foundDevice.DescriptionLocation.Host;
                            row["ResponseTime"] = "";
                            scanningMethods.NetworkResultsTable.Rows.Add(row);
                        }
                        else
                        {
                            //wenn bereits vorhanden dann setze SSDP auf green_dot
                        }
                        //Debug.WriteLine($"Device: IP={foundDevice.DescriptionLocation.Host}");
                        //Debug.WriteLine($"Device: usn={foundDevice.Usn}");
                        //devices.Add(foundDevice);
                    }
                }
        }
    }
}
