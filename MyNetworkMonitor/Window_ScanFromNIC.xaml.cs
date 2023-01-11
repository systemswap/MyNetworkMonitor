using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace MyNetworkMonitor
{
    /// <summary>
    /// Interaction logic for Window_ScanFromNIC.xaml
    /// </summary>
    public partial class Window_ScanFromNIC : Window
    {
        public Window_ScanFromNIC(List<NicInfo> NicInfos)
        {
            InitializeComponent();
            nicInfos = NicInfos;

            cb_NetworkAdapters.ItemsSource = nicInfos.Select(n => n.NicName).ToList();
            cb_NetworkAdapters.SelectedIndex = 0;
        }

        bool TextChangedByComboBox = false;

        List<NicInfo> nicInfos = new List<NicInfo>();

        private void cb_NetworkAdapters_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            NicInfo n = new NicInfo();
            n = nicInfos.Where(name => name.NicName == cb_NetworkAdapters.SelectedItem).FirstOrDefault();

            TextChangedByComboBox = true;

            tb_AdapterIP.Text = n.IPv4;
            tb_AdapterSubnetMask.Text = n.IPv4Mask;
            tb_Adapter_FirstSubnetIP.Text = n.FirstSubnetIP;
            tb_Adapter_LastSubnetIP.Text = n.LastSubnetIP;
            lb_IPsToScan.Content = n.IPsCount;

            TextChangedByComboBox = false;
        }



        private void bt_StartScan_Click(object sender, RoutedEventArgs e)
        {
            IpRanges.IPRange range = new IpRanges.IPRange(tb_Adapter_FirstSubnetIP.Text, tb_Adapter_LastSubnetIP.Text);
            
            foreach (var item in range.GetAllIP())
            {
                IPToScan toScan = new IPToScan();
                toScan.IPGroupDescription = "@NetworkAdapters";
                toScan.DeviceDescription = cb_NetworkAdapters.SelectedItem.ToString() + " Adapter";
                toScan.IPorHostname = item.ToString();

                _IPsToScan.Add(toScan);
            }
            this.Close();
        }

        private List<IPToScan> _IPsToScan = new List<IPToScan>();
        public List<IPToScan> IPsToScan { get { return _IPsToScan; } }

        private async void tb_Adapter_FirstSubnetIP_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (TextChangedByComboBox) return;
            
            try
            {
                lb_IPsToScan.Content = "calc. number of IPs";              
                lb_IPsToScan.Content = new IpRanges.IPRange().NumberOfIPsInRange(tb_Adapter_FirstSubnetIP.Text, tb_Adapter_LastSubnetIP.Text);
            }
            catch (Exception)
            {

                lb_IPsToScan.Content = "...";
            }
        }

        

        private async void tb_Adapter_LastSubnetIP_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (TextChangedByComboBox) return;

            try
            {
                lb_IPsToScan.Content = "calc. number of IPs";
                lb_IPsToScan.Content = new IpRanges.IPRange().NumberOfIPsInRange(tb_Adapter_FirstSubnetIP.Text, tb_Adapter_LastSubnetIP.Text);
            }
            catch (Exception)
            {

                lb_IPsToScan.Content = "...";
            }
        }

        private void bt_cancel_Click(object sender, RoutedEventArgs e)
        {
            this.Close();
        }
    }
}


