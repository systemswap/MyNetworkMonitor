using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Data;
using System.IO;
using System.Linq;
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
    /// Interaction logic for IPGroups.xaml
    /// </summary>
    public partial class ManageIPGroups : Window
    {
        public ManageIPGroups(DataTable IPGroupDT, string IPGroupsXMLFile)
        {
            InitializeComponent();

            _ipGroupsXMLFile= IPGroupsXMLFile;
            _dt = IPGroupDT;

            DataContext = _dt.DefaultView;
        }
        DataTable _dt  = new DataTable();
        
        int indexOfCurrentRow= -1;
        string _ipGroupsXMLFile = string.Empty;

        private void bt_SaveChanges_Click(object sender, RoutedEventArgs e)
        {
            if (!Directory.Exists(System.IO.Path.GetDirectoryName(_ipGroupsXMLFile)))
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(_ipGroupsXMLFile));
            }
            _dt.WriteXml(_ipGroupsXMLFile, XmlWriteMode.WriteSchema);
            this.Close();
        }


        private void bt_EditRow_Click(object sender, RoutedEventArgs e)
        {
            // Die aktuell ausgewählte Zeile aus dem DataGrid holen
            var row = dg_IPGroups.SelectedItems[0];

            // Werte aus der DataGrid-Zeile extrahieren
            string selectedIPGroup = ((DataRowView)row)["IPGroupDescription"].ToString();
            string selectedDeviceDescription = ((DataRowView)row)["DeviceDescription"].ToString();
            string selectedFirstIP = ((DataRowView)row)["FirstIP"].ToString();

            // Die richtige Zeile in der DataTable suchen
            DataRow[] foundRows = _dt.Select(
                $"IPGroupDescription = '{selectedIPGroup}' AND DeviceDescription = '{selectedDeviceDescription}' AND FirstIP = '{selectedFirstIP}'"
            );

            
                DataRow selectedRow = foundRows[0];

                // Werte aus der gefundenen DataRow setzen
                chk_isActive.IsChecked = Convert.ToBoolean(selectedRow["isActive"]);
                tb_Description.Text = selectedRow["IPGroupDescription"].ToString();
                tb_DeviceDescription.Text = selectedRow["DeviceDescription"].ToString();
                tb_firstIP.Text = selectedRow["FirstIP"].ToString();
                tb_LastIP.Text = selectedRow["LastIP"].ToString();
                tb_Domain.Text = selectedRow["Domain"].ToString();
                tb_DNSServer.Text = selectedRow["DNSServers"].ToString();
                tb_IPWhereNetworkMonitorRunAsGateway.Text = selectedRow["NMGatewayIP"].ToString();
                tb_GatewayPort.Text = selectedRow["NMGatewayPort"].ToString();
                chk_AutomaticScan.IsChecked = Convert.ToBoolean(selectedRow["AutomaticScan"]);
                tb_ScanInterval.Text = selectedRow["ScanIntervalMinutes"].ToString();
          

        }

        private void bt_addEntry_Click(object sender, RoutedEventArgs e)
        {
            if (indexOfCurrentRow == -1)
            {
                DataRow row = _dt.NewRow();
                row["isActive"] = Convert.ToBoolean(chk_isActive.IsChecked);
                row["IPGroupDescription"] = tb_Description.Text;
                row["DeviceDescription"] = tb_DeviceDescription.Text;
                row["FirstIP"] = tb_firstIP.Text;
                row["LastIP"] = tb_LastIP.Text;
                row["Domain"] = tb_Domain.Text;
                row["DNSServers"] = tb_DNSServer.Text;
                row["NMGatewayIP"] = tb_IPWhereNetworkMonitorRunAsGateway.Text;
                row["NMGatewayPort"] = tb_GatewayPort.Text;
                row["AutomaticScan"] = Convert.ToBoolean(chk_AutomaticScan.IsChecked);
                row["ScanIntervalMinutes"] = tb_ScanInterval.Text;

                _dt.Rows.Add(row);
            }
            else
            {
                _dt.Rows[indexOfCurrentRow]["isActive"] = Convert.ToBoolean(chk_isActive.IsChecked);
                _dt.Rows[indexOfCurrentRow]["IPGroupDescription"] = tb_Description.Text;
                _dt.Rows[indexOfCurrentRow]["DeviceDescription"] = tb_DeviceDescription.Text;
                _dt.Rows[indexOfCurrentRow]["FirstIP"] = tb_firstIP.Text;
                _dt.Rows[indexOfCurrentRow]["LastIP"] = tb_LastIP.Text;
                _dt.Rows[indexOfCurrentRow]["Domain"] = tb_Domain.Text;
                _dt.Rows[indexOfCurrentRow]["DNSServers"] = tb_DNSServer.Text;
                _dt.Rows[indexOfCurrentRow]["NMGatewayIP"] = tb_IPWhereNetworkMonitorRunAsGateway.Text;
                _dt.Rows[indexOfCurrentRow]["NMGatewayPort"] = tb_GatewayPort.Text;
                _dt.Rows[indexOfCurrentRow]["AutomaticScan"] = Convert.ToBoolean(chk_AutomaticScan.IsChecked);
                _dt.Rows[indexOfCurrentRow]["ScanIntervalMinutes"] = tb_ScanInterval.Text;
            }
            indexOfCurrentRow = -1;
        }

        private void bt_deleteEntry_Click(object sender, RoutedEventArgs e)
        {
            if (dg_IPGroups.SelectedItems.Count > 0)
            {
                DataRowView selectedRowView = (DataRowView)dg_IPGroups.SelectedItems[0];
                DataRow selectedRow = selectedRowView.Row;

                string rowContent = string.Join(" // ", selectedRow.ItemArray);  // Alle Spalten in einen String zusammenfügen

                MessageBoxResult result = MessageBox.Show($"Delete the entry: {rowContent}", "Delete row", MessageBoxButton.YesNo);

                if (result == MessageBoxResult.Yes)
                {
                    selectedRow.Delete();  // Direkt die DataRow löschen
                }
            }
        }

        private void Window_Closing(object sender, CancelEventArgs e)
        {

        }
    }
   
}
