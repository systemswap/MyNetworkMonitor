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
        public ManageIPGroups(DataSet IPGroupDS, string IPGroupsXML)
        {
            InitializeComponent();

            _ipGroupsXML= IPGroupsXML;
            _ds = IPGroupDS;

            //mycollection.Source = mydt;
            //mycollection.GroupDescriptions.Add(new PropertyGroupDescription("GroupDescription"));

            
            //dt.Columns.Add("Name", typeof(string));
            //dt.Columns.Add("Age", typeof(int));
            //dt.Columns.Add("Group", typeof(int));
            //dt.Rows.Add(new object[3] { "Mary", 22, 1 });
            //dt.Rows.Add(new object[3] { "Peter", 24, 3 });
            //dt.Rows.Add(new object[3] { "Rose", 17, 1 });
            //dt.Rows.Add(new object[3] { "John", 19, 2 });
            //dt.Rows.Add(new object[3] { "Steven", 20, 1 });
            //dt.Rows.Add(new object[3] { "Tom", 20, 3 });

            DataContext = _ds.Tables["IPGroups"].DefaultView;
            
        }
        DataSet _ds  = new DataSet();
        CollectionViewSource mycollection = new CollectionViewSource();
        
        int indexOfCurrentRow= -1;
        string _ipGroupsXML = string.Empty;

        private void bt_SaveChanges_Click(object sender, RoutedEventArgs e)
        {
            if (!Directory.Exists(System.IO.Path.GetDirectoryName(_ipGroupsXML)))
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(_ipGroupsXML));
            }
            _ds.WriteXml(_ipGroupsXML);
            this.Close();
        }


        private void bt_EditRow_Click(object sender, RoutedEventArgs e)
        {
            var row = dg_IPGroups.SelectedItems[0];
            indexOfCurrentRow = dg_IPGroups.Items.IndexOf(row);

            chk_isActive.IsChecked = (bool)_ds.Tables["IPGroups"].Rows[indexOfCurrentRow]["isActive"];
            tb_Description.Text = _ds.Tables["IPGroups"].Rows[indexOfCurrentRow]["GroupDescription"].ToString();
            tb_DeviceDescription.Text = _ds.Tables["IPGroups"].Rows[indexOfCurrentRow]["DeviceDescription"].ToString();
            tb_firstIP.Text = _ds.Tables["IPGroups"].Rows[indexOfCurrentRow]["FirstIP"].ToString();
            tb_LastIP.Text = _ds.Tables["IPGroups"].Rows[indexOfCurrentRow]["LastIP"].ToString();
            tb_DNSServer.Text = _ds.Tables["IPGroups"].Rows[indexOfCurrentRow]["DNSServer"].ToString();
            chk_AutomaticScan.IsChecked = (bool)_ds.Tables["IPGroups"].Rows[indexOfCurrentRow]["AutomaticScan"];
            tb_ScanInterval.Text = _ds.Tables["IPGroups"].Rows[indexOfCurrentRow]["ScanIntervalMinutes"].ToString();
            _ = _ds.Tables["IPGroups"].Rows[indexOfCurrentRow]["GatewayIP"].ToString();
        }

        private void bt_addEntry_Click(object sender, RoutedEventArgs e)
        {
            if (indexOfCurrentRow == -1)
            {
                DataRow row = _ds.Tables["IPGroups"].NewRow();
                row["isActive"] = (bool)chk_isActive.IsChecked;
                row["GroupDescription"] = tb_Description.Text;
                row["DeviceDescription"] = tb_DeviceDescription.Text;
                row["FirstIP"] = tb_firstIP.Text;
                row["LastIP"] = tb_LastIP.Text;
                row["DNSServer"] = tb_DNSServer.Text;
                row["AutomaticScan"] = chk_AutomaticScan.IsChecked;
                row["ScanIntervalMinutes"] = tb_ScanInterval.Text;
                row["GatewayIP"] = string.Empty;

                _ds.Tables["IPGroups"].Rows.Add(row);
            }
            else
            {
                _ds.Tables["IPGroups"].Rows[indexOfCurrentRow]["isActive"] = (bool)chk_isActive.IsChecked;
                _ds.Tables["IPGroups"].Rows[indexOfCurrentRow]["GroupDescription"] = tb_Description.Text;
                _ds.Tables["IPGroups"].Rows[indexOfCurrentRow]["DeviceDescription"] = tb_DeviceDescription.Text;
                _ds.Tables["IPGroups"].Rows[indexOfCurrentRow]["FirstIP"] = tb_firstIP.Text;
                _ds.Tables["IPGroups"].Rows[indexOfCurrentRow]["LastIP"] = tb_LastIP.Text;
                _ds.Tables["IPGroups"].Rows[indexOfCurrentRow]["DNSServer"] = tb_DNSServer.Text;
                _ds.Tables["IPGroups"].Rows[indexOfCurrentRow]["AutomaticScan"] = chk_AutomaticScan.IsChecked;
                _ds.Tables["IPGroups"].Rows[indexOfCurrentRow]["ScanIntervalMinutes"] = tb_ScanInterval.Text;
                _ds.Tables["IPGroups"].Rows[indexOfCurrentRow]["GatewayIP"] = string.Empty;
            }
            indexOfCurrentRow = -1;
        }
    }
   
}
