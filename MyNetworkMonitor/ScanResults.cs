using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    internal class ScanResults
    {
        public ScanResults()
        {
            dt_NetworkResults.Columns.Add("ARPStatus", typeof(byte[]));
            dt_NetworkResults.Columns.Add("PingStatus", typeof(byte[]));
            dt_NetworkResults.Columns.Add("SSDPStatus", typeof(byte[]));
            //dt_NetworkResults.Columns.Add("SendAlert", typeof(bool));
            dt_NetworkResults.Columns.Add("IP", typeof(string));
            dt_NetworkResults.Columns.Add("ResponseTime", typeof(string));
            dt_NetworkResults.Columns.Add("InternalName", typeof(string));
            dt_NetworkResults.Columns.Add("Hostname", typeof(string));            
            dt_NetworkResults.Columns.Add("Aliases", typeof(string));
            dt_NetworkResults.Columns.Add("ReverseLookUpStatus", typeof(byte[]));
            dt_NetworkResults.Columns.Add("ReverseLookUpIPs", typeof(string));
            dt_NetworkResults.Columns.Add("OpenTCP_Ports", typeof(string));
            dt_NetworkResults.Columns.Add("OpenUDP_Ports", typeof(string));
            dt_NetworkResults.Columns.Add("Comment", typeof(string));
            dt_NetworkResults.Columns.Add("Mac", typeof(string));
            dt_NetworkResults.Columns.Add("Vendor", typeof(string));
            dt_NetworkResults.Columns.Add("Exception", typeof(string));
        }

        public DataTable dt_NetworkResults = new DataTable();

        public DataTable ResultTable 
        { 
            get { return dt_NetworkResults; }
            set { dt_NetworkResults = value; }
        }
    }
}
