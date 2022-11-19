using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    internal class ScanningMethod_ReverseLookUp
    {
        public ScanningMethod_ReverseLookUp(ScanResults scanResults)
        {
            _scannResults = scanResults;
        }

        ScanResults _scannResults;

        public void HostToIP()
        {
            foreach(DataRow row in _scannResults.ResultTable.Rows)
            {
                if (!string.IsNullOrEmpty(row["Hostname"].ToString()))
                {
                    string host = row["Hostname"].ToString();

                    try
                    {
                        var ip = Dns.GetHostByName(row["Hostname"].ToString()).AddressList.ToList();


                        int rowIndex = _scannResults.ResultTable.Rows.IndexOf(row);

                        if (ip.Count == 1 && _scannResults.ResultTable.Rows[rowIndex]["IP"].ToString() == ip[0].ToString())
                        {
                            _scannResults.ResultTable.Rows[rowIndex]["ReverseLookUp"] = Properties.Resources.green_dot;
                        }
                        if (ip.Count != 1)
                        {
                            _scannResults.ResultTable.Rows[rowIndex]["ReverseLookUp"] = Properties.Resources.red_dot;

                            if (ip == null)
                            {
                                _scannResults.ResultTable.Rows[rowIndex]["ReverseLookUpIPs"] = "no IPs registred";
                            }
                            else
                            {
                                _scannResults.ResultTable.Rows[rowIndex]["ReverseLookUpIPs"] = string.Join("\r\n", ip);
                            }
                        }
                    }
                    catch (Exception)
                    {
                        
                    }                    
                }
            }
            
        }
    }
}
