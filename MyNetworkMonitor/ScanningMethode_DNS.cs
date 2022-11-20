using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    internal class ScanningMethode_DNS
    {
        public ScanningMethode_DNS(ScanResults scanResults)
        {
            _scannResults = scanResults;
        }

        ScanResults _scannResults;

        public event EventHandler<Finished_DNS_Query_EventArgs>? CustomEvent_Finished_DNS_Query;

        public async void Get_Host_and_Alias_From_IP(List<string> IPs)
        {
            if (_scannResults.ResultTable.Rows.Count == 0)
            {
                return;
            }


            var tasks = new List<Task>();

            foreach (var ip in IPs)
            {
                
                var task =DNS_Task(ip);
                tasks.Add(task);
            }
            await Task.WhenAll(tasks);


            //foreach (string ip in IPs)
            //{
            //    List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + ip + "'").ToList();
            //    IPHostEntry entry = new IPHostEntry();

            //    try
            //    {
            //        entry = (await Dns.GetHostEntryAsync(IPAddress.Parse(ip)));
                    
            //    }
            //    catch (Exception)
            //    {
            //        continue;
            //    }

            //    if (rows.Count == 0)
            //    {
            //        DataRow row = _scannResults.ResultTable.NewRow();

            //        row["Hostname"] = entry.HostName;
            //        row["Aliases"] = string.Join("\r\n", entry.Aliases);
            //        _scannResults.ResultTable.Rows.Add(row);
            //    }
            //    else
            //    {
            //        int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);
            //        _scannResults.ResultTable.Rows[rowIndex]["Hostname"] = entry.HostName;
            //        _scannResults.ResultTable.Rows[rowIndex]["Aliases"] = string.Join("\r\n", entry.Aliases);
            //    }
            //}

            if(CustomEvent_Finished_DNS_Query!= null) 
            { 
                CustomEvent_Finished_DNS_Query(this, new Finished_DNS_Query_EventArgs(true)); 
            }
        }

        private async Task DNS_Task(string ip)
        {
            List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + ip + "'").ToList();
            IPHostEntry entry = new IPHostEntry();

            try
            {
                entry = await Dns.GetHostEntryAsync(IPAddress.Parse(ip));

                if (rows.Count == 0)
                {
                    DataRow row = _scannResults.ResultTable.NewRow();

                    row["Hostname"] = entry.HostName;
                    row["Aliases"] = string.Join("\r\n", entry.Aliases);
                    _scannResults.ResultTable.Rows.Add(row);
                }
                else
                {
                    int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);
                    _scannResults.ResultTable.Rows[rowIndex]["Hostname"] = entry.HostName;
                    _scannResults.ResultTable.Rows[rowIndex]["Aliases"] = string.Join("\r\n", entry.Aliases);
                }
            }
            catch (Exception ex)
            {
                
            }
        }
    }

    public class Finished_DNS_Query_EventArgs : EventArgs
    {
        private bool _finished = false;
        public bool FinishedDNSQuery { get { return _finished; } }
        public Finished_DNS_Query_EventArgs(bool Finished_DNS_Query)
        {
            _finished = Finished_DNS_Query;
        }
    }
}
