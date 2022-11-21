using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Threading;

namespace MyNetworkMonitor
{
    internal class ScanningMethode_DNS
    {
        public ScanningMethode_DNS(ScanResults scanResults)
        {
            _scannResults = scanResults;
        }

        ScanResults _scannResults;

        public event EventHandler<DNS_Task_Finished_EventArgs>? CustomEvent_DNSTaskFinished;
        public event EventHandler<DNS_Finished_EventArgs>? CustomEvent_DNS_Finished;

        public async Task Get_Host_and_Alias_From_IP(List<string> IPs)
        {
            if (_scannResults.ResultTable.Rows.Count == 0)
            {
                return;
            }

            var tasks = new List<Task>();

            foreach (var ip in IPs)
            {
                var task = DNS_Task(ip);
                tasks.Add(task);
            }

            await Task.WhenAll(tasks);
            if (CustomEvent_DNS_Finished != null)
            {
                CustomEvent_DNS_Finished(this, new DNS_Finished_EventArgs(true));
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

    public class DNS_Task_Finished_EventArgs : EventArgs
    {
        private bool _finished = false;
        public bool TaskFinished { get { return _finished; } }
        public DNS_Task_Finished_EventArgs(bool Finished_DNS_Query)
        {
            _finished = Finished_DNS_Query;
        }
    }

    public class DNS_Finished_EventArgs : EventArgs
    {
        private bool _finished = false;
        public bool FinishedDNSQuery { get { return _finished; } }
        public DNS_Finished_EventArgs(bool Finished_DNS_Query)
        {
            _finished = Finished_DNS_Query;
        }
    }
}
