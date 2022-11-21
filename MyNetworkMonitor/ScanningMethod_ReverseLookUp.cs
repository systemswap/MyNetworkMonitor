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

        public event EventHandler<ReverseLookup_Finished_EventArgs>? CustomEvent_ReverseLookup_Finished;

       

        public async void ReverseLookupAsync()
        {
            if (_scannResults.ResultTable.Rows.Count == 0)
            {
                return;
            }

            var tasks = new List<Task>();

            foreach (DataRow  row in _scannResults.ResultTable.Rows)
            {
                var task = ReverseLookupTask(row);
                tasks.Add(task);
            }

            await Task.WhenAll(tasks);

            if (CustomEvent_ReverseLookup_Finished != null)
            {
                CustomEvent_ReverseLookup_Finished(this, new ReverseLookup_Finished_EventArgs(true));
            }
        }

        private async Task ReverseLookupTask(DataRow row)
        {
            if (!string.IsNullOrEmpty(row["Hostname"].ToString()))
            {
                string host = row["Hostname"].ToString();

                try
                {
                    var ip = (await Dns.GetHostEntryAsync(row["Hostname"].ToString())).AddressList.ToList();


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


    public class ReverseLookup_Finished_EventArgs : EventArgs
    {
        private bool _finished = false;
        public bool FinishedDNSQuery { get { return _finished; } }
        public ReverseLookup_Finished_EventArgs(bool Finished_ReverseLookup)
        {
            _finished = Finished_ReverseLookup;
        }
    }
}
