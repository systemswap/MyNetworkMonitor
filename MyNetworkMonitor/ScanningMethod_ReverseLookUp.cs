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

        public ScanningMethod_ReverseLookUp()
        {
           
        }


        public event EventHandler<ReverseLookup_Task_Finished_EventArgs>? ReverseLookup_Task_Finished;
        public event EventHandler<ReverseLookup_Finished_EventArgs>? ReverseLookup_Finished;


        public async void ReverseLookupAsync(Dictionary<string, string> SourceIPsWithHostnames)
        {
            var tasks = new List<Task>();

            foreach (KeyValuePair<string, string> entry in SourceIPsWithHostnames)
            {
                var task = ReverseLookupTask(entry.Key, entry.Value);
                tasks.Add(task);
            }

            await Task.WhenAll(tasks);

            if (ReverseLookup_Finished != null)
            {
                ReverseLookup_Finished(this, new ReverseLookup_Finished_EventArgs(true));
            }
        }

        private async Task ReverseLookupTask(string SourceIP, string Hostname)
        {
            try
            {
                IPHostEntry _entry = await Dns.GetHostEntryAsync(Hostname);

                bool _ReverseLookupStatus = false;
                string _ReverseLookUpIPs = string.Empty;

                if (_entry.AddressList.ToList().Count == 1 && SourceIP == _entry.AddressList[0].ToString())
                {
                    _ReverseLookupStatus = true;
                }
                if (_entry.AddressList.ToList().Count != 1)
                {
                    _ReverseLookupStatus = false;

                    if (_entry.AddressList.ToList().Count == 0)
                    {
                        _ReverseLookUpIPs = "no IPs registred";
                    }
                    else
                    {
                        _ReverseLookUpIPs = string.Join("\r\n", _entry.AddressList.ToList());
                    }
                }

                if (ReverseLookup_Task_Finished != null)
                {
                    ReverseLookup_Task_Finished(this, new ReverseLookup_Task_Finished_EventArgs(SourceIP, _ReverseLookupStatus, _ReverseLookUpIPs, _entry));
                }
            }
            catch (Exception)
            {

            }
        }
    }

    public class ReverseLookup_Task_Finished_EventArgs : EventArgs
    {
        public ReverseLookup_Task_Finished_EventArgs(string SourceIP, bool ReverseLookUpStatus, string ReverseLookUpIPs, IPHostEntry Entry)
        {
            _IP = SourceIP;
            _ReverseLookUpStatus = ReverseLookUpStatus;
            _ReverseLookUpIPs = ReverseLookUpIPs;
            _Entry = Entry;
        }

        private string _IP = string.Empty;
        public string IP { get { return _IP; } }

        private bool _ReverseLookUpStatus = false;
        public bool ReverseLookUpStatus { get { return _ReverseLookUpStatus; } }

        private string _ReverseLookUpIPs = string.Empty;
        public string ReverseLookUpIPs { get { return _ReverseLookUpIPs; } }

        private IPHostEntry _Entry = null;
        public IPHostEntry Entry { get { return _Entry; } }
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
