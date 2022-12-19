using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    internal class ScanningMethod_LookUp
    {

        public ScanningMethod_LookUp()
        {

        }


        //public event EventHandler<Lookup_Task_Finished_EventArgs>? Lookup_Task_Finished;
        public event EventHandler<ScanTask_Finished_EventArgs>? Lookup_Task_Finished;

        public event EventHandler<Lookup_Finished_EventArgs>? Lookup_Finished;


        public async void LookupAsync(List<IPToRefresh> IPs)
        {
            var tasks = new List<Task>();

            foreach (IPToRefresh ip in IPs)
            {
                if (!string.IsNullOrEmpty(ip.Hostname))
                {
                    var task = LookupTask(ip);
                    if (task != null) tasks.Add(task);
                }
            }

            await Task.WhenAll(tasks.Where(t => t != null));

            if (Lookup_Finished != null)
            {
                Lookup_Finished(this, new Lookup_Finished_EventArgs(true));
            }
        }

        private async Task LookupTask(IPToRefresh ip)
        {
            IPHostEntry _entry;
            try
            {
                _entry = await Dns.GetHostEntryAsync(ip.Hostname);

                bool _LookUpStatus = false;
                string _LookUpIPs = string.Empty;

                if (_entry.AddressList.ToList().Count == 1 && ip.IP == _entry.AddressList[0].ToString())
                {
                    _LookUpStatus = true;
                }
                if (_entry.AddressList.ToList().Count != 1)
                {
                    _LookUpStatus = false;

                    if (_entry.AddressList.ToList().Count == 0)
                    {
                        _LookUpIPs = "no IPs registred";
                    }
                    else
                    {
                        _LookUpIPs = string.Join("\r\n", _entry.AddressList.ToList());
                    }
                }

                if (Lookup_Task_Finished != null)
                {
                    //Lookup_Task_Finished(this, new Lookup_Task_Finished_EventArgs(ip.IP, _ReverseLookupStatus, _ReverseLookUpIPs, _entry));

                    ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs();
                    scanTask_Finished.IP = ip.IP;
                    scanTask_Finished.LookUpStatus = _LookUpStatus;
                    scanTask_Finished.LookUpIPs = _LookUpIPs;
                    scanTask_Finished.IP_HostEntry = _entry;                   
                    scanTask_Finished.DNSServers = string.Join(',', ip.DNSServers);
                    
                    Lookup_Task_Finished(this, scanTask_Finished);
                }
            }
            catch (Exception)
            {

            }
        }





        public async Task<IPHostEntry> nsLookup(string Hostname)
        {
            IPHostEntry _entry;
            try
            {
                _entry = await Dns.GetHostEntryAsync(Hostname);
                if (_entry.AddressList.ToList().Count == 0)
                {
                    // "no IPs registred";
                    return null;
                }
                else
                {
                    return _entry;
                }
            }
            catch (Exception)
            {
                return null;
            }
        }
    }

    //public class Lookup_Task_Finished_EventArgs : EventArgs
    //{
    //    public Lookup_Task_Finished_EventArgs(string SourceIP, bool LookUpStatus, string LookUpIPs, IPHostEntry Entry)
    //    {
    //        _IP = SourceIP;
    //        _LookUpStatus = LookUpStatus;
    //        _LookUpIPs = LookUpIPs;
    //        _Entry = Entry;
    //    }

    //    private string _IP = string.Empty;
    //    public string IP { get { return _IP; } }

    //    private bool _LookUpStatus = false;
    //    public bool LookUpStatus { get { return _LookUpStatus; } }

    //    private string _LookUpIPs = string.Empty;
    //    public string LookUpIPs { get { return _LookUpIPs; } }

    //    private IPHostEntry _Entry = new IPHostEntry();
    //    public IPHostEntry Entry { get { return _Entry; } }
    //}

    public class Lookup_Finished_EventArgs : EventArgs
    {
        private bool _finished = false;
        public bool FinishedDNSQuery { get { return _finished; } }
        public Lookup_Finished_EventArgs(bool Finished_Lookup)
        {
            _finished = Finished_Lookup;
        }
    }
}
