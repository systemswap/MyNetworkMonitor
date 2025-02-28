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

        public event EventHandler<ScanTask_Finished_EventArgs>? Lookup_Task_Finished;
        public event EventHandler<Method_Finished_EventArgs>? Lookup_Finished;


        public async Task LookupAsync(List<IPToScan> IPs)
        {
            var tasks = new List<Task>();

            Parallel.ForEach(IPs, ip =>
            {
                if (!string.IsNullOrEmpty(ip.HostName))
                {
                    var task = Task.Run(() => LookupTask(ip));
                    if (task != null) tasks.Add(task);
                }
            });

            await Task.WhenAll(tasks.Where(t => t != null));

            if (Lookup_Finished != null)
            {
                Lookup_Finished(this, new Method_Finished_EventArgs());
            }
        }

        private async Task LookupTask(IPToScan ipToScan)
        {
            IPHostEntry _entry;
            try
            {
                _entry = await Dns.GetHostEntryAsync(ipToScan.HostnameWithDomain);

                bool _LookUpStatus = false;
                string _LookUpIPs = string.Empty;

                //wenn nur eine ip zurück kommt und diese gleich der in der spalte ip dann passt alles
                if (_entry.AddressList.ToList().Count == 1 && ipToScan.IPorHostname == _entry.AddressList[0].ToString())
                {
                    _LookUpStatus = true;
                }

                //wenn nur eine ip zurück kommt und diese ungleich der in der spalte ip ist dann false
                if (_entry.AddressList.ToList().Count == 1 && ipToScan.IPorHostname != _entry.AddressList[0].ToString())
                {
                    _LookUpStatus = false;
                    _LookUpIPs = _entry.AddressList[0].ToString();
                }

                //werden mehrere ips zurück gegeben werden alle eingetragen
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
                    ipToScan.LookUpStatus = _LookUpStatus;
                    ipToScan.LookUpIPs = _LookUpIPs;
                    ipToScan.IP_HostEntry = _entry;

                    ipToScan.UsedScanMethod = ScanMethod.Lookup;

                    ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs();
                    scanTask_Finished.ipToScan = ipToScan;

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
}
