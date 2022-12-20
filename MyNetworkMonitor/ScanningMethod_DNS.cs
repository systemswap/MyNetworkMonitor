
using DnsClient;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

namespace MyNetworkMonitor
{
    internal class ScanningMethod_DNS
    {
        public ScanningMethod_DNS()
        {

        }

        //public event EventHandler<GetHostAndAliasFromIP_Task_Finished_EventArgs>? GetHostAliases_Task_Finished;
        public event EventHandler<ScanTask_Finished_EventArgs>? GetHostAliases_Task_Finished;

        //public event EventHandler<GetHostAndAliasFromIP_Finished_EventArgs>? GetHostAliases_Finished;
        public event EventHandler<Method_Finished_EventArgs>? GetHostAliases_Finished;

        public async Task GetHost_Aliases(List<IPToScan> IPs)
        {
            if (IPs.Count == 0)
            {
                return;
            }

            var tasks = new List<Task>();

            Parallel.ForEach(IPs, ip =>
                    {
                        var task = Task.Run(() => GetHost_Aliases_Task(ip));
                        if (task != null) tasks.Add(task);
                    });

            await Task.WhenAll(tasks.Where(t => t != null));

            if (GetHostAliases_Finished != null)
            {
                GetHostAliases_Finished(this, new Method_Finished_EventArgs());
            }
        }



        private async Task GetHost_Aliases_Task(IPToScan ip)
        {
            try
            {
                //IPHostEntry _IPHostEntry = Dns.GetHostEntryAsync(ip.IP.ToString(), System.Net.Sockets.AddressFamily.InterNetwork).Result;


                List<NameServer> dnsServers = new List<NameServer>();
                DnsClient.LookupClient client = null;
                if (ip.DNSServerList != null && ip.DNSServerList.Count > 0 && !string.IsNullOrEmpty(string.Join(string.Empty, ip.DNSServerList)))
                {
                    foreach (string s in ip.DNSServerList)
                    {
                        dnsServers.Add(IPAddress.Parse(s));
                    }
                    client = new DnsClient.LookupClient(dnsServers.ToArray());
                }
                else
                {
                    client = new DnsClient.LookupClient();
                }
                IPHostEntry _IPHostEntry = await client.GetHostEntryAsync(ip.IP);

                if (_IPHostEntry == null)                
                {
                    throw new Exception("IPHostEntry is null");
                    //GetHostAliases_Task_Finished(this, null);
                    //return;
                }

                if (GetHostAliases_Task_Finished != null)
                {
                    //GetHostAliases_Task_Finished(this, new GetHostAndAliasFromIP_Task_Finished_EventArgs(ip.IPGroupDescription, ip.DeviceDescription, ip.IP, entry.HostName, string.Join("\r\n", entry.Aliases)));

                    ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs();
                    scanTask_Finished.ipToScan.IPGroupDescription = ip.IPGroupDescription;
                    scanTask_Finished.ipToScan.DeviceDescription = ip.DeviceDescription;
                    scanTask_Finished.ipToScan.IP = ip.IP;
                    scanTask_Finished.ipToScan.HostName = _IPHostEntry.HostName;
                    scanTask_Finished.ipToScan.Aliases = (_IPHostEntry.Aliases != null) ? string.Join("\r\n", _IPHostEntry.Aliases) : string.Empty;  
                    scanTask_Finished.ipToScan.DNSServers = (ip.DNSServerList != null) ? string.Join(',', ip.DNSServerList) : string.Empty;

                    GetHostAliases_Task_Finished(this, scanTask_Finished);
                }
            }
            catch (Exception ex)
            {
                GetHostAliases_Task_Finished(this, null);
            }
        }
    }

    //public class GetHostAndAliasFromIP_Task_Finished_EventArgs : EventArgs
    //{
    //    //public GetHostAndAliasFromIP_Task_Finished_EventArgs(string IP, string Hostname, string Aliases, int CurrentHostnamesCount, int CountedHostnames)
    //    //{
    //    //    _resultRow = results.ResultTable.NewRow();
    //    //    _resultRow["IP"] = _IP = IP;
    //    //    _resultRow["Hostname"] = _Hostname = Hostname;
    //    //    _resultRow["Aliases"] = _Aliases = Aliases;

    //    //    _currentHostnamesCount = CurrentHostnamesCount;
    //    //    _countedHostnames = CountedHostnames;
    //    //}

    //    public GetHostAndAliasFromIP_Task_Finished_EventArgs(string IPGroupDescription, string DeviceDescription, string IP, string Hostname, string Aliases)
    //    {
    //        //_resultRow = results.ResultTable.NewRow();
    //        //_resultRow["IP"] = _IP = IP;
    //        //_resultRow["Hostname"] = _Hostname = Hostname;
    //        //_resultRow["Aliases"] = _Aliases = Aliases;

    //        //_currentHostnamesCount = CurrentHostnamesCount;
    //        //_countedHostnames = CountedHostnames;

    //        _IPGroupDescription= IPGroupDescription;
    //        _DeviceDescription= DeviceDescription;
    //        _IP= IP;
    //        _Hostname= Hostname;
    //        _Aliases= Aliases;
    //    }

    //    //ScanResults results = new ScanResults();

    //    //private DataRow _resultRow;
    //    //public DataRow ResultRow { get { return _resultRow; } }

    //    private string _IPGroupDescription = string.Empty;
    //    public string IPGroupDescription { get { return _IPGroupDescription; } }

    //    private string _DeviceDescription = string.Empty;
    //    public string DeviceDescription { get { return _DeviceDescription; } }

    //    private string _IP = string.Empty;
    //    public string IP { get { return _IP; } }


    //    private string _Hostname = string.Empty;
    //    public string Hostname { get { return _Hostname; } }

    //    private string _Aliases = string.Empty;
    //    public string Aliases { get { return _Aliases; } }


    //    //private int _countedHostnames = 0;
    //    //public int CountedHostnames { get { return _countedHostnames; } }


    //    //private int _currentHostnamesCount = 0;
    //    //public int CurrentHostnamesCount { get { return _currentHostnamesCount; } }
    //}

    //public class GetHostAndAliasFromIP_Finished_EventArgs : EventArgs
    //{
    //    private bool _finished = false;
    //    public bool FinishedDNSQuery { get { return _finished; } }
    //    public GetHostAndAliasFromIP_Finished_EventArgs(bool Finished_DNS_Query)
    //    {
    //        _finished = Finished_DNS_Query;
    //    }
    //}
}
