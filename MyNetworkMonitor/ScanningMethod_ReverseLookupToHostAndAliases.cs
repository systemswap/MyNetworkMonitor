
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
    internal class ScanningMethod_ReverseLookupToHostAndAlieases
    {
        public ScanningMethod_ReverseLookupToHostAndAlieases()
        {

        }


        public event EventHandler<ScanTask_Finished_EventArgs>? GetHostAliases_Task_Finished;
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
                        var task = Task.Run(() => ReverseLookupToHostAndAliases(ip));
                        if (task != null) tasks.Add(task);
                    });

            await Task.WhenAll(tasks.Where(t => t != null));

            if (GetHostAliases_Finished != null)
            {
                GetHostAliases_Finished(this, new Method_Finished_EventArgs());
            }
        }



        private async Task ReverseLookupToHostAndAliases(IPToScan ipToScan)
        {
            try
            {
                List<NameServer> dnsServers = new List<NameServer>();
                DnsClient.LookupClient client = null;
                if (ipToScan.DNSServerList != null && ipToScan.DNSServerList.Count > 0 && !string.IsNullOrEmpty(string.Join(string.Empty, ipToScan.DNSServerList)))
                {
                    foreach (string s in ipToScan.DNSServerList)
                    {
                        dnsServers.Add(IPAddress.Parse(s));
                    }
                    client = new DnsClient.LookupClient(dnsServers.ToArray());
                }
                else
                {
                    client = new DnsClient.LookupClient();
                }
                IPHostEntry _IPHostEntry = await client.GetHostEntryAsync(ipToScan.IP);

                if (_IPHostEntry == null)
                {
                    throw new Exception("IPHostEntry is null");
                }

                if (GetHostAliases_Task_Finished != null)
                {
                    ipToScan.HostName = _IPHostEntry.HostName;
                    ipToScan.Aliases = (_IPHostEntry.Aliases != null) ? string.Join("\r\n", _IPHostEntry.Aliases) : string.Empty;

                    ipToScan.UsedScanMethod = ScanMethod.ReverseLookup;

                    ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs();
                    scanTask_Finished.ipToScan = ipToScan;

                    GetHostAliases_Task_Finished(this, scanTask_Finished);
                }
            }
            catch (Exception ex)
            {
                GetHostAliases_Task_Finished(this, null);
            }
        }
    }
}
