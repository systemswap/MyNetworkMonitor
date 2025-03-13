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

        public event Action<int, int, int, ScanStatus> ProgressUpdated;
        public event EventHandler<ScanTask_Finished_EventArgs>? GetHostAliases_Task_Finished;
        public event EventHandler<Method_Finished_EventArgs>? GetHostAliases_Finished;



        private int current = 0;
        private int responded = 0;
        private int total = 0;


        private CancellationTokenSource _cts = new CancellationTokenSource(); // 🔹 Ermöglicht das Abbrechen

        public void StopScan()
        {
            if (_cts != null && !_cts.IsCancellationRequested)
            {
                _cts.Cancel(); // 🔹 Scan abbrechen
                _cts.Dispose();
                _cts = new CancellationTokenSource();
            }
          
            Task.Run(() => ProgressUpdated?.Invoke(current, responded, total, ScanStatus.stopped)); // 🔹 UI auf 0 setzen
        }

        private void StartNewScan()
        {
            if (_cts != null)
            {
                if (!_cts.IsCancellationRequested)
                {
                    _cts.Cancel();
                }
                _cts.Dispose();
            }
            _cts = new CancellationTokenSource();

            // 🔹 Zähler zurücksetzen
            current = 0;
            responded = 0;
            total = 0;
        }

        public async Task GetHost_Aliases(List<IPToScan> IPs)
        {

            StartNewScan();


            current = 0;
            responded = 0;
            total = IPs.Count; // 🔹 Gesamtanzahl setzen

            Task.Run(() => ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running)); // 🔹 UI auf 0 setzen


            if (_cts.Token.IsCancellationRequested) return; // 🔹 Falls der Scan direkt nach Start gestoppt wird

            Task.Run(() => ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running)); // 🔹 UI auf 0 setzen

            if (IPs.Count == 0)
            {
                return;
            }

            var tasks = new List<Task>();

            //Parallel.ForEach(IPs, async ip =>
            //        {
            //            await Task.Delay(50, _cts.Token);

            //            int currentValue = Interlocked.Increment(ref current);
            //            Task.Run(() => ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running));

            //            var task = Task.Run(() => ReverseLookupToHostAndAliases(ip), _cts.Token);
            //            if (task != null) tasks.Add(task);
            //        });

            //foreach (IPToScan ip in IPs)
            //{
            //    if (_cts.Token.IsCancellationRequested) return;

            //    int currentValue = Interlocked.Increment(ref current);
            //    Task.Run(() => ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running));

            //    var task = Task.Run(() => ReverseLookupToHostAndAliases(ip));
            //    if (task != null) tasks.Add(task);
            //}


            SemaphoreSlim semaphore = new SemaphoreSlim(50); // Begrenze parallele Tasks auf 10

            foreach (IPToScan ip in IPs)
            {
                if (_cts.Token.IsCancellationRequested) return;

               

                var task = Task.Run(async () =>
                {
                    await semaphore.WaitAsync();
                    try
                    {
                        await ReverseLookupToHostAndAliases(ip);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }, _cts.Token);

                tasks.Add(task);
            }

            await Task.WhenAll(tasks);

            if (GetHostAliases_Finished != null)
            {
                Task.Run(() => ProgressUpdated?.Invoke(current, responded, total, ScanStatus.finished)); // 🔹 UI auf 0 setzen
                GetHostAliases_Finished(this, new Method_Finished_EventArgs());
            }
        }





        private async Task ReverseLookupToHostAndAliases(IPToScan ipToScan)
        {
            if (_cts.Token.IsCancellationRequested) return; // 🔹 Abbruch vor dem Start prüfen

            try
            {
                List<NameServer> dnsServers = new List<NameServer>();
                DnsClient.LookupClient client = null;
                if (ipToScan.DNSServerList != null && ipToScan.DNSServerList.Count > 0 && !string.IsNullOrEmpty(string.Join(string.Empty, ipToScan.DNSServerList)))
                {
                    foreach (string s in ipToScan.DNSServerList)
                    {
                        if (_cts.Token.IsCancellationRequested) return; // 🔹 Abbruch vor dem Start prüfen

                        dnsServers.Add(IPAddress.Parse(s));
                    }
                    client = new DnsClient.LookupClient(dnsServers.ToArray());
                }
                else
                {
                    client = new DnsClient.LookupClient();
                }


                int currentValue = Interlocked.Increment(ref current);
                Task.Run(() => ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running));

                IPHostEntry _IPHostEntry = await client.GetHostEntryAsync(ipToScan.IPorHostname).WaitAsync(_cts.Token);


                if (_cts.Token.IsCancellationRequested) return; // 🔹 Falls der Scan abgebrochen wurde, keine weiteren Aktionen durchführen


                if (_IPHostEntry == null)
                {
                    throw new Exception("IPHostEntry is null");
                }

                if (GetHostAliases_Task_Finished != null)
                {
                    if (_IPHostEntry.HostName.Split('.').ToList().Count > 2)
                    {
                        List<string> HostDomainSplit = new List<string>();
                        HostDomainSplit.AddRange(_IPHostEntry.HostName.ToString().Split(".", 2, StringSplitOptions.None).ToList());
                        ipToScan.HostName = (HostDomainSplit.Count >= 1) ? HostDomainSplit[0] : string.Empty;
                        ipToScan.Domain = (HostDomainSplit.Count >= 2) ? HostDomainSplit[1] : string.Empty;
                    }
                    else
                    {
                        ipToScan.HostName = _IPHostEntry.HostName;
                        ipToScan.Domain = string.Empty;
                    }

                    ipToScan.Aliases = (_IPHostEntry.Aliases != null) ? string.Join("\r\n", _IPHostEntry.Aliases) : string.Empty;

                    ipToScan.UsedScanMethod = ScanMethod.ReverseLookup;

                    ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs();
                    scanTask_Finished.ipToScan = ipToScan;

                    int respondedValue = Interlocked.Increment(ref responded);
                    Task.Run(() => ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running));

                    Task.Run(() => GetHostAliases_Task_Finished(this, scanTask_Finished));
                }
            }
            catch (Exception ex)
            {
                Task.Run(() => GetHostAliases_Task_Finished(this, null));
            }
        }
    }
}
