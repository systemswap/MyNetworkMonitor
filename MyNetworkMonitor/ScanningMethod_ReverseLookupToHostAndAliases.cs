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
        public event Action<ScanStatus>? GetHostAliases_Finished;



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
          
            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.stopped); // 🔹 UI auf 0 setzen
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

        public async Task GetHost_Aliases(List<IPToScan> IPs, bool isDeepDNSServerScan)
        {

            StartNewScan();


            current = 0;
            responded = 0;
            total = IPs.Count; // 🔹 Gesamtanzahl setzen

            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running); // 🔹 UI auf 0 setzen


            if (_cts.Token.IsCancellationRequested) return; // 🔹 Falls der Scan direkt nach Start gestoppt wird


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
                        await ReverseLookupToHostAndAliases(ip, isDeepDNSServerScan);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }, _cts.Token);

                tasks.Add(task);
            }

            try
            {
                await Task.WhenAll(tasks.Where(t => t != null));
            }
            catch { }

            GetHostAliases_Finished?.Invoke(ScanStatus.finished);
        }





        private async Task ReverseLookupToHostAndAliases(IPToScan ipToScan, bool isDeepDNSServerScan)
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

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                cts.CancelAfter(TimeSpan.FromSeconds(10));


                int currentValue = Interlocked.Increment(ref current);
                ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running);

                //IPHostEntry _IPHostEntry = await client.GetHostEntryAsync(ipToScan.IPorHostname).WaitAsync(_cts.Token);

                IPHostEntry? _IPHostEntry = null;
                int maxRetries = 3;
                int attempt = 0;
               

                while (attempt < maxRetries && _IPHostEntry == null)
                {
                    try
                    {
                        _IPHostEntry = await client.GetHostEntryAsync(ipToScan.IPorHostname).WaitAsync(cts.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        // Abbruch durch CancellationToken
                        throw;
                    }
                    catch (Exception ex)
                    {
                        attempt++;
                        if (attempt >= maxRetries)
                        {
                            // Option: Log oder Fehlerbehandlung hier
                            Console.WriteLine($"Fehler bei Versuch {attempt}: {ex.Message}");
                        }
                        else
                        {
                            await Task.Delay(500); // kurze Pause vor erneutem Versuch
                        }
                    }
                }
                    var results = new List<string>();

                if (isDeepDNSServerScan)
                {
                    //alle DNS Server einzeln prüfen welcher diesen hostnamen auflösen kann
                    foreach (var dnsServer in client.NameServers)
                    {
                        try
                        {
                            // Erstelle LookupClient mit spezifischem Nameserver
                            var singleLookup = new LookupClient(dnsServer);
                            var result = await singleLookup.GetHostEntryAsync(ipToScan.IPorHostname).WaitAsync(cts.Token);

                            if (result != null)
                            {
                                results.Add(dnsServer.Address.ToString().PadRight(17, ' ') + "\t-> " + result.HostName);
                            }
                            else
                            {
                                results.Add(dnsServer.Address.ToString().PadRight(17, ' ') + "\t-> nothing");
                            }


                        }
                        catch (Exception ex)
                        {

                        }
                    }
                }


                if (cts.Token.IsCancellationRequested) return; // 🔹 Falls der Scan abgebrochen wurde, keine weiteren Aktionen durchführen


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

                    
                    ipToScan.DNSServerList = results;

                    ipToScan.UsedScanMethod = ScanMethod.ReverseLookup;

                    ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs();
                    scanTask_Finished.ipToScan = ipToScan;

                    int respondedValue = Interlocked.Increment(ref responded);
                    ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running);

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
