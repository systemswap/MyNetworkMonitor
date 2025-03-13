using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    internal class ScanningMethod_LookUp
    {
        public ScanningMethod_LookUp()
        {

        }

        public event Action<int, int, int, ScanStatus> ProgressUpdated;
        public event EventHandler<ScanTask_Finished_EventArgs>? Lookup_Task_Finished;
        public event EventHandler<Method_Finished_EventArgs>? Lookup_Finished;

        private static readonly SemaphoreSlim _semaphore = new SemaphoreSlim(10); // Max. 10 parallele Lookups

        private int current = 0;
        private int responded = 0;
        private int total = 0;


        private CancellationTokenSource _cts = new CancellationTokenSource(); // 🔹 Ermöglicht das Abbrechen

        //int currentValue = Interlocked.Increment(ref current);
        //ProgressUpdated?.Invoke(currentValue, responded, total, ScanStatus.running);

        //int respondedValue = Interlocked.Increment(ref responded);
        //ProgressUpdated?.Invoke(current, respondedValue, total, ScanStatus.running);

        //ProgressUpdated?.Invoke(current, responded, total, ScanStatus.finished);

        public void StopScan()
        {
            if (_cts != null && !_cts.IsCancellationRequested)
            {
                _cts.Cancel(); // 🔹 Scan abbrechen
                _cts.Dispose();
                _cts = new CancellationTokenSource();
            }

            // 🔹 Zähler zurücksetzen
            current = 0;
            responded = 0;
            total = 0;

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



        //public async Task LookupAsync(List<IPToScan> IPs)
        //{
        //    StartNewScan();

        //    if (_cts.Token.IsCancellationRequested) return; // 🔹 Sofort abbrechen

        //    current = 0;
        //    responded = 0;
        //    total = 0;
        //    ProgressUpdated?.Invoke(current, responded, total);


        //    var tasks = new List<Task>();

        //    Parallel.ForEach(IPs, ip =>
        //    {
        //        if (!string.IsNullOrEmpty(ip.HostName))
        //        {
        //            var task = Task.Run(() => LookupTask(ip));
        //            if (task != null) tasks.Add(task);
        //        }
        //    });

        //    await Task.WhenAll(tasks.Where(t => t != null));

        //    if (Lookup_Finished != null)
        //    {
        //        Lookup_Finished(this, new Method_Finished_EventArgs());
        //    }
        //}

        public async Task LookupAsync(List<IPToScan> IPs)
        {
            StartNewScan();

            if (_cts.Token.IsCancellationRequested) return; // 🔹 Sofort abbrechen

            current = 0;
            responded = 0;
            total = IPs.Count; // 🔹 Gesamtzahl setzen
            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running);

            var tasks = new List<Task>();

            //foreach (var ip in IPs)
            //{ 
            //    if (_cts.Token.IsCancellationRequested) break; // 🔹 Falls abgebrochen, verlasse die Schleife

            //    if (!string.IsNullOrEmpty(ip.HostName))
            //    {
            //        tasks.Add(LookupTask(ip)); // 🔹 CancellationToken übergeben
            //    }
            //}

            foreach (var ip in IPs)
            {
                if (_cts.Token.IsCancellationRequested) break;

                if (!string.IsNullOrEmpty(ip.HostName))
                {
                    tasks.Add(Task.Run(async () =>
                    {
                        await _semaphore.WaitAsync(); // Warte, bis ein Platz frei wird
                        try
                        {
                            await LookupTask(ip);
                        }
                        finally
                        {
                            _semaphore.Release(); // Nach Abschluss freigeben
                        }
                    }));
                }
            }

            try
            {
                await Task.WhenAll(tasks);
            }
            catch (OperationCanceledException)
            {
                // 🔹 Falls abgebrochen, wird das hier abgefangen
            }

            if (Lookup_Finished != null)
            {
                Lookup_Finished(this, new Method_Finished_EventArgs());
            }
        }


        //private async Task LookupTask(IPToScan ipToScan)
        //{
        //    IPHostEntry _entry;
        //    try
        //    {
        //        _entry = await Dns.GetHostEntryAsync(ipToScan.HostnameWithDomain);

        //        bool _LookUpStatus = false;
        //        string _LookUpIPs = string.Empty;

        //        //wenn nur eine ip zurück kommt und diese gleich der in der spalte ip dann passt alles
        //        if (_entry.AddressList.ToList().Count == 1 && ipToScan.IPorHostname == _entry.AddressList[0].ToString())
        //        {
        //            _LookUpStatus = true;
        //        }

        //        //wenn nur eine ip zurück kommt und diese ungleich der in der spalte ip ist dann false
        //        if (_entry.AddressList.ToList().Count == 1 && ipToScan.IPorHostname != _entry.AddressList[0].ToString())
        //        {
        //            _LookUpStatus = false;
        //            _LookUpIPs = _entry.AddressList[0].ToString();
        //        }

        //        //werden mehrere ips zurück gegeben werden alle eingetragen
        //        if (_entry.AddressList.ToList().Count != 1)
        //        {
        //            _LookUpStatus = false;

        //            if (_entry.AddressList.ToList().Count == 0)
        //            {
        //                _LookUpIPs = "no IPs registred";
        //            }
        //            else
        //            {
        //                _LookUpIPs = string.Join("\r\n", _entry.AddressList.ToList());
        //            }
        //        }

        //        if (Lookup_Task_Finished != null)
        //        {
        //            ipToScan.LookUpStatus = _LookUpStatus;
        //            ipToScan.LookUpIPs = _LookUpIPs;
        //            ipToScan.IP_HostEntry = _entry;

        //            ipToScan.UsedScanMethod = ScanMethod.Lookup;

        //            ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs();
        //            scanTask_Finished.ipToScan = ipToScan;

        //            Lookup_Task_Finished(this, scanTask_Finished);
        //        }
        //    }
        //    catch (Exception)
        //    {

        //    }
        //}


        private async Task LookupTask(IPToScan ipToScan)
        {
            if (_cts.IsCancellationRequested) return;

            int currentValue = Interlocked.Increment(ref current);
            ProgressUpdated?.Invoke(currentValue, responded, total, ScanStatus.running);

            IPHostEntry _entry;
            try
            {
                _entry = await Dns.GetHostEntryAsync(ipToScan.HostnameWithDomain).WaitAsync(_cts.Token);
                
                if (_cts.Token.IsCancellationRequested) return;

                bool _LookUpStatus = false;
                string _LookUpIPs = string.Empty;

                var addressList = _entry.AddressList.ToList();

                if (addressList.Count == 1)
                {
                    if (ipToScan.IPorHostname == addressList[0].ToString())
                    {
                        _LookUpStatus = true;
                    }
                    else
                    {
                        _LookUpStatus = false;
                        _LookUpIPs = addressList[0].ToString();
                    }
                }
                else if (addressList.Count > 1)
                {
                    _LookUpStatus = false;
                    _LookUpIPs = string.Join("\r\n", addressList);
                }
                else
                {
                    _LookUpIPs = "no IPs registered";
                }

                if (Lookup_Task_Finished != null)
                {
                    ipToScan.LookUpStatus = _LookUpStatus;
                    ipToScan.LookUpIPs = _LookUpIPs;
                    ipToScan.IP_HostEntry = _entry;
                    ipToScan.UsedScanMethod = ScanMethod.Lookup;

                    var scanTask_Finished = new ScanTask_Finished_EventArgs { ipToScan = ipToScan };
                    Lookup_Task_Finished(this, scanTask_Finished);

                    int respondedValue = Interlocked.Increment(ref responded);
                    ProgressUpdated?.Invoke(current, respondedValue, total, ScanStatus.running);
                }
            }
            catch (OperationCanceledException)
            {
                // 🔹 Falls das Lookup abgebrochen wurde, wird das hier behandelt
            }
            catch (Exception)
            {
                // 🔹 Andere Fehler abfangen
            }
        }



        //public async Task<IPHostEntry> nsLookup(string Hostname)
        //{
        //    IPHostEntry _entry;
        //    try
        //    {
        //        _entry = await Dns.GetHostEntryAsync(Hostname);
        //        if (_entry.AddressList.ToList().Count == 0)
        //        {
        //            // "no IPs registred";
        //            return null;
        //        }
        //        else
        //        {
        //            return _entry;
        //        }
        //    }
        //    catch (Exception)
        //    {
        //        return null;
        //    }
        //}

        //public async Task<IPHostEntry> nsLookup(string Hostname)
        //{
        //    try
        //    {
        //        IPHostEntry _entry = await Dns.GetHostEntryAsync(Hostname).WaitAsync(_cts.Token);
        //        return _entry.AddressList.Length > 0 ? _entry : null;
        //    }
        //    catch (OperationCanceledException)
        //    {
        //        return null; // 🔹 Abbruch sicherstellen
        //    }
        //    catch (Exception)
        //    {
        //        return null;
        //    }
        //}


        public async Task<IPHostEntry> nsLookup(string Hostname)
        {
            if (_cts.Token.IsCancellationRequested) return null;

            try
            {               
                IPHostEntry _entry = await Dns.GetHostEntryAsync(Hostname).WaitAsync(TimeSpan.FromSeconds(3), _cts.Token);
                return _entry.AddressList.Length > 0 ? _entry : null;
            }
            catch (OperationCanceledException)
            {
                return null; // 🔹 Abbruch sicherstellen
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Fehler bei nsLookup für {Hostname}: {ex.Message}");
                return null;
            }
        }

    }
}
