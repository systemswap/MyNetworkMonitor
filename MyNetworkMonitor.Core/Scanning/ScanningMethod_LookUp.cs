using DnsClient;
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
    public class ScanningMethod_LookUp
    {
        public ScanningMethod_LookUp()
        {

        }

        public event Action<int, int, int, ScanStatus> ProgressUpdated;
        public event EventHandler<ScanTask_Finished_EventArgs>? Lookup_Task_Finished;
        public event Action<ScanStatus>? Lookup_Finished;

        // War 10 gegen den System-Resolver. Direkt gegen den (per Scope oder
        // Gateway-Fallback bekannten) DNS-Server beantwortet, siehe
        // ScanningMethod_ReverseLookupToHostAndAliases: dort verkraftete
        // dasselbe Gateway live 32 gleichzeitige Anfragen in unter 100ms.
        private static readonly SemaphoreSlim _semaphore = new SemaphoreSlim(16);

        /// <summary>Wie oft eine ausbleibende Antwort erneut angefragt wird, bevor der Name als nicht aufloesbar gilt.</summary>
        private const int QueryRetries = 3;

        /// <summary>Wie lange je Versuch auf eine Antwort gewartet wird - siehe ReverseLookup fuer die Begruendung derselben Werte.</summary>
        private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(1);

        /// <summary>Gesamtbudget je Name, ueber alle Wiederholungen hinweg.</summary>
        private static readonly TimeSpan QueryBudget =
            QueryTimeout * (QueryRetries + 1) + TimeSpan.FromMilliseconds(500);

        /// <summary>
        /// Ein Client je Namensserver-Zusammenstellung, ueber den ganzen Lauf
        /// hinweg - derselbe Grund wie bei
        /// <see cref="ScanningMethod_ReverseLookupToHostAndAlieases.ClientFor"/>.
        /// </summary>
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, LookupClient> _clients = new();

        private LookupClient ClientFor(IPToScan ipToScan)
        {
            List<string> servers = ipToScan.DNSServerList?
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Select(s => s.Trim())
                .ToList() ?? [];

            return _clients.GetOrAdd(string.Join(",", servers), _ =>
            {
                LookupClientOptions options = servers.Count > 0 && servers.All(s => IPAddress.TryParse(s, out IPAddress? _))
                    ? new LookupClientOptions([.. servers.Select(s => new NameServer(IPAddress.Parse(s)))])
                    : new LookupClientOptions();

                options.Timeout = QueryTimeout;
                options.Retries = QueryRetries;
                options.UseCache = true;
                options.ThrowDnsErrors = false;

                // Der Reihe nach fragen, nicht zufaellig - die Liste ist eine
                // Rangfolge. Siehe die gleichlautende Stelle in der
                // Rueckwaertsaufloesung.
                options.UseRandomNameServer = false;

                return new LookupClient(options);
            });
        }

        /// <summary>
        /// Namensserver, die in diesem Lauf nur Zeitueberschreitungen lieferten,
        /// und der zuletzt erfolgreiche. Beides wie in der
        /// Rueckwaertsaufloesung - dort steht die ausfuehrliche Begruendung.
        /// </summary>
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> _silence = new();

        private const int SilentAfter = 3;

        private volatile string? _preferredServer;

        private bool IsKnownSilent(NameServer server) =>
            _silence.TryGetValue(server.Address.ToString(), out int misses) && misses >= SilentAfter;

        /// <summary>
        /// Fragt genau einen Server, mit eigenem Zeitbudget. Ein Schweigen wird
        /// vermerkt, eine Antwort macht den Server zum bevorzugten.
        /// </summary>
        private async Task<IPHostEntry?> AskOneAsync(NameServer server, string hostname)
        {
            try
            {
                using CancellationTokenSource oneCts =
                    CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                oneCts.CancelAfter(QueryBudget);

                IPHostEntry? entry = await SingleServerClientFor(server)
                    .GetHostEntryAsync(hostname)
                    .WaitAsync(oneCts.Token);

                _silence[server.Address.ToString()] = 0;

                if (entry is not null) _preferredServer = server.Address.ToString();

                return entry;
            }
            catch (OperationCanceledException) when (!_cts.Token.IsCancellationRequested)
            {
                _silence.AddOrUpdate(server.Address.ToString(), 1, (_, misses) => misses + 1);
                return null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>Ein Client je einzelnem Namensserver, wiederverwendet wie oben.</summary>
        private LookupClient SingleServerClientFor(NameServer dnsServer) =>
            _clients.GetOrAdd("single:" + dnsServer.Address, _ => new LookupClient(
                new LookupClientOptions([dnsServer])
                {
                    Timeout = QueryTimeout,
                    Retries = QueryRetries,
                    UseCache = true,
                    ThrowDnsErrors = false
                }));

        private int current = 0;
        private int responded = 0;
        private int total = 0;


        private CancellationTokenSource _cts = new CancellationTokenSource(); // 🔹 Ermöglicht das Abbrechen

        //int currentValue = Interlocked.Increment(ref current);
        //Task.Run(() => ProgressUpdated?.Invoke(currentValue, responded, total, ScanStatus.running));

        //int respondedValue = Interlocked.Increment(ref responded);
        //Task.Run(() => ProgressUpdated?.Invoke(current, respondedValue, total, ScanStatus.running));

        //Task.Run(() => ProgressUpdated?.Invoke(current, responded, total, ScanStatus.finished));

        public void StopScan()
        {
            if (_cts != null && !_cts.IsCancellationRequested)
            {
                _cts.Cancel(); // 🔹 Scan abbrechen
                // Hier NICHT aufraeumen und ersetzen: die Schleifen lesen _cts ueber
                // das Feld. Ein frisches CTS an dieser Stelle meldet ihnen wieder
                // "nicht abgebrochen", und der Lauf geht weiter, statt zu enden.
                // Das Zuruecksetzen erledigt StartNewScan beim naechsten Lauf.
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



        //public async Task LookupAsync(List<IPToScan> IPs)
        //{
        //    StartNewScan();

        //    if (_cts.Token.IsCancellationRequested) return; // 🔹 Sofort abbrechen

        //    current = 0;
        //    responded = 0;
        //    total = 0;
        //    Task.Run(() => ProgressUpdated?.Invoke(current, responded, total));


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
                await Task.WhenAll(tasks.Where(t => t != null));
            }
            catch (OperationCanceledException)
            {
                // 🔹 Falls abgebrochen, wird das hier abgefangen
            }

            
                Lookup_Finished?.Invoke(ScanStatus.finished);            
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

        //            Task.Run(() => Lookup_Task_Finished(this, scanTask_Finished));
        //        }
        //    }
        //    catch (Exception)
        //    {

        //    }
        //}


        private async Task LookupTask(IPToScan ipToScan)
        {
            if (_cts.IsCancellationRequested) return;

            IPHostEntry _entry;
            try
            {
                LookupClient client = ClientFor(ipToScan);

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                cts.CancelAfter(QueryBudget);

                IPHostEntry? found = null;

                // Zuerst der Server, der zuletzt aufgeloest hat.
                if (_preferredServer is { } preferredAddress)
                {
                    NameServer? preferred = client.NameServers
                        .FirstOrDefault(s => s.Address.ToString() == preferredAddress);

                    if (preferred is not null)
                    {
                        found = await AskOneAsync(preferred, ipToScan.HostnameWithDomain);
                    }
                }

                NameServer? leading = client.NameServers.FirstOrDefault();
                bool leadingSilent =
                    leading is not null && client.NameServers.Count > 1 && IsKnownSilent(leading);

                if (found is null && !leadingSilent)
                {
                    try
                    {
                        found = await client.GetHostEntryAsync(ipToScan.HostnameWithDomain)
                                            .WaitAsync(cts.Token);
                    }
                    catch (OperationCanceledException) when (!_cts.Token.IsCancellationRequested)
                    {
                        // Der vordere Server schweigt - das kostet den Namen
                        // nicht mehr, unten ist jeder einzeln an der Reihe.
                        leadingSilent = true;
                        if (leading is not null)
                            _silence.AddOrUpdate(leading.Address.ToString(), 1, (_, misses) => misses + 1);
                    }
                }

                // Dann jeder hinterlegte Server einzeln, bis einer den Namen
                // aufloest - in einem Netz mit mehreren Zonen kennt ihn oft nur
                // einer von ihnen.
                if (found is null && client.NameServers.Count > 1)
                {
                    foreach (NameServer dnsServer in client.NameServers.Skip(leadingSilent ? 1 : 0))
                    {
                        if (_cts.Token.IsCancellationRequested) return;
                        if (IsKnownSilent(dnsServer)) continue;
                        if (dnsServer.Address.ToString() == _preferredServer) continue;

                        found = await AskOneAsync(dnsServer, ipToScan.HostnameWithDomain);
                        if (found is not null) break;
                    }
                }

                if (found is null) return;

                _entry = found;

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
                    //ipToScan.LookUpStatus = _LookUpStatus;
                    ipToScan.LookUpIPs = _LookUpIPs;
                    ipToScan.IP_HostEntry = _entry;
                    ipToScan.UsedScanMethod = ScanMethod.Lookup;

                    int respondedValue = Interlocked.Increment(ref responded);
                    ProgressUpdated?.Invoke(current, respondedValue, total, ScanStatus.running);

                    var scanTask_Finished = new ScanTask_Finished_EventArgs { ipToScan = ipToScan };
                    Lookup_Task_Finished(this, scanTask_Finished);
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
            finally
            {
                // Erst zaehlen, wenn die Abfrage beantwortet oder abgelaufen
                // ist. Beim Absenden zu zaehlen liesse den Balken lange vor
                // dem eigentlichen Ende am Anschlag stehen.
                int currentValue = Interlocked.Increment(ref current);
                ProgressUpdated?.Invoke(currentValue, responded, total, ScanStatus.running);
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


        // nsLookup(string) stand hier bis zum 13.08.2026. Aufrufer waren allein
        // die alten Oberflaechen (WPF und MainWindowView); mit ihnen ist sie
        // weggefallen. Die Namensaufloesung des Laufs geht ueber
        // ReverseLookup/Hostname, die ihren DNS-Server aus dem Bereich kennen -
        // etwas, das dieser Methode ohne IPToScan nie zur Verfuegung stand.
    }
}
