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
    public class ScanningMethod_ReverseLookupToHostAndAlieases
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


            // War 50: ein Heim-DNS-Server (Router oder NAS) verliert unter einem
            // Burst von 50 gleichzeitigen PTR-Anfragen die meisten UDP-Pakete,
            // bevor die Zeitgrenze ablaeuft. Live gemessen an einem echten /24
            // mit ca. 33 Geraeten: bei 50 kamen 4 Treffer zurueck, bei 8 (mit den
            // unten angepassten Zeiten) alle 32 erreichbaren - und das in einem
            // Bruchteil der Zeit, die eine rein sequentielle Abfrage braeuchte.
            SemaphoreSlim semaphore = new SemaphoreSlim(MaxConcurrentLookups);

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





        /// <summary>Wie viele Adressen gleichzeitig abgefragt werden. Siehe Kommentar oben an der Semaphore.</summary>
        private const int MaxConcurrentLookups = 8;

        /// <summary>Wie oft eine ausbleibende Antwort erneut angefragt wird, bevor die Adresse als "kein PTR" gilt.</summary>
        private const int QueryRetries = 3;

        /// <summary>
        /// Wie lange je Versuch auf eine Antwort gewartet wird. Kurz gehalten:
        /// eine einzelne Rueckwaertsaufloesung, die zwei Sekunden braucht, wird
        /// auch nach zehn nicht besser - stattdessen zaehlt <see cref="QueryRetries"/>
        /// mehr als ein langes Warten, weil ein Heim-DNS-Server verlorene Pakete
        /// eher durch eine zweite Chance kurz danach wettmacht als durch mehr
        /// Geduld beim ersten Versuch.
        /// </summary>
        private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(1);

        /// <summary>
        /// Gesamtbudget je Adresse, ueber alle Wiederholungen hinweg. Der
        /// aeussere Abbruch (<see cref="CancellationTokenSource.CancelAfter"/>)
        /// muss dafuer mehr Zeit einraeumen als <see cref="QueryTimeout"/> allein -
        /// sonst reisst er die Abfrage schon beim ersten Versuch ab, und die im
        /// Client konfigurierten Wiederholungen kommen nie zum Zug.
        /// </summary>
        private static readonly TimeSpan QueryBudget =
            QueryTimeout * (QueryRetries + 1) + TimeSpan.FromMilliseconds(500);

        /// <summary>
        /// Ein Client je Namensserver-Zusammenstellung, ueber den ganzen Lauf
        /// hinweg.
        /// <para>
        /// Vorher wurde je Adresse ein neuer <see cref="LookupClient"/> gebaut.
        /// Der bringt seinen eigenen Zwischenspeicher mit - je Abfrage neu
        /// erzeugt, ist der immer leer, und dieselbe Zone wird hundertfach neu
        /// erfragt. Wiederverwendet traegt er dagegen ueber den ganzen Lauf.
        /// </para>
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
                LookupClientOptions options;

                if (servers.Count > 0 && servers.All(s => IPAddress.TryParse(s, out IPAddress? _)))
                {
                    options = new LookupClientOptions([.. servers.Select(s => new NameServer(IPAddress.Parse(s)))]);
                }
                else
                {
                    // Ohne eigene Angabe die Server des Systems - dieselben,
                    // die auch der Rest des Rechners benutzt.
                    options = new LookupClientOptions();
                }

                options.Timeout = QueryTimeout;
                options.Retries = QueryRetries;
                options.UseCache = true;

                // Ein fehlender Eintrag ist eine Antwort, kein Fehler. Als
                // Ausnahme geworfen, kostet er nur Zeit.
                options.ThrowDnsErrors = false;

                return new LookupClient(options);
            });
        }

        /// <summary>
        /// Ein Client je einzelnem Namensserver, fuer den Deep-Scan - derselbe
        /// Grund wie bei <see cref="ClientFor"/>, nur nach Server statt nach
        /// Server-Zusammenstellung geschluesselt.
        /// </summary>
        private LookupClient SingleServerClientFor(NameServer dnsServer)
        {
            return _clients.GetOrAdd("single:" + dnsServer.Address, _ =>
            {
                LookupClientOptions options = new([dnsServer])
                {
                    Timeout = QueryTimeout,
                    Retries = QueryRetries,
                    UseCache = true,
                    ThrowDnsErrors = false
                };

                return new LookupClient(options);
            });
        }

        private async Task ReverseLookupToHostAndAliases(IPToScan ipToScan, bool isDeepDNSServerScan)
        {
            if (_cts.Token.IsCancellationRequested) return; // 🔹 Abbruch vor dem Start prüfen

            try
            {
                LookupClient client = ClientFor(ipToScan);

                using var cts = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                // Muss QueryBudget sein, nicht QueryTimeout: sonst reisst dieser
                // aeussere Abbruch die Abfrage schon nach dem ersten Versuch ab,
                // noch bevor der Client unten selbst zum zweiten kommt - genau
                // das hat die konfigurierten Retries bisher wirkungslos gemacht.
                cts.CancelAfter(QueryBudget);

                // Die abgeschickte Abfrage zaehlt. Neben "geantwortet" und
                // "gesamt" ergibt das die dreiteilige Anzeige, an der man sieht,
                // wie viel schon draussen ist und wie viel davon zurueckkam.
                int sentCount = Interlocked.Increment(ref current);
                ProgressUpdated?.Invoke(sentCount, responded, total, ScanStatus.running);

                // Eine Abfrage, kein eigener Wiederholungslauf: der Client
                // wiederholt selbst und kennt sein Zeitlimit. Die fruehere
                // Schleife hat daneben noch dreimal gefragt und dabei eine
                // Adresse ohne PTR-Eintrag - den Normalfall - wie einen Fehler
                // behandelt.
                IPHostEntry? _IPHostEntry = await client.GetHostEntryAsync(ipToScan.IPorHostname)
                                                        .WaitAsync(cts.Token);
                    var results = new List<string>();

                if (isDeepDNSServerScan)
                {
                    // Alle DNS-Server einzeln pruefen, welcher diesen Hostnamen
                    // aufloesen kann. Jeder Server bekommt sein eigenes
                    // Zeitbudget statt sich eines mit der ersten Abfrage und
                    // allen uebrigen Servern zu teilen - vorher lief das
                    // gemeinsame CancelAfter(QueryTimeout) schon fuer die
                    // Abfrage oben mit, und bei mehr als ein, zwei konfigurierten
                    // Servern blieb fuer die spaeteren nichts mehr uebrig; sie
                    // scheiterten dann lautlos an der bereits abgelaufenen Zeit,
                    // nicht am fehlenden Eintrag. Der Client wird ausserdem
                    // wiederverwendet statt bei jeder Adresse neu gebaut -
                    // derselbe Grund wie bei ClientFor().
                    foreach (var dnsServer in client.NameServers)
                    {
                        try
                        {
                            LookupClient singleLookup = SingleServerClientFor(dnsServer);

                            using CancellationTokenSource serverCts =
                                CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                            serverCts.CancelAfter(QueryBudget);

                            var result = await singleLookup.GetHostEntryAsync(ipToScan.IPorHostname).WaitAsync(serverCts.Token);

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
                    // Ab zwei Labels trennen, nicht erst ab drei: ein Name wie
                    // "fritz.box" oder "dns.google" hat nur zwei, landete vorher
                    // aber komplett im HostName-Feld statt sauber in Host+Domain
                    // getrennt zu werden - live an der eigenen FRITZ!Box
                    // (192.168.178.1 -> "fritz.box") nachgewiesen.
                    if (_IPHostEntry.HostName.Split('.').ToList().Count > 1)
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
