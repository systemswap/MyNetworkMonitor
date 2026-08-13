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





        /// <summary>
        /// Wie viele Adressen gleichzeitig abgefragt werden. Siehe Kommentar
        /// oben an der Semaphore.
        /// <para>
        /// Kein fester Wert mehr: die 8 sind die schonende Vorgabe fuer einen
        /// Heimrouter, ein Namensserver im Firmennetz vertraegt ein Vielfaches.
        /// Gesetzt wird das aus den Einstellungen.
        /// </para>
        /// </summary>
        public int MaxConcurrentLookups
        {
            get => _maxConcurrentLookups;
            set => _maxConcurrentLookups = value > 0 ? value : 1;
        }

        private int _maxConcurrentLookups = 8;

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

        /// <summary>
        /// Namensserver, die in diesem Lauf nur Zeitueberschreitungen
        /// geliefert haben, mit der Zahl ihrer Fehlversuche.
        /// <para>
        /// Ein Server, der gar keiner ist - etwa ein Gateway, das als Rueckfall
        /// eingetragen wurde -, kostet sonst bei <em>jeder</em> Adresse das
        /// volle Zeitbudget. Nach <see cref="SilentAfter"/> Fehlversuchen ohne
        /// eine einzige Antwort wird er fuer den Rest des Laufs uebergangen;
        /// eine Antwort setzt den Zaehler sofort zurueck, damit ein kurzer
        /// Aussetzer keinen brauchbaren Server aussperrt.
        /// </para>
        /// </summary>
        private readonly System.Collections.Concurrent.ConcurrentDictionary<string, int> _silence = new();

        /// <summary>So viele Fehlversuche in Folge gelten als "antwortet nicht".</summary>
        private const int SilentAfter = 3;

        /// <summary>
        /// Der Server, der zuletzt einen Namen geliefert hat. Er wird bei der
        /// naechsten Adresse zuerst gefragt.
        /// <para>
        /// In einem Netz mit mehreren Namensservern kennt oft nur einer die
        /// gesuchte Zone. Ihn zu merken macht aus dem Suchen beim ersten Mal
        /// eine einzige Abfrage bei allen weiteren. Kennt er ein Geraet
        /// <em>nicht</em>, aendert das nichts an seinem Rang: dann laeuft
        /// darunter wie bisher der ganze Durchgang ueber alle Server, denn
        /// dieses eine Geraet kann sehr wohl in der Zone eines anderen stehen.
        /// </para>
        /// </summary>
        private volatile string? _preferredServer;

        private bool IsKnownSilent(NameServer server) =>
            _silence.TryGetValue(server.Address.ToString(), out int misses) && misses >= SilentAfter;

        private void NoteSilence(NameServer server) =>
            _silence.AddOrUpdate(server.Address.ToString(), 1, (_, misses) => misses + 1);

        private void NoteAnswered(NameServer server) =>
            _silence[server.Address.ToString()] = 0;

        /// <summary>
        /// Fragt genau einen Server, mit eigenem Zeitbudget. Liefert den
        /// Eintrag oder <c>null</c>; ein Schweigen wird vermerkt, eine Antwort
        /// setzt den Zaehler zurueck.
        /// </summary>
        private async Task<IPHostEntry?> AskOneAsync(NameServer server, string address)
        {
            try
            {
                using CancellationTokenSource oneCts =
                    CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                oneCts.CancelAfter(QueryBudget);

                IPHostEntry? entry = await SingleServerClientFor(server)
                    .GetHostEntryAsync(address)
                    .WaitAsync(oneCts.Token);

                NoteAnswered(server);

                if (entry is not null) _preferredServer = server.Address.ToString();

                return entry;
            }
            catch (OperationCanceledException) when (!_cts.Token.IsCancellationRequested)
            {
                NoteSilence(server);
                return null;
            }
            catch (Exception)
            {
                return null;
            }
        }

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

                // Der Reihe nach fragen, nicht zufaellig: die Liste ist eine
                // Rangfolge - erst der Server des Bereichs oder das Gateway,
                // dann der Rueckhalt dahinter. Mit der Vorgabe (zufaellige
                // Wahl) waere sie bedeutungslos.
                options.UseRandomNameServer = false;

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
                IPHostEntry? _IPHostEntry = null;

                // Zuerst der Server, der zuletzt einen Namen geliefert hat.
                // Danach ist fuer die allermeisten Adressen schon Schluss - der
                // Rest darunter greift nur, wenn gerade er dieses Geraet nicht
                // kennt.
                if (_preferredServer is { } preferredAddress)
                {
                    NameServer? preferred = client.NameServers
                        .FirstOrDefault(s => s.Address.ToString() == preferredAddress);

                    if (preferred is not null)
                    {
                        _IPHostEntry = await AskOneAsync(preferred, ipToScan.IPorHostname);
                    }
                }

                // Steht vorn ein Server, der in diesem Lauf schon mehrfach
                // geschwiegen hat, wird die gemeinsame Abfrage uebersprungen -
                // sie liefe genau in dieselbe Zeitueberschreitung. Unten sind
                // die uebrigen Server ohnehin einzeln an der Reihe.
                NameServer? leading = client.NameServers.FirstOrDefault();
                bool firstServerSilent =
                    leading is not null && client.NameServers.Count > 1 && IsKnownSilent(leading);

                try
                {
                    if (_IPHostEntry is null && !firstServerSilent)
                    {
                        _IPHostEntry = await client.GetHostEntryAsync(ipToScan.IPorHostname)
                                                   .WaitAsync(cts.Token);

                        if (leading is not null) NoteAnswered(leading);
                    }
                }
                catch (OperationCanceledException) when (!_cts.Token.IsCancellationRequested)
                {
                    firstServerSilent = true;
                    if (leading is not null) NoteSilence(leading);

                    // Nur das Budget dieser einen Abfrage ist abgelaufen - der
                    // erste Server hat also nicht geantwortet. Das ist kein
                    // Grund aufzugeben: unten bekommt jeder Server seinen
                    // eigenen Anlauf mit eigenem Budget.
                    //
                    // Frueher riss dieser Abbruch die ganze Aufloesung mit, und
                    // ein stummer erster Server (etwa ein Gateway, das gar kein
                    // Namensserver ist) kostete jeden Namen im Lauf.
                }

                // Bleibt die erste Abfrage ohne Namen, wird jeder hinterlegte
                // Server einzeln gefragt, bis einer auflöst.
                //
                // Noetig, weil die erste Abfrage die Liste nur bei einem
                // *Fehlschlag* weiterreicht - antwortet ein Server "kenne ich
                // nicht", ist fuer sie Schluss. In einem Netz mit mehreren
                // Zonen kennt aber oft nur einer der Server den Namen, und
                // ohne diesen Durchgang entschiede allein, welcher Server
                // zufaellig vorne steht.
                if (_IPHostEntry is null && client.NameServers.Count > 1)
                {
                    // Hat der erste Server geschwiegen, wird er hier nicht noch
                    // einmal gefragt - er hat sein Budget gerade eben schon
                    // verbraucht, und ein zweiter Anlauf verdoppelt nur die
                    // Wartezeit je Adresse. Die Reihenfolge steht fest
                    // (UseRandomNameServer ist aus), also ist der erste der
                    // Liste auch der, der eben stumm blieb.
                    foreach (NameServer dnsServer in client.NameServers.Skip(firstServerSilent ? 1 : 0))
                    {
                        if (_cts.Token.IsCancellationRequested) return;

                        // Uebergangen wird, wer nur schweigt, und wer eben
                        // schon als bevorzugter Server gefragt wurde.
                        if (IsKnownSilent(dnsServer)) continue;
                        if (dnsServer.Address.ToString() == _preferredServer) continue;

                        IPHostEntry? single = await AskOneAsync(dnsServer, ipToScan.IPorHostname);

                        if (single is not null)
                        {
                            _IPHostEntry = single;
                            break;
                        }
                    }
                }

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


                // Bewusst der Abbruch des Laufs und nicht mehr das Zeitbudget
                // dieser Abfrage: seit die erste Abfrage ihr Budget ueberziehen
                // darf, ist "cts" hier regelmaessig abgelaufen, obwohl ein
                // spaeterer Server laengst geantwortet hat. Mit cts.Token waere
                // genau dieses Ergebnis wieder weggeworfen worden.
                if (_cts.Token.IsCancellationRequested) return;


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
