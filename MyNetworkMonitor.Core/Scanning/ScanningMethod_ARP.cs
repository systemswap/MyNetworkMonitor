using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using MyNetworkMonitor.Core.Services;
namespace MyNetworkMonitor
{
    public class ScanningMethod_ARP
    {
        private readonly IArpProvider _arp;

        /// <summary>
        /// <paramref name="routingProvider"/> wird nicht mehr ausgewertet: die
        /// Vorauswahl der Ziele richtet sich nach den Netzen der aktiven
        /// Adapter, nicht nach der Routing-Tabelle. Der Parameter bleibt, damit
        /// bestehende Aufrufe unveraendert uebersetzen.
        /// </summary>
        public ScanningMethod_ARP(IArpProvider? arpProvider = null, IRoutingProvider? routingProvider = null)
        {
            // Ohne Injection kommen die vom Startprojekt registrierten
            // Plattform-Provider zum Einsatz – die Scan-Logik bleibt unveraendert.
            _arp = arpProvider ?? PlatformServices.Arp;
        }
        
        
        
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
        




        SupportMethods support = new SupportMethods();

        public event Action<int, int, int, ScanStatus> ProgressUpdated;
        public event EventHandler<ScanTask_Finished_EventArgs>? ARP_A_newDevice;
        public event EventHandler<ScanTask_Finished_EventArgs> ARP_Request_Task_Finished;
        public event Action<ScanStatus> ARP_Request_Finished;


        


        public async Task SendARPRequestAsync(List<IPToScan> ipsToRefresh)
        {
            StartNewScan();

            if (_cts.Token.IsCancellationRequested) return; // 🔹 Sofort abbrechen
            
            current = 0;
            responded = 0;
            total = 0;
            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running);

            List<IPToScan> filtered;
            try
            {
                filtered = await GetIPsInSameVLANAsync(ipsToRefresh).WaitAsync(_cts.Token);
            }
            catch (TaskCanceledException)
            {
                Debug.WriteLine("Task für GetIPsInSameVLANAsync wurde abgebrochen.");
                return; // Beende die Methode sauber
            }

            // Frueher wurde bei hoechstens einem Treffer die ganze Liste
            // wiederhergestellt. Das hob die Beschraenkung genau dann auf,
            // wenn sie am meisten gebracht haette: wenn nichts davon lokal
            // erreichbar ist. Ein leeres Ergebnis ist hier eine Antwort.
            total = filtered.Count;
            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running);

            try
            {
                await Parallel.ForEachAsync(filtered.Where(ip => !string.IsNullOrEmpty(ip.IPorHostname)), _cts.Token,
                    async (ip, token) =>
                    {
                        token.ThrowIfCancellationRequested(); // 🔹 Sofort abbrechen, wenn gefordert
                        await ArpRequestTask(ip);
                    });
            }
            catch (OperationCanceledException)
            {
                Debug.WriteLine("Scan wurde abgebrochen!");
            }
            finally
            {
                // 🔹 Sicherstellen, dass der Scan als beendet gemeldet wird
                ARP_Request_Finished?.Invoke(ScanStatus.finished);
            }
        }


        private async Task ArpRequestTask(IPToScan ipToScan)
        {
            _cts.Token.ThrowIfCancellationRequested(); // 🔹 Falls abgebrochen, sofort raus

            if (_cts.Token.IsCancellationRequested) return;

            IPAddress ipAddress = IPAddress.Parse(ipToScan.IPorHostname);

            string? mac = await _arp.ResolveMacAsync(ipAddress, _cts.Token);

            // Erst hochzaehlen, wenn die Anfrage beantwortet oder abgelaufen
            // ist - beim Versenden stuende der Balken viel zu frueh am Ende.
            int currentValue = Interlocked.Increment(ref current);
            ProgressUpdated?.Invoke(currentValue, responded, total, ScanStatus.running);

            if (_cts.Token.IsCancellationRequested) return;

            if (mac == null)
            {
                ARP_Request_Task_Finished?.Invoke(this, new ScanTask_Finished_EventArgs()
                {
                    ipToScan = { UsedScanMethod = ScanMethod.failed }
                });
            }
            else
            {
                if (ARP_Request_Task_Finished != null)
                {
                    ipToScan.ARPStatus = true;
                    ipToScan.MAC = mac;
                    ipToScan.Vendor = support.GetVendorFromMac(mac).First();
                    ipToScan.UsedScanMethod = ScanMethod.ARPRequest;

                    int respondedValue = Interlocked.Increment(ref responded);
                    ProgressUpdated?.Invoke(current, respondedValue, total, ScanStatus.running);

                    ARP_Request_Task_Finished(this, new ScanTask_Finished_EventArgs() { ipToScan = ipToScan });
                }
            }
        }


















        private string MacAddresstoString(byte[] MacAddress)
        {
            return BitConverter.ToString(MacAddress);
        }



        /// <summary>
        /// Retrieves the IPInfo for All machines on the local network.
        /// </summary>
        /// <returns></returns>
        public async Task ARP_A(List<IPToScan> IPs)
        {
            StartNewScan();

            try
            {
                var arpTable = await _arp.GetArpTableAsync(_cts.Token);

                foreach (var entry in arpTable)
                {
                    if (_cts.Token.IsCancellationRequested) break;

                    string ip = entry.IpAddress;
                    string mac = entry.MacAddress;
                    var vendor = support.GetVendorFromMac(mac);

                    if (ARP_A_newDevice != null)
                    {
                        IPToScan ipToScan;

                        try
                        {
                            ipToScan = IPs.Where(i => string.Equals(i.IPorHostname, ip)).ToList()[0];
                            ipToScan.ARPStatus = true;
                            ipToScan.MAC = mac;
                            ipToScan.Vendor = vendor[0];
                        }
                        catch (Exception)
                        {
                            ipToScan = new IPToScan();
                            ipToScan.ARPStatus = true;
                            ipToScan.IPorHostname = ip;
                            ipToScan.MAC = mac;
                            ipToScan.Vendor = vendor[0];
                            ipToScan.IPGroupDescription = "not specified";
                            ipToScan.DeviceDescription = "not specified";
                        }

                        ipToScan.UsedScanMethod = ScanMethod.ARP_A;

                        ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs();
                        scanTask_Finished.ipToScan = ipToScan;

                        Task.Run(() => ARP_A_newDevice(this, scanTask_Finished));
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception("IPInfo: Error Parsing 'arp -a' results", ex);
            }
        }

        public bool DeleteARPCache()
        {
            return _arp.FlushArpCache();
        }


















        /// <summary>
        /// Grenzt die Zielliste auf das ein, was ARP ueberhaupt beantworten
        /// kann.
        /// <para>
        /// Eine ARP-Anfrage bleibt im eigenen Netzsegment: sie geht als
        /// Broadcast raus, und nur wer daran haengt, hoert sie. Alles hinter
        /// einem Router kann per Definition nicht antworten - jede solche
        /// Anfrage ist reine Wartezeit bis zum Timeout. Massgeblich ist
        /// deshalb, wo ein <em>aktiver</em> Adapter steht und welche Maske er
        /// traegt, nicht, wohin die Routing-Tabelle zeigt.
        /// </para>
        /// </summary>
        public async Task<List<IPToScan>> GetIPsInSameVLANAsync(List<IPToScan> ipsToRefresh)
        {
            List<LocalSubnet> subnets = GetLocalSubnets();

            // Dazu, was ohnehin schon aufgeloest ist: ein Eintrag in der
            // Tabelle beweist, dass die Adresse erreichbar war.
            HashSet<string> knownIps = new(await GetLocalArpTableAsync(), StringComparer.OrdinalIgnoreCase);

            if (subnets.Count == 0 && knownIps.Count == 0)
            {
                // Kein aktiver IPv4-Adapter und keine Tabelle - dann ist gar
                // nichts bekannt, und lieber alles versuchen als nichts.
                return ipsToRefresh;
            }

            List<IPToScan> reachable = [.. ipsToRefresh.Where(ip => IsReachableByArp(ip.IPorHostname, subnets, knownIps))];

            Debug.WriteLine($"ARP: {reachable.Count} von {ipsToRefresh.Count} Zielen liegen an einem aktiven Adapter.");

            return reachable;
        }

        /// <summary>Ein Netz, an dem ein aktiver Adapter dieses Rechners haengt.</summary>
        private sealed record LocalSubnet(byte[] Address, byte[] Mask)
        {
            public bool Contains(byte[] candidate)
            {
                for (int i = 0; i < 4; i++)
                {
                    if ((candidate[i] & Mask[i]) != (Address[i] & Mask[i])) return false;
                }

                return true;
            }
        }

        /// <summary>
        /// Die IPv4-Netze aller betriebsbereiten Adapter. Loopback und Tunnel
        /// bleiben draussen - dort gibt es niemanden, den man per Broadcast
        /// fragen koennte.
        /// </summary>
        private static List<LocalSubnet> GetLocalSubnets()
        {
            List<LocalSubnet> subnets = [];

            foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (adapter.OperationalStatus != OperationalStatus.Up) continue;

                if (adapter.NetworkInterfaceType is NetworkInterfaceType.Loopback
                                                 or NetworkInterfaceType.Tunnel)
                {
                    continue;
                }

                foreach (UnicastIPAddressInformation address in adapter.GetIPProperties().UnicastAddresses)
                {
                    if (address.Address.AddressFamily != AddressFamily.InterNetwork) continue;

                    // Ohne Maske laesst sich das Netz nicht bestimmen; ein
                    // geratenes /24 waere genau der Fehler, der hier weg soll.
                    IPAddress? mask = address.IPv4Mask;
                    if (mask == null || mask.Equals(IPAddress.Any)) continue;

                    subnets.Add(new LocalSubnet(address.Address.GetAddressBytes(), mask.GetAddressBytes()));
                }
            }

            return subnets;
        }

        private static bool IsReachableByArp(string? address, List<LocalSubnet> subnets, HashSet<string> knownIps)
        {
            if (string.IsNullOrWhiteSpace(address)) return false;

            if (knownIps.Contains(address)) return true;

            // ARP gibt es nur ueber IPv4. Hostnamen und IPv6-Adressen gehoeren
            // anderen Verfahren - hier wuerden sie beim Parsen fliegen und den
            // ganzen Lauf mitnehmen.
            if (!IPAddress.TryParse(address, out IPAddress? parsed)
                || parsed.AddressFamily != AddressFamily.InterNetwork)
            {
                return false;
            }

            byte[] bytes = parsed.GetAddressBytes();

            return subnets.Any(subnet => subnet.Contains(bytes));
        }


        private async Task<List<string>> GetLocalArpTableAsync()
        {
            var table = await _arp.GetArpTableAsync();
            return table.Select(e => e.IpAddress).ToList();
        }


    }
}