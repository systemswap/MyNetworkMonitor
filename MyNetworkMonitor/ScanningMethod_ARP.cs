using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using SnmpSharpNet;
namespace MyNetworkMonitor
{
    internal class ScanningMethod_ARP
    {
        public ScanningMethod_ARP()
        {

        }

        private CancellationTokenSource _cts = new CancellationTokenSource(); // 🔹 Ermöglicht das Abbrechen
     
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

            //ProgressUpdated?.Invoke(current, responded, total); // 🔹 UI auf 0 setzen
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

        public event Action<int, int, int> ProgressUpdated;
        public event EventHandler<ScanTask_Finished_EventArgs>? ARP_A_newDevice;
        public event EventHandler<ScanTask_Finished_EventArgs> ARP_Request_Task_Finished;
        public event EventHandler<Method_Finished_EventArgs> ARP_Request_Finished;


        private int current = 0;
        private int responded = 0;
        private int total = 0;


        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref uint PhyAddrLen);

        public async Task SendARPRequestAsync(List<IPToScan> ipsToRefresh)
        {
            StartNewScan();

            if (_cts.Token.IsCancellationRequested) return; // 🔹 Sofort abbrechen
            
            current = 0;
            responded = 0;
            total = 0;
            ProgressUpdated?.Invoke(current, responded, total);

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

            if (filtered.Count <= 1) filtered = ipsToRefresh;
          
            total = filtered.Count;
            ProgressUpdated?.Invoke(current, responded, total);

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
                ARP_Request_Finished?.Invoke(this, new Method_Finished_EventArgs()
                {
                    ScanStatus = MainWindow.ScanStatus.finished
                });
            }
        }


        private async Task ArpRequestTask(IPToScan ipToScan)
        {
            _cts.Token.ThrowIfCancellationRequested(); // 🔹 Falls abgebrochen, sofort raus

            Interlocked.Increment(ref current); // 🔹 Thread-sicheres Hochzählen
            ProgressUpdated?.Invoke(current, responded, total);

            if (_cts.Token.IsCancellationRequested) return;

            IPAddress ipAddress = IPAddress.Parse(ipToScan.IPorHostname);
            byte[] macAddr = new byte[6];
            uint macAddrLen = (uint)macAddr.Length;

            int arp_response = await Task.Run(() =>
            {
                _cts.Token.ThrowIfCancellationRequested(); // 🔹 Falls abgebrochen, sofort raus
                return SendARP(BitConverter.ToInt32(ipAddress.GetAddressBytes(), 0), 0, macAddr, ref macAddrLen);
            }, _cts.Token);

            if (_cts.Token.IsCancellationRequested || arp_response == -1) return;

            if (arp_response != 0)
            {
                ARP_Request_Task_Finished?.Invoke(this, new ScanTask_Finished_EventArgs()
                {
                    ipToScan = { UsedScanMethod = ScanMethod.failed }
                });
            }
            else
            {
                string mac = string.Join("-", macAddr.Take((int)macAddrLen).Select(b => b.ToString("x2")));

                if (ARP_Request_Task_Finished != null)
                {
                    ipToScan.ARPStatus = true;
                    ipToScan.MAC = mac;
                    ipToScan.Vendor = support.GetVendorFromMac(mac).First();
                    ipToScan.UsedScanMethod = ScanMethod.ARPRequest;

                    Interlocked.Increment(ref responded); // 🔹 Thread-sicheres Hochzählen
                    ProgressUpdated?.Invoke(current, responded, total);

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
                string str_arpResult = await GetARPResult().WaitAsync(_cts.Token);
                string[] arpResult = str_arpResult.Split(new char[] { '\n', '\r' });

                foreach (var arp in arpResult)
                {
                    if (_cts.Token.IsCancellationRequested) break;

                    // Parse out all the MAC / IP Address combinations
                    if (!string.IsNullOrEmpty(arp))
                    {
                        var pieces = (from piece in arp.Split(new char[] { ' ', '\t' })
                                      where !string.IsNullOrEmpty(piece)
                                      select piece).ToArray();
                        if (pieces.Length == 3)
                        {

                            string ip = pieces[0];
                            string mac = pieces[1];
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

                                ARP_A_newDevice(this, scanTask_Finished);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception("IPInfo: Error Parsing 'arp -a' results", ex);
            }
        }

        /// <summary>
        /// This runs the "arp" utility in Windows to retrieve all the MAC / IP Address entries.
        /// </summary>
        /// <returns></returns>
        private async Task<string> GetARPResult()
        {
            Process p = null;
            string output = string.Empty;

            try
            {
                p = Process.Start(new ProcessStartInfo("arp", "-a")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true
                });

                output = await p.StandardOutput.ReadToEndAsync();

                p.Close();
            }
            catch (Exception ex)
            {
                throw new Exception("IPInfo: Error Retrieving 'arp -a' Results", ex);
            }
            finally
            {
                if (p != null)
                {
                    p.Close();
                }
            }
            return output;
        }

        public bool DeleteARPCache()
        {
            Process p = null;
            string output = string.Empty;

            try
            {
                p = Process.Start(new ProcessStartInfo("arp", "-d")
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true
                });

                p.Close();
            }
            catch (Exception ex)
            {
                //throw new Exception("IPInfo: Error Retrieving 'arp -a' Results", ex);
            }
            finally
            {
                if (p != null)
                {
                    p.Close();
                }
            }
            return true;
        }


















        public static async Task<List<IPToScan>> GetIPsInSameVLANAsync(List<IPToScan> ipsToRefresh)
        {
            var knownIpsTask = Task.Run(() => GetLocalArpTable()); // 1️⃣ ARP-Tabelle abrufen (asynchron)
            var gatewayTask = Task.Run(() => GetDefaultGateway()); // 2️⃣ Standard-Gateway bestimmen (asynchron)
            var routingTableTask = Task.Run(() => GetRoutingTable()); // 3️⃣ Routing-Tabelle abrufen (asynchron)

            await Task.WhenAll(knownIpsTask, gatewayTask, routingTableTask);

            List<string> knownIps = await knownIpsTask;
            string gateway = await gatewayTask;
            List<string> routingTable = await routingTableTask;
            string subnetMask = await Task.Run(() => GetSubnetMaskViaSnmp(gateway)); // 4️⃣ SNMP-Subnetzmaske abrufen (asynchron)

            return ipsToRefresh.Where(ip =>
                knownIps.Contains(ip.IPorHostname) || // Ist IP in ARP-Tabelle?
                (!string.IsNullOrEmpty(gateway) && ip.IPorHostname.StartsWith(gateway.Substring(0, gateway.LastIndexOf('.')))) || // Gehört IP zum Gateway-Netz?
                routingTable.Any(route => ip.IPorHostname.StartsWith(route.Substring(0, route.LastIndexOf('.')))) || // Gehört IP zu bekannten Routen?
                (subnetMask != "255.255.255.255" && IsIpInSubnet(ip.IPorHostname, gateway, subnetMask)) // Falls SNMP-Subnetzmaske sinnvoll ist
            ).ToList();
        }


        private static List<string> GetLocalArpTable()
        {
            var ipList = new List<string>();
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "arp",
                    Arguments = "-a",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            var matches = Regex.Matches(output, @"(\d+\.\d+\.\d+\.\d+)\s+");
            foreach (Match match in matches)
            {
                ipList.Add(match.Groups[1].Value);
            }

            return ipList;
        }

        private static string GetDefaultGateway()
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up)
                .SelectMany(n => n.GetIPProperties().GatewayAddresses)
                .Select(g => g.Address.ToString())
                .FirstOrDefault();
        }

        private static List<string> GetRoutingTable()
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "route",
                    Arguments = "print",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            var matches = Regex.Matches(output, @"(\d+\.\d+\.\d+\.\d+)\s+255");
            return matches.Cast<Match>().Select(m => m.Groups[1].Value).ToList();
        }

        private static string GetSubnetMaskViaSnmp(string gatewayIp, string community = "public")
        {
            if (string.IsNullOrEmpty(gatewayIp)) return "255.255.255.255"; // Fallback

            try
            {
                SimpleSnmp snmp = new SimpleSnmp(gatewayIp) { Timeout = 2000 };

                // SNMP OID für Subnetzmaske
                var result = snmp.Walk(SnmpVersion.Ver2, "1.3.6.1.2.1.4.20.1.3");

                if (result == null || result.Count == 0)
                {
                    Console.WriteLine("❌ Keine SNMP-Subnetzmaske erhalten.");
                    return "255.255.255.255";
                }

                string localIp = SupportMethods.SelectedNetworkInterfaceInfos.IPv4_string;
                foreach (var kvp in result)
                {
                    if (kvp.Key.ToString().EndsWith("." + localIp))
                    {
                        Console.WriteLine($"✅ SNMP-Subnetzmaske gefunden: {kvp.Value}");
                        return kvp.Value.ToString();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Fehler bei der SNMP-Abfrage: {ex.Message}");
            }

            return "255.255.255.255"; // Falls keine brauchbare Subnetzmaske gefunden wird
        }

      

        private static bool IsIpInSubnet(string ipAddress, string networkIp, string subnetMask)
        {
            var ip = IPAddress.Parse(ipAddress).GetAddressBytes();
            var network = IPAddress.Parse(networkIp).GetAddressBytes();
            var mask = IPAddress.Parse(subnetMask).GetAddressBytes();

            for (int i = 0; i < 4; i++)
            {
                if ((ip[i] & mask[i]) != (network[i] & mask[i]))
                {
                    return false;
                }
            }

            return true;
        }
    }
}