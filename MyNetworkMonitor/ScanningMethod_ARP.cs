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

            List<IPToScan> filtered = GetIPsInSameVLAN(ipsToRefresh);

            total = filtered.Count;
            ProgressUpdated?.Invoke(current, responded, total);


            //var tasks = new List<Task>();

            //Parallel.ForEach(ipsToRefresh, ip =>
            //{
            //    if (!string.IsNullOrEmpty(ip.IPorHostname))
            //    {
            //        var task = ArpRequestTask(ip);
            //        if (task != null) tasks.Add(task);
            //    }
            //});

            var tasks = new List<Task>();

            //foreach (var ip in ipsToRefresh.Where(ip => !string.IsNullOrEmpty(ip.IPorHostname)))
            foreach (var ip in filtered.Where(ip => !string.IsNullOrEmpty(ip.IPorHostname)))
            {
                tasks.Add(ArpRequestTask(ip));

                await Task.Delay(20);
            }

            await Task.WhenAll(tasks);

            // mit ? prüft man ob das event im hauptthread auch angelegt wurde mit +=
            ARP_Request_Finished?.Invoke(this, new Method_Finished_EventArgs() { ScanStatus = MainWindow.ScanStatus.finished});
        }

        private async Task ArpRequestTask(IPToScan ipToScan)
        {
            IPAddress ipAddress = IPAddress.Parse(ipToScan.IPorHostname);
            byte[] macAddr = new byte[6];
            uint macAddrLen = (uint)macAddr.Length;

            int arp_response = await Task.Run(() => SendARP(BitConverter.ToInt32(ipAddress.GetAddressBytes(), 0), 0, macAddr, ref macAddrLen));

            if (arp_response != 0)
            {
                if (ARP_Request_Task_Finished != null)
                {
                    ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs();

                    scanTask_Finished.ipToScan.UsedScanMethod = ScanMethod.failed;

                    ARP_Request_Task_Finished(this, scanTask_Finished);
                }
            }
            else
            {
                string[] str = new string[(int)macAddrLen];
                for (int i = 0; i < macAddrLen; i++)
                {
                    str[i] = macAddr[i].ToString("x2");
                }
                string mac = string.Join("-", str);

                if (ARP_Request_Task_Finished != null)
                {
                    ipToScan.ARPStatus = true;
                    ipToScan.MAC = mac;
                    ipToScan.Vendor = support.GetVendorFromMac(mac).First();


                    ipToScan.UsedScanMethod = ScanMethod.ARPRequest;

                    ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs();
                    scanTask_Finished.ipToScan = ipToScan;

                    ARP_Request_Task_Finished(this, scanTask_Finished);
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
            try
            {
                string str_arpResult = await GetARPResult();
                string[] arpResult = str_arpResult.Split(new char[] { '\n', '\r' });

                foreach (var arp in arpResult)
                {
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


















        public static List<IPToScan> GetIPsInSameVLAN(List<IPToScan> ipsToRefresh)
        {
            var knownIps = GetLocalArpTable();      // 1️⃣ ARP-Tabelle abrufen
            string gateway = GetDefaultGateway();   // 2️⃣ Standard-Gateway bestimmen
            var routingTable = GetRoutingTable();   // 3️⃣ Routing-Tabelle abrufen
            string subnetMask = GetSubnetMaskViaSnmp(gateway); // 4️⃣ SNMP-Subnetzmaske abrufen

            return ipsToRefresh.Where(ip =>
                knownIps.Contains(ip.IPorHostname) || // Ist IP in ARP-Tabelle?
                (gateway != null && ip.IPorHostname.StartsWith(gateway.Substring(0, gateway.LastIndexOf('.')))) || // Gehört IP zum Gateway-Netz?
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