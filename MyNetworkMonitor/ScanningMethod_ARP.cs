using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    internal class ScanningMethod_ARP
    {
        public ScanningMethod_ARP()
        {

        }

        SupportMethods support = new SupportMethods();

        public event EventHandler<ScanTask_Finished_EventArgs>? ARP_A_newDevice;
        public event EventHandler<ScanTask_Finished_EventArgs> ARP_Request_Task_Finished;
        public event EventHandler<Method_Finished_EventArgs> ARP_Request_Finished;


        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref uint PhyAddrLen);

        public async Task SendARPRequestAsync(List<IPToScan> ipsToRefresh)
        {
            var tasks = new List<Task>();

            Parallel.ForEach(ipsToRefresh, ip =>
            {
                if (!string.IsNullOrEmpty(ip.IP))
                {
                    var task = ArpRequestTask(ip);
                    if (task != null) tasks.Add(task);
                }
            });
            await Task.WhenAll(tasks.Where(t => t != null));

            if (ARP_Request_Finished != null)
            {
                ARP_Request_Finished(this, new Method_Finished_EventArgs());
            }
        }

        private async Task ArpRequestTask(IPToScan ipToScan)
        {
            IPAddress ipAddress = IPAddress.Parse(ipToScan.IP);
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


                    ipToScan.UsedScanMethod = ScanMethod.ARP;

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
                                    ipToScan = IPs.Where(i => string.Equals(i.IP, ip)).ToList()[0];
                                    ipToScan.ARPStatus = true;
                                    ipToScan.MAC = mac;
                                    ipToScan.Vendor = vendor[0];
                                }
                                catch (Exception)
                                {
                                    ipToScan = new IPToScan();
                                    ipToScan.ARPStatus = true;
                                    ipToScan.IP = ip;
                                    ipToScan.MAC = mac;
                                    ipToScan.Vendor = vendor[0];
                                    ipToScan.IPGroupDescription = "not specified";
                                    ipToScan.DeviceDescription = "not specified";
                                }

                                ipToScan.UsedScanMethod = ScanMethod.ARP;

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
    }
}
