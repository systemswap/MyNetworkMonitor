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
    internal class ScanningMethode_ARP
    {
        public ScanningMethode_ARP(ScanResults scanResults)
        {
            _scannResults = scanResults;
        }

        ScanResults _scannResults;
        SupportMethods support = new SupportMethods();


        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref uint PhyAddrLen);

        private uint macAddrLen = (uint)new byte[6].Length;


        public async Task SendARPRequestAsync(List<string> IPs)
        {
            var tasks = new List<Task>();

            foreach (var ip in IPs)
            {
                var task = ArpRequestTask(IPAddress.Parse(ip));
                tasks.Add(task);
            }
            await Task.WhenAll(tasks);
        }

        private async Task ArpRequestTask(IPAddress ipAddress)
        {
            byte[] macAddr = new byte[6];

            try
            {
                _ = await Task.Run(() => SendARP(BitConverter.ToInt32(ipAddress.GetAddressBytes(), 0), 0, macAddr, ref macAddrLen));
                string mac = MacAddresstoString(macAddr);
                if (mac != "00-00-00-00-00-00")
                {
                    List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + ipAddress.ToString() + "'").ToList();
                    int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);
                    _scannResults.ResultTable.Rows[rowIndex]["Mac"] = mac;
                    _scannResults.ResultTable.Rows[rowIndex]["Vendor"] = support.GetVendorFromMac(mac).First();
                }
            }
            catch (Exception e)
            {
                //ConsoleExt.WriteLine(e.Message, ConsoleColor.Red);
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
        public void ARP_A()
        {
            try
            {
                //var list = new List<IPInfo>();

               
                string[] arpResult = GetARPResult().Split(new char[] { '\n', '\r' });

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

                            //list.Add(new IPInfo(mac, ip));

                            List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + ip + "'").ToList();

                            if (rows.Count == 0)
                            {
                                DataRow row = _scannResults.ResultTable.NewRow();

                                row["ARP"] = Properties.Resources.green_dot;
                                row["IP"] = ip;
                                row["MAC"] = mac;
                                row["Vendor"] = vendor[0];
                                _scannResults.ResultTable.Rows.Add(row);
                            }
                            else
                            {
                                int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);
                                _scannResults.ResultTable.Rows[rowIndex]["ARP"] = Properties.Resources.green_dot;
                                _scannResults.ResultTable.Rows[rowIndex]["IP"] = ip;
                                _scannResults.ResultTable.Rows[rowIndex]["MAC"] = mac;
                                _scannResults.ResultTable.Rows[rowIndex]["Vendor"] = vendor[0];
                            }
                        }
                    }
                }

                // Return list of IPInfo objects containing MAC / IP Address combinations
                //return list;
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
        private string GetARPResult()
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

                output = p.StandardOutput.ReadToEnd();

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
    }
}
