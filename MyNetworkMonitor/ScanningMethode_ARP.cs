using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
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

        public string? SendArpRequest(IPAddress ipAddress)
        {
            byte[] macAddr = new byte[6];

            try
            {
                _ = SendARP(BitConverter.ToInt32(ipAddress.GetAddressBytes(), 0), 0, macAddr, ref macAddrLen);
                if (MacAddresstoString(macAddr) != "00-00-00-00-00-00")
                {
                    return MacAddresstoString(macAddr);
                }
            }
            catch (Exception e)
            {
                //ConsoleExt.WriteLine(e.Message, ConsoleColor.Red);
            }
            return null;
        }

        public static string MacAddresstoString(byte[] macAdrr)
        {
            string macString = BitConverter.ToString(macAdrr);
            return macString.ToUpper();
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

                foreach (var arp in GetARPResult().Split(new char[] { '\n', '\r' }))
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
                            var vendor = support.GetVendorFromMac(mac.Replace("-",":"));

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
