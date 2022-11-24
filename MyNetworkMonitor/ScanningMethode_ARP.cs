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
        public ScanningMethode_ARP()
        {
           
        }

        SupportMethods support = new SupportMethods();

        public event EventHandler<ARP_A_Finished_EventArgs>? ARP_A_Finished;

        public event EventHandler<ARP_Request_Task_Finished_EventArgs> ARP_Request_Task_Finished;
        public event EventHandler<ARP_Request_Finished_EventArgs> ARP_Request_Finished;


        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref uint PhyAddrLen);

        private uint macAddrLen = (uint)new byte[6].Length;


        public async Task SendARPRequestAsync(List<string> IPs)
        {
            var tasks = new List<Task>();

            Parallel.ForEach(IPs, ip =>
            {
                if (!string.IsNullOrEmpty(ip))
                {
                    var task = ArpRequestTask(IPAddress.Parse(ip));
                    tasks.Add(task);
                }
            });
            await Task.WhenAll(tasks);

            if (ARP_Request_Finished != null)
            {
                ARP_Request_Finished(this, new ARP_Request_Finished_EventArgs(true));
            }
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
                    if (ARP_Request_Task_Finished != null)
                    {
                        ARP_Request_Task_Finished(this, new ARP_Request_Task_Finished_EventArgs(ipAddress.ToString(), mac, support.GetVendorFromMac(mac).First()));
                    }
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
        public void ARP_A(ScanResults _scannResults)
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

                            List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + ip + "'").ToList();

                            if (rows.Count == 0)
                            {
                                DataRow row = _scannResults.ResultTable.NewRow();

                                row["ARPStatus"] = Properties.Resources.green_dot;
                                row["IP"] = ip;
                                row["MAC"] = mac;
                                row["Vendor"] = vendor[0];
                                _scannResults.ResultTable.Rows.Add(row);
                            }
                            else
                            {
                                int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);
                                _scannResults.ResultTable.Rows[rowIndex]["ARPStatus"] = Properties.Resources.green_dot;
                                _scannResults.ResultTable.Rows[rowIndex]["IP"] = ip;
                                _scannResults.ResultTable.Rows[rowIndex]["MAC"] = mac;
                                _scannResults.ResultTable.Rows[rowIndex]["Vendor"] = vendor[0];
                            }
                        }
                    }
                }

                if (ARP_A_Finished != null)
                {
                    ARP_A_Finished(this, new ARP_A_Finished_EventArgs(true));
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

    public class ARP_A_Finished_EventArgs : EventArgs
    {
        private bool _finished = false;
        public bool ARP_A_Finished { get { return _finished; } }
        public ARP_A_Finished_EventArgs(bool ARP_A_Finished)
        {
            _finished = ARP_A_Finished;
        }
    }



    public class ARP_Request_Task_Finished_EventArgs : EventArgs
    {
        public ARP_Request_Task_Finished_EventArgs(string IP, string MAC, string Vendor)
        {
            _IP = IP;
            _MAC = MAC;
            _Vendor = Vendor;
        }

        private string _IP = string.Empty;
        public string IP { get { return _IP; } }

        private string _MAC = string.Empty;
        public string MAC { get { return _MAC; } }

        private string _Vendor = string.Empty;
        public string Vendor { get { return _Vendor; } }

    }

    public class ARP_Request_Finished_EventArgs : EventArgs
    {
        public ARP_Request_Finished_EventArgs(bool ARP_Request_Finished)
        {
            _finished = ARP_Request_Finished;
        }

        private bool _finished = false;
        public bool ARP_Request_Finished { get { return _finished; } }
        
    }
}
