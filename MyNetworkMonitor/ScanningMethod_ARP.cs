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

        public event EventHandler<ARP_A_newDevice_EventArgs>? ARP_A_newDevice;

        public event EventHandler<ARP_Request_Task_Finished_EventArgs> ARP_Request_Task_Finished;
        public event EventHandler<ARP_Request_Finished_EventArgs> ARP_Request_Finished;


        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        private static extern int SendARP(int DestIP, int SrcIP, byte[] pMacAddr, ref uint PhyAddrLen);
       


        //private uint macAddrLen = (uint)new byte[6].Length;
       
        //public async Task SendARPRequestAsync(List<string> IPs)
        //{
        //    var tasks = new List<Task>();

        //    Parallel.ForEach(IPs, ip =>
        //    {
        //        if (!string.IsNullOrEmpty(ip))
        //        {
        //            var task = ArpRequestTask(IPAddress.Parse(ip));
        //            tasks.Add(task);
        //        }
        //    });
        //    await Task.WhenAll(tasks);

        //    if (ARP_Request_Finished != null)
        //    {
        //        ARP_Request_Finished(this, new ARP_Request_Finished_EventArgs(true));
        //    }
        //}

        //private async Task ArpRequestTask(IPAddress ipAddress)
        //{
        //    byte[] macAddr = new byte[6];

        //    try
        //    {
        //        _ = await Task.Run(() => SendARP(BitConverter.ToInt32(ipAddress.GetAddressBytes(), 0), 0, macAddr, ref macAddrLen));
        //        string mac = MacAddresstoString(macAddr);
        //        if (mac != "00-00-00-00-00-00")
        //        {
        //            if (ARP_Request_Task_Finished != null)
        //            {
        //                ARP_Request_Task_Finished(this, new ARP_Request_Task_Finished_EventArgs(ipAddress.ToString(), mac, support.GetVendorFromMac(mac).First()));
        //            }
        //        }
        //        else
        //        {
        //            if (ARP_Request_Task_Finished != null)
        //            {
        //                ARP_Request_Task_Finished(this, new ARP_Request_Task_Finished_EventArgs(string.Empty, string.Empty, string.Empty));
        //            }
        //        }
        //    }
        //    catch (Exception e)
        //    {
        //        //ConsoleExt.WriteLine(e.Message, ConsoleColor.Red);
        //    }
        //}




        public async Task SendARPRequestAsync(List<IPToRefresh> ipsToRefresh)
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
            await Task.WhenAll(tasks);

            if (ARP_Request_Finished != null)
            {
                ARP_Request_Finished(this, new ARP_Request_Finished_EventArgs(true));
            }
        }

        private async Task ArpRequestTask(IPToRefresh IPAddr)
        {
            IPAddress IP = IPAddress.Parse(IPAddr.IP);
            byte[] macAddr = new byte[6];
            uint macAddrLen = (uint)macAddr.Length;

            int arp_respone = await Task.Run(() => SendARP((int)IP.Address, 0, macAddr, ref macAddrLen));

            if (arp_respone != 0)
            {
                if (ARP_Request_Task_Finished != null)
                {
                    ARP_Request_Task_Finished(this, new ARP_Request_Task_Finished_EventArgs(string.Empty, string.Empty, string.Empty, string.Empty, string.Empty));
                }
                //throw new Exception("ARP command failed");
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
                    ARP_Request_Task_Finished(this, new ARP_Request_Task_Finished_EventArgs(IPAddr.IPGroupDescription, IPAddr.DeviceGroupDescription, IPAddr.IP, mac, support.GetVendorFromMac(mac).First()));
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
        public async Task ARP_A()
        {
            try
            {
                //var list = new List<IPInfo>();

               
                string str_arpResult =  await GetARPResult();
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
                                ARP_A_newDevice(this, new ARP_A_newDevice_EventArgs(true, ip, mac, vendor[0]));
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

    public class ARP_A_newDevice_EventArgs : EventArgs
    {
        public ARP_A_newDevice_EventArgs(bool ARPStatus, string IP, string MAC, string Vendor)
        {
            _ARPStatus = ARPStatus;
            _IP = IP;
            _MAC = MAC;
            _Vendor = Vendor;
        }
        private bool _ARPStatus = false;
        public bool ARPStatus { get { return _ARPStatus; } }

        private string _IP = string.Empty;
        public string IP { get { return _IP; } }

        private string _MAC = string.Empty;
        public string MAC { get { return _MAC; } }

        private string _Vendor = string.Empty;
        public string Vendor { get { return _Vendor; } }
    }



    public class ARP_Request_Task_Finished_EventArgs : EventArgs
    {
        public ARP_Request_Task_Finished_EventArgs(string IPGroupDescription, string DeviceDescription,string IP, string MAC, string Vendor)
        {
            _IPGroupDescription = IPGroupDescription;
            _DeviceDescription = DeviceDescription;
            _IP = IP;
            _MAC = MAC;
            _Vendor = Vendor;
        }

        string _IPGroupDescription = string.Empty;
        public string IPGroupDescription { get { return _IPGroupDescription; } }

        string _DeviceDescription = string.Empty;
        public string DeviceGroupDescription { get { return _DeviceDescription; } }

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
