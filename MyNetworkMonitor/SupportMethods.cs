using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection.PortableExecutable;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    internal class SupportMethods
    {
        public bool IsAdministrator()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        public string GetLocalIPv4(NetworkInterfaceType _type)
        {
            string output = "";
            foreach (NetworkInterface item in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (item.NetworkInterfaceType == _type && item.OperationalStatus == OperationalStatus.Up)
                {
                    foreach (UnicastIPAddressInformation ip in item.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            output = ip.Address.ToString();
                        }
                    }
                }
            }
            return output;
        }

        public string[] header;
        private string[][] fields;

        private void LoadMacVendors()
        {
            string csvPath = Directory.GetFiles(@".\MacVendors", "mac_vendors.csv").First();
            if (!File.Exists(csvPath))
            {
                header = Array.Empty<string>();
                fields = Array.Empty<string[]>();
                return;
            }

            string[] lines = File.ReadAllLines(csvPath);

            header = lines[0].Split(',');
            fields = lines.Skip(1).Select(l => Regex.Split(l, ",(?=(?:[^\"]*\"[^\"]*\")*(?![^\"]*\"))")).ToArray();
        }

        public string[] GetVendorFromMac(string macAdress)
        {
            if (fields == null)
            {
                LoadMacVendors();
            }

            string[]? data = fields.FirstOrDefault(f => macAdress.Replace("-",":").ToLower().StartsWith(f[0].ToLower()))?.ToArray();

            if (fields.Length == 0 || header.Length == 0)
            {
                return Array.Empty<string>();
            }
            else if (data is null)
            {
                string[] result = new string[header.Length - 1];
                for (int i = 0; i < result.Length; i++)
                {
                    result[i] = "Unknown";
                }
                return result;
            }
            else
            {
                List<string> result = new List<string>();
                for (int i = 1; i < header.Length; i++)
                {
                    result.Add($"{data[i]}");
                }
                return result.ToArray();
            }
        }

        public string[] GetHeader()
        {
            return header!.Skip(1).ToArray();
        }

       

        public bool Is_Valid_IP(string ip)
        {
            // (?!0) check if the numeric part starts with zero
            string pattern = "" +
                "^(?!0)(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                "(?!0)(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                "(?!0)(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                "(?!0)(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";

            Regex regex = new Regex(pattern);

            return regex.IsMatch(ip);            
        }

        public class ValidAndCleanedIP 
        { 
            public bool IsValid { get; set; }
            public string IP { get; set; }
        }

        public ValidAndCleanedIP ValidAndCleanIP(string ip)
        {
            // ^(?!0)(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?) (?!0) check if the numeric part starts not with zero, optional you can use this pattern (25[0-5]|2[0-4][0-9]|[1][0-9][0-9]|[1][0-9]|[1-9])
            // there is no check for leading zero becaus there is it possible to order the IP Addresses
            string pattern = "" +
                "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\." +
                "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$";

            Regex regex = new Regex(pattern);
            bool test = regex.IsMatch(ip);

            ValidAndCleanedIP validAndCleanedIP = new ValidAndCleanedIP();

            validAndCleanedIP.IsValid = test;
            if (test)
            {
                //version removes leading zeros after the dots
                validAndCleanedIP.IP = new Version(ip).ToString();
            }
            else
            {
                validAndCleanedIP.IP = string.Empty;
            }

            return validAndCleanedIP;
        }
    }




    public class ScanTask_Finished_EventArgs : EventArgs
    {
        //public ScanTask_Finished_EventArgs()
        //{

        //}
         // { get { return ; } set {  = value; } }

        private string _IPGroupDescription = string.Empty;
        private string _DeviceDescription = string.Empty;
        private string _IP = string.Empty;

        public string IPGroupDescription { get { return _IPGroupDescription; } set { _IPGroupDescription = value; } }
        public string DeviceDescription { get { return _DeviceDescription; } set { _DeviceDescription = value; } }
        public string IP { get { return _IP; } set { _IP = value; } }


        private bool _PingStatus = false;
        private string _ResponseTime = string.Empty;
        public bool PingStatus { get { return _PingStatus; } set { _PingStatus = value; } }
        public string ResponseTime { get { return _ResponseTime; } set { _ResponseTime = value; } }

        private bool _ARPStatus = false;
        private string _MAC = string.Empty;
        private string _Vendor = string.Empty;
        public bool ARPStatus { get { return _ARPStatus; } set { _ARPStatus = value; } }
        public string MAC { get { return _MAC; } set { _MAC = value; } }
        public string Vendor { get { return _Vendor; } set { _Vendor = value; } }


        private string _Hostname = string.Empty;
        private string _Aliases = string.Empty;
        public string HostName { get { return _Hostname; } set { _Hostname = value; } }
        public string Aliases { get { return _Aliases; } set { _Aliases = value; } }


        private bool _LookUpStatus = false;
        private string _LookUpIPs = string.Empty;
        private IPHostEntry _IP_HostEntry = null;
        private string _DNSServers = string.Empty;
        public bool LookUpStatus { get { return _LookUpStatus; } set { _LookUpStatus = value; } }
        public string LookUpIPs { get { return _LookUpIPs; } set { _LookUpIPs = value; } }
        public IPHostEntry IP_HostEntry { get { return _IP_HostEntry; } set { _IP_HostEntry = value; } }
        public string DNSServers { get { return _DNSServers; } set { _DNSServers = value; } }

        private bool _SSDPStatus = false;
        public bool SSDPStatus { get { return _SSDPStatus; } set { _SSDPStatus = value; } }


        private List<int> _TCP_OpenPorts = new List<int>();
        private List<int> _TCP_FirewallBlockedPorts = new List<int>();
        private List<int> _TCP_TargetDeniedAccessToPorts = new List<int>();
        public List<int> TCP_OpenPorts { get { return _TCP_OpenPorts; } set { _TCP_OpenPorts = value; } }
        public List<int> TCP_FirewallBlockedPorts { get { return _TCP_FirewallBlockedPorts; } set { _TCP_FirewallBlockedPorts = value; } }
        public List<int> TCP_TargetDeniedAccessToPorts { get { return _TCP_TargetDeniedAccessToPorts; } set { _TCP_TargetDeniedAccessToPorts = value; } }


        private List<int> _UDP_OpenPorts = new List<int>();
        private List<int> _UDP_FirewallBlockedPorts = new List<int>();
        private List<int> _UDP_TargetDeniedAccessToPorts = new List<int>();
        public List<int> UDP_OpenPorts { get { return _UDP_OpenPorts; } set { _UDP_OpenPorts = value; } }
        public List<int> UDP_FirewallBlockedPorts { get { return _UDP_FirewallBlockedPorts; } set { _UDP_FirewallBlockedPorts = value; } }
        public List<int> UDP_TargetDeniedAccessToPorts { get { return _UDP_TargetDeniedAccessToPorts; } set { _UDP_TargetDeniedAccessToPorts = value; } }
    }
}

