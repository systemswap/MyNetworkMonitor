using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime;
using System.Text;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    public class NicInfo
    {
        public NetworkInterface nic { get; set; }
        public string NicName { get; set; }
        public string IPv4 { get; set; }
        public string IPv4Mask { get; set; }
        public string FirstSubnetIP { get; set; }
        public string LastSubnetIP { get; set; }
        public double IPsCount { get; set; }
        public string IPv6 { get; set; }
        public List<string> StandardGateways { get; set; }
        public List<string> DHCPServers { get; set; }
        public List<string> DNSServers { get; set; }

    }
    public class Supporter_NetworkInterfaces
    {       
        public List<NicInfo> NetworkInterfaces_Infos { get; set; }        

        public List<NicInfo> GetNetworkInterfaces()
        {
            List<NicInfo> nicInfos = new List<NicInfo>();
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 || ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
                {
                    IPInterfaceProperties niProperties = ni.GetIPProperties();

                    NicInfo _nicInfo = new NicInfo();
                    _nicInfo.NicName = ni.Name;

                    //_nicInfo.StandardGateways = niProperties.GatewayAddresses.Select(g => g.Address.ToString()).ToList();
                    //_nicInfo.DHCPServers = niProperties.DhcpServerAddresses.Select(g => g.Address.ToString()).ToList();
                    //_nicInfo.DNSServers = niProperties.DnsAddresses.Select(d => d.Address.ToString()).ToList();


                    foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            _nicInfo.IPv4 = ip.Address.ToString();
                            _nicInfo.IPv4Mask = ip.IPv4Mask.ToString();
                            
                            string[] ipRanges = GetIpRange(_nicInfo.IPv4, _nicInfo.IPv4Mask);
                            _nicInfo.FirstSubnetIP = ipRanges[0];
                            _nicInfo.LastSubnetIP = ipRanges[1];

                            //IpRanges.IPRange range = new IpRanges.IPRange(_nicInfo.FirstSubnetIP, _nicInfo.LastSubnetIP);
                            _nicInfo.IPsCount = new IpRanges.IPRange().NumberOfIPsInRange(_nicInfo.FirstSubnetIP, _nicInfo.LastSubnetIP); //range.GetAllIP().Count().ToString();

                            nicInfos.Add(_nicInfo);
                        }
                    }
                }
            }
            NetworkInterfaces_Infos = nicInfos;
            return nicInfos;
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



        /// <summary>
        /// IPAddress to UInteger 
        /// </summary>
        /// <param name="ipAddress"></param>
        /// <returns></returns>
        private uint IPToUInt(string ipAddress)
        {
            if (string.IsNullOrEmpty(ipAddress))
                return 0;

            if (IPAddress.TryParse(ipAddress, out IPAddress ip))
            {
                var bytes = ip.GetAddressBytes();
                Array.Reverse(bytes);
                return BitConverter.ToUInt32(bytes, 0);
            }
            else
                return 0;

        }

        /// <summary>
        /// IP in Uinteger to string
        /// </summary>
        /// <param name="ipUInt"></param>
        /// <returns></returns>
        private string IPToString(uint ipUInt)
        {
            return ToIPAddress(ipUInt).ToString();
        }


        /// <summary>
        /// IP in Uinteger to IPAddress
        /// </summary>
        /// <param name="ipUInt"></param>
        /// <returns></returns>
        private IPAddress ToIPAddress(uint ipUInt)
        {
            var bytes = BitConverter.GetBytes(ipUInt);
            Array.Reverse(bytes);
            return new IPAddress(bytes);
        }

        /// <summary>
        /// First and Last IPv4 from IP + Mask
        /// </summary>
        /// <param name="ipv4"></param>
        /// <param name="mask">Accepts CIDR or IP. Example 255.255.255.0 or 24</param>
        /// <param name="filterUsable">Removes not usable IPs from Range</param>
        /// <returns></returns>
        /// <remarks>
        /// If ´filterUsable=false´ first IP is not usable and last is reserved for broadcast.
        /// </remarks>
        private string[] GetIpRange(string ipv4, string mask, bool filterUsable = true)
        {
            uint[] uiIpRange = GetIpUintRange(ipv4, mask, filterUsable);

            return Array.ConvertAll(uiIpRange, x => IPToString(x));
        }

        /// <summary>
        /// First and Last IPv4 + Mask. 
        /// </summary>
        /// <param name="ipv4"></param>
        /// <param name="mask">Accepts CIDR or IP. Example 255.255.255.0 or 24</param>
        /// <param name="filterUsable">Removes not usable IPs from Range</param>
        /// <returns></returns>
        /// <remarks>
        /// First IP is not usable and last is reserverd for broadcast.
        /// Can use all IPs in between
        /// </remarks>
        private uint[] GetIpUintRange(string ipv4, string mask, bool filterUsable)
        {
            uint sub;
            //check if mask is CIDR Notation
            if (mask.Contains("."))
            {
                sub = IPToUInt(mask);
            }
            else
            {
                sub = ~(0xffffffff >> Convert.ToInt32(mask));
            }

            uint ip2 = IPToUInt(ipv4);


            uint first = ip2 & sub;
            uint last = first | (0xffffffff & ~sub);

            if (filterUsable && mask != "255.255.255.255")
            {
                first += 1;
                last -= 1;
            }

            return new uint[] { first, last };
        }
    }
}
