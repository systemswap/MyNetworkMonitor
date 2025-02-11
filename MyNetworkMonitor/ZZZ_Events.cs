using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using static MyNetworkMonitor.MainWindow;

namespace MyNetworkMonitor
{
    public class ScanTask_Finished_EventArgs : EventArgs
    {
        private IPToScan _ipToScan = new IPToScan();
        public IPToScan ipToScan { get { return _ipToScan; } set { _ipToScan = value; } }

        //public ScanTask_Finished_EventArgs()
        //{

        //}
        // { get { return ; } set {  = value; } }

        //private string _IPGroupDescription = string.Empty;
        //private string _DeviceDescription = string.Empty;
        //private string _IP = string.Empty;

        //public string IPGroupDescription { get { return _IPGroupDescription; } set { _IPGroupDescription = value; } }
        //public string DeviceDescription { get { return _DeviceDescription; } set { _DeviceDescription = value; } }
        //public string IP { get { return _IP; } set { _IP = value; } }


        //private bool _PingStatus = false;
        //private string _ResponseTime = string.Empty;
        //public bool PingStatus { get { return _PingStatus; } set { _PingStatus = value; } }
        //public string ResponseTime { get { return _ResponseTime; } set { _ResponseTime = value; } }

        //private bool _ARPStatus = false;
        //private string _MAC = string.Empty;
        //private string _Vendor = string.Empty;
        //public bool ARPStatus { get { return _ARPStatus; } set { _ARPStatus = value; } }
        //public string MAC { get { return _MAC; } set { _MAC = value; } }
        //public string Vendor { get { return _Vendor; } set { _Vendor = value; } }


        //private string _Hostname = string.Empty;
        //private string _Aliases = string.Empty;
        //public string HostName { get { return _Hostname; } set { _Hostname = value; } }
        //public string Aliases { get { return _Aliases; } set { _Aliases = value; } }


        //private bool _LookUpStatus = false;
        //private string _LookUpIPs = string.Empty;
        //private IPHostEntry _IP_HostEntry = null;
        //private string _str_DNSServers = string.Empty;
        //public bool LookUpStatus { get { return _LookUpStatus; } set { _LookUpStatus = value; } }
        //public string LookUpIPs { get { return _LookUpIPs; } set { _LookUpIPs = value; } }
        //public IPHostEntry IP_HostEntry { get { return _IP_HostEntry; } set { _IP_HostEntry = value; } }
        //public string DNSServers { get { return _str_DNSServers; } set { _str_DNSServers = value; } }

        //private bool _SSDPStatus = false;
        //public bool SSDPStatus { get { return _SSDPStatus; } set { _SSDPStatus = value; } }


        //private List<int> _TCP_OpenPorts = new List<int>();
        //private List<int> _TCP_FirewallBlockedPorts = new List<int>();
        //private List<int> _TCP_TargetDeniedAccessToPorts = new List<int>();
        //public List<int> TCP_OpenPorts { get { return _TCP_OpenPorts; } set { _TCP_OpenPorts = value; } }
        //public List<int> TCP_FirewallBlockedPorts { get { return _TCP_FirewallBlockedPorts; } set { _TCP_FirewallBlockedPorts = value; } }
        //public List<int> TCP_TargetDeniedAccessToPorts { get { return _TCP_TargetDeniedAccessToPorts; } set { _TCP_TargetDeniedAccessToPorts = value; } }


        //private List<int> _UDP_OpenPorts = new List<int>();
        //private List<int> _UDP_FirewallBlockedPorts = new List<int>();
        //private List<int> _UDP_TargetDeniedAccessToPorts = new List<int>();
        //public List<int> UDP_OpenPorts { get { return _UDP_OpenPorts; } set { _UDP_OpenPorts = value; } }
        //public List<int> UDP_FirewallBlockedPorts { get { return _UDP_FirewallBlockedPorts; } set { _UDP_FirewallBlockedPorts = value; } }
        //public List<int> UDP_TargetDeniedAccessToPorts { get { return _UDP_TargetDeniedAccessToPorts; } set { _UDP_TargetDeniedAccessToPorts = value; } }
    }

    public class Method_Finished_EventArgs : EventArgs
    {
        public Method_Finished_EventArgs()
        {
            
        }

        private bool _finished = false;
        public bool Methode_Finished { get { return _finished; } }
        public ScanStatus ScanStatus { get; set; }
    }
}
