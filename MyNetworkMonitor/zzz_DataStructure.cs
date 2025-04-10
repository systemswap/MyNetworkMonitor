﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;


namespace MyNetworkMonitor
{
    public enum ScanStatus
    {
        ignored,
        waiting,
        running,
        finished,
        stopped,
        [Description("port was used by another app, try later again")]
        AnotherLocalAppUsedThePort,

        [Description("wrong network interface selected")]
        wrongNetworkInterfaceSelected
    }

    public enum ScanMethod
    {
        failed,
        SSDP,
        ARPRequest,
        ARP_A,
        Ping,
        ONVIF_IPCam,
        SNMP,
        NetBios,
        SMB,
        Services,
        ReverseLookup,
        Lookup,
        TCPPorts,
        UDPPorts,
    }


    public class ServiceScanData
    {
        public class PortResult
        {
            public int Port { get; set; }
            public PortStatus Status { get; set; }
            public string PortLog { get; set; }
        }

        public class ServiceResult
        {
            public ServiceType Service { get; set; }
            public List<PortResult> Ports { get; set; } = new List<PortResult>();
        }

        public class ServiceScanResult
        {
            public string IP { get; set; }
            public List<ServiceResult> Services { get; set; } = new List<ServiceResult>();

            public bool ShowOnlyIsRunningServices = false;

            //public override string ToString()
            //{
            //    if (Services == null || Services.Count == 0)
            //        return "Keine Services gefunden.";

            //    StringBuilder sb = new StringBuilder();

            //    foreach (var service in Services)
            //    {
            //        //if if there is no service running continue
            //        if (ShowOnlyIsRunningServices && service.Ports.Count(p => p.Status == PortStatus.IsRunning) == 0) continue;                    

            //        string serviceWithIcon = string.Empty;

            //        switch (service.Service)
            //        {
            //            case ServiceType.WebServices:
            //                serviceWithIcon = "🌐 " + service.Service.ToString();
            //                break;
            //            case ServiceType.DNS_TCP:
            //                serviceWithIcon = "🌐 " + service.Service.ToString();
            //                break;
            //            case ServiceType.DNS_UDP:
            //                serviceWithIcon = "🌐 " + service.Service.ToString();
            //                break;
            //            case ServiceType.DHCP:
            //                serviceWithIcon = "🌐 " + service.Service.ToString();
            //                break;
            //            case ServiceType.SSH:
            //                serviceWithIcon = "🔐 " + service.Service.ToString();
            //                break;
            //            case ServiceType.FTP:
            //                serviceWithIcon = "📡 " + service.Service.ToString();
            //                break;
            //            case ServiceType.RDP:
            //                serviceWithIcon = "🖥️ " + service.Service.ToString();
            //                break;
            //            case ServiceType.UltraVNC:
            //                serviceWithIcon = "🖥️ " + service.Service.ToString();
            //                break;
            //            case ServiceType.BigFixRemote:
            //                serviceWithIcon = "🖥️ " + service.Service.ToString();
            //                break;
            //            case ServiceType.RustdeskServer:
            //                serviceWithIcon = "🖥️ " + service.Service.ToString();
            //                break;
            //            case ServiceType.RustdeskClient:
            //                serviceWithIcon = "🖥️ " + service.Service.ToString();
            //                break;
            //            case ServiceType.TeamViewer:
            //                serviceWithIcon = "🖥️ " + service.Service.ToString();
            //                break;
            //            case ServiceType.Anydesk:
            //                serviceWithIcon = "🖥️ " + service.Service.ToString();
            //                break;
            //            case ServiceType.MSSQLServer:
            //                serviceWithIcon = "🗄️ " + service.Service.ToString();
            //                break;
            //            case ServiceType.PostgreSQL:
            //                serviceWithIcon = "🗄️ " + service.Service.ToString();
            //                break;                        
            //            case ServiceType.MariaDB:
            //                serviceWithIcon = "🗄️ " + service.Service.ToString();
            //                break;
            //            case ServiceType.MySQL:
            //                serviceWithIcon = "🗄️ " + service.Service.ToString();
            //                break;
            //            case ServiceType.OracleDB:
            //                serviceWithIcon = "🗄️ " + service.Service.ToString();
            //                break;
            //            case ServiceType.MongoDB:
            //                serviceWithIcon = "🛢️ " + service.Service.ToString();
            //                break;
            //            case ServiceType.InfluxDB2:
            //                serviceWithIcon = "🛢️ " + service.Service.ToString();
            //                break;
            //            case ServiceType.OPCUA:
            //                serviceWithIcon = "⚙️ " + service.Service.ToString();
            //                break;
            //            case ServiceType.ModBus:
            //                serviceWithIcon = "🔌 " + service.Service.ToString();
            //                break;
            //            case ServiceType.S7:
            //                serviceWithIcon = "📟 " + service.Service.ToString();
            //                break;
            //            default:
            //                break;
            //        }



            //        sb.Append((serviceWithIcon + ":").ToString().PadRight(25, ' ')); // Service-Name (UltraVNC, RDP, etc.)   

            //        int portcounter = 0;
            //        List<PortResult> sortedPorts = service.Ports.OrderBy(x => x.Port).ToList();
            //        foreach (var port in sortedPorts)
            //        {
            //            // if the port is not running, skip it
            //            if (ShowOnlyIsRunningServices && port.Status != PortStatus.IsRunning) continue;

            //            if (portcounter++ == 0)
            //            {
            //                sb.Append($"\t{port.Port.ToString().PadRight(6)}\t({port.Status})");
            //            }
            //            else
            //            {
            //                sb.Append(" ".ToString().PadRight(35, ' ') + $"\t{port.Port}\t({port.Status})");
            //            }
            //            if(port != sortedPorts.Last()) sb.AppendLine();
            //        }
            //        if (service != Services.Last()) sb.AppendLine();
            //    }
            //    string tmp = sb.ToString().Replace(", ", string.Empty);
            //    return tmp.TrimEnd();
            //}


            public override string ToString()
            {
                if (Services == null || Services.Count == 0)
                    return "Keine Services gefunden.";

                StringBuilder sb = new StringBuilder();

                foreach (var service in Services)
                {
                    // Filtere die Ports nach dem gewünschten Status
                    List<PortResult> filteredPorts = service.Ports
                        .Where(p => !ShowOnlyIsRunningServices || p.Status == PortStatus.IsRunning || p.Status == PortStatus.Error)
                        .OrderBy(x => x.Port)
                        .ToList();

                    // Wenn nach dem Filtern keine Ports übrig bleiben, den Service nicht anzeigen
                    if (filteredPorts.Count == 0) continue;

                    string serviceWithIcon = string.Empty;

                    switch (service.Service)
                    {
                        case ServiceType.WebServices:
                            serviceWithIcon = "🌐 " + service.Service.ToString();
                            break;
                        case ServiceType.DNS_TCP:
                            serviceWithIcon = "🌐 " + service.Service.ToString();
                            break;
                        case ServiceType.DNS_UDP:
                            serviceWithIcon = "🌐 " + service.Service.ToString();
                            break;
                        case ServiceType.DHCP:
                            serviceWithIcon = "🌐 " + service.Service.ToString();
                            break;
                        case ServiceType.SSH:
                            serviceWithIcon = "🔐 " + service.Service.ToString();
                            break;
                        case ServiceType.FTP:
                            serviceWithIcon = "📡 " + service.Service.ToString();
                            break;
                        case ServiceType.RDP:
                            serviceWithIcon = "🖥️ " + service.Service.ToString();
                            break;
                        case ServiceType.UltraVNC:
                            serviceWithIcon = "🖥️ " + service.Service.ToString();
                            break;
                        case ServiceType.BigFixRemote:
                            serviceWithIcon = "🖥️ " + service.Service.ToString();
                            break;
                        case ServiceType.RustdeskServer:
                            serviceWithIcon = "🖥️ " + service.Service.ToString();
                            break;
                        case ServiceType.RustdeskClient:
                            serviceWithIcon = "🖥️ " + service.Service.ToString();
                            break;
                        case ServiceType.TeamViewer:
                            serviceWithIcon = "🖥️ " + service.Service.ToString();
                            break;
                        case ServiceType.Anydesk:
                            serviceWithIcon = "🖥️ " + service.Service.ToString();
                            break;
                        case ServiceType.MSSQLServer:
                            serviceWithIcon = "🗄️ " + service.Service.ToString();
                            break;
                        case ServiceType.PostgreSQL:
                            serviceWithIcon = "🗄️ " + service.Service.ToString();
                            break;
                        case ServiceType.MariaDB:
                            serviceWithIcon = "🗄️ " + service.Service.ToString();
                            break;
                        case ServiceType.MySQL:
                            serviceWithIcon = "🗄️ " + service.Service.ToString();
                            break;
                        case ServiceType.OracleDB:
                            serviceWithIcon = "🗄️ " + service.Service.ToString();
                            break;
                        case ServiceType.MongoDB:
                            serviceWithIcon = "🛢️ " + service.Service.ToString();
                            break;
                        case ServiceType.InfluxDB2:
                            serviceWithIcon = "🛢️ " + service.Service.ToString();
                            break;
                        case ServiceType.OPCUA:
                            serviceWithIcon = "⚙️ " + service.Service.ToString();
                            break;
                        case ServiceType.ModBus:
                            serviceWithIcon = "🔌 " + service.Service.ToString();
                            break;
                        case ServiceType.S7:
                            serviceWithIcon = "📟 " + service.Service.ToString();
                            break;                        
                        default:
                            serviceWithIcon = "🤔 " + service.Service.ToString();
                            break;
                    }

                    sb.Append(serviceWithIcon.PadRight(25, ' '));

                    int portCounter = 0;
                    foreach (var port in filteredPorts)
                    {
                        if (portCounter++ == 0)
                            sb.Append($"\t{port.Port.ToString().PadRight(6)}\t({port.Status})");
                        else
                            sb.Append("\n" + "".PadRight(35, ' ') + $"\t{port.Port}\t({port.Status})");
                    }

                    sb.AppendLine(); // Nur eine Zeile nach einem kompletten Service-Block einfügen
                }

                return sb.ToString().TrimEnd(); // Entfernt letzte leere Zeile
            }

        }
    }




    [Serializable]
    public class IPToScan
    {
        public IPToScan()
        {
            _lst_DNSServers = new List<string>();

            _TCPPortsToScan = new List<int>();
            _UDPPortsToScan = new List<int>();

            _TCP_OpenPorts = new List<int>();
            _TCP_FirewallBlockedPorts = new List<int>();
            _TCP_TargetDeniedAccessToPorts = new List<int>();

            _UDP_OpenPorts = new List<int>();
            _UDP_FirewallBlockedPorts = new List<int>();
            _UDP_TargetDeniedAccessToPorts = new List<int>();
        }

        private ScanMethod _UsedScanMethod;
        public ScanMethod UsedScanMethod { get { return _UsedScanMethod; } set { _UsedScanMethod = value; } }

        private string _IPGroupDescription = string.Empty;
        private string _DeviceDescription = string.Empty;
        private string _IP = string.Empty;
        
        public bool isStaticIP = false;
        public string IPGroupDescription { get { return _IPGroupDescription; } set { _IPGroupDescription = value; } }
        public string DeviceDescription { get { return _DeviceDescription; } set { _DeviceDescription = value; } }
        public string IPorHostname { get { return _IP; } set { _IP = value; } }



        private bool _PingStatus = false;
        private string _ResponseTime = string.Empty;
        public bool PingStatus { get { return _PingStatus; } set { _PingStatus = value; } }        
        public string ResponseTime { get { return _ResponseTime; } set { _ResponseTime = value; } }


        private bool _IsIPCam = false;
        private string _IPCamName = string.Empty;
        private string _IPCamXAddress = string.Empty;
        public bool IsIPCam { get { return _IsIPCam; } set { _IsIPCam = value; } }
        public string IPCamName { get { return _IPCamName; } set { _IPCamName = value; } }
        public string IPCamXAddress { get { return _IPCamXAddress; } set { _IPCamXAddress = value; } }
       

        private string _SNMP_SysName = string.Empty;
        private string _SNMP_Serial = string.Empty;
        private string _SNMP_SysDesc = string.Empty;
        private string _SNMP_Location = string.Empty;
        private string _SNMP_Contact = string.Empty;
        private string _SNMP_MAC = string.Empty;

        public string SNMP_SysName { get { return _SNMP_SysName; } set { _SNMP_SysName = value; } }
        public string SNMP_Serial { get { return _SNMP_Serial; } set { _SNMP_Serial = value; } }
        public string SNMP_SysDesc { get { return _SNMP_SysDesc; } set { _SNMP_SysDesc = value; } }
        public string SNMP_Location { get { return _SNMP_Location; } set { _SNMP_Location = value; } }
        public string SNMP_Contact { get { return _SNMP_Contact; } set { _SNMP_Contact = value; } }
        public string SNMP_MAC { get { return _SNMP_MAC; } set { _SNMP_MAC = value; } }

        public string SNMPInfos 
        { 
            get 
            {
                return string.Join("\r\n", "Serial: ".PadRight(15) + "\t" + _SNMP_Serial, "Descr: ".PadRight(15) + "\t" + _SNMP_SysDesc, "Location: ".PadRight(15) + "\t" + _SNMP_Location, "Contact: ".PadRight(15) + "\t" + _SNMP_Contact, "MAC: ".PadRight(15) + "\t" + _SNMP_MAC);
            } 
        }


        private bool _ARPStatus = false;
        private string _MAC = string.Empty;
        private string _Vendor = string.Empty;
        public bool ARPStatus { get { return _ARPStatus; } set { _ARPStatus = value; } }        
        public string MAC { get { return _MAC; } set { _MAC = value; } }
        public string Vendor { get { return _Vendor; } set { _Vendor = value; } }



        private string _HostName = string.Empty;        
        private string _Domain = string.Empty;
        private string _Aliases = string.Empty;
        public string HostName { get { return _HostName; } set { _HostName = value; } }
        public string Domain { get { return _Domain; } set { _Domain = value; } }
        public string HostnameWithDomain 
        { 
            get 
            {
                List<string> list = new List<string>();
                if (!string.IsNullOrEmpty(_HostName)) list.Add(_HostName);
                if (!string.IsNullOrEmpty(_Domain)) list.Add(_Domain);

                return string.Join('.', list);
            }
        }
        public string Aliases { get { return _Aliases; } set { _Aliases = value; } }
       
        private string _NetBiosHostname = string.Empty;
        public string NetBiosHostname { get { return _NetBiosHostname; } set { _NetBiosHostname= value; } }

        
        public List<string> SMBVersions = new List<string>();
        // 🔹 Eigene ToString()-Methode für SMBVersions
        public string SMBVersionsToString()
        {
            return SMBVersions.Any() ? string.Join(", ", SMBVersions) : "Keine SMB-Versionen gefunden";
        }


        private string _destectedServices = string.Empty;
        public string detectedServices { get { return _destectedServices; } set { _destectedServices = value; } }




        private ServiceScanData.ServiceScanResult _services = new ServiceScanData.ServiceScanResult();

        public ServiceScanData.ServiceScanResult Services
        {
            get => _services;
            set => _services = value ?? new ServiceScanData.ServiceScanResult();

        }






        private bool _LookUpStatus = false;
        private string _LookUpIPs = string.Empty;
        private IPHostEntry _IP_HostEntry = null;
        //private string _str_DNSServers = string.Empty;
        private List<string> _lst_DNSServers;
        public bool LookUpStatus { get { return _LookUpStatus; } set { _LookUpStatus = value; } }
        public string LookUpIPs { get { return _LookUpIPs; } set { _LookUpIPs = value; } }
        public IPHostEntry IP_HostEntry { get { return _IP_HostEntry; } set { _IP_HostEntry = value; } }
        //public string DNSServers { get { return _str_DNSServers; } set { _str_DNSServers = value; } }
        public List<string> DNSServerList { get { return _lst_DNSServers; } set { _lst_DNSServers = value; }}

        
        
        private bool _SSDPStatus = false;
        public bool SSDPStatus { get { return _SSDPStatus; } set { _SSDPStatus = value; } }



        private List<int> _TCPPortsToScan;
        private List<int> _UDPPortsToScan;
        public List<int> TCPPortsToScan { get { return _TCPPortsToScan; } set { _TCPPortsToScan = value; } }        
        public List<int> UDPPortsToScan { get { return _UDPPortsToScan; } set { _UDPPortsToScan = value; } }



        private List<int> _TCP_OpenPorts;
        private List<int> _TCP_FirewallBlockedPorts;
        private List<int> _TCP_TargetDeniedAccessToPorts;
        public List<int> TCP_OpenPorts { get { return _TCP_OpenPorts; } set { _TCP_OpenPorts = value; } }
        public List<int> TCP_FirewallBlockedPorts { get { return _TCP_FirewallBlockedPorts; } set { _TCP_FirewallBlockedPorts = value; } }
        public List<int> TCP_TargetDeniedAccessToPorts { get { return _TCP_TargetDeniedAccessToPorts; } set { _TCP_TargetDeniedAccessToPorts = value; } }



        private List<int> _UDP_OpenPorts;
        private List<int> _UDP_FirewallBlockedPorts;
        private List<int> _UDP_TargetDeniedAccessToPorts;
        private int _UDP_ListenerFound = 0;
        public List<int> UDP_OpenPorts { get { return _UDP_OpenPorts; } set { _UDP_OpenPorts = value; } }
        public List<int> UDP_FirewallBlockedPorts { get { return _UDP_FirewallBlockedPorts; } set { _UDP_FirewallBlockedPorts = value; } }
        public List<int> UDP_TargetDeniedAccessToPorts { get { return _UDP_TargetDeniedAccessToPorts; } set { _UDP_TargetDeniedAccessToPorts = value; } }
        public int UDP_ListenerFound { get { return _UDP_ListenerFound; } set { _UDP_ListenerFound = value; } }


        private int _TimeOut = 250;
        public int TimeOut { get { return _TimeOut; } set { _TimeOut = value; } }



        private string _NMGatewayIP = string.Empty;
        private string _NMGatewayPort = string.Empty;
        public string NMGatewayIP { get { return _NMGatewayIP; } set { _NMGatewayIP = value; } }
        public string NMGatewayPort { get { return _NMGatewayPort; } set { _NMGatewayPort = value; } }
    }





    public class ScanResults
    {
        public ScanResults()
        {
            dt_NetworkResults.TableName = "ScanResults";
            dt_NetworkResults.Columns.Add("IPGroupDescription", typeof(string));
            dt_NetworkResults.Columns.Add("DeviceDescription", typeof(string));
            dt_NetworkResults.Columns.Add("SSDPStatus", typeof(byte[]));
            dt_NetworkResults.Columns.Add("ARPStatus", typeof(byte[]));
            dt_NetworkResults.Columns.Add("PingStatus", typeof(byte[]));
            dt_NetworkResults.Columns.Add("IsIPCam", typeof(byte[]));            
            dt_NetworkResults.Columns.Add("IP", typeof(string));
            dt_NetworkResults.Columns.Add("ResponseTime", typeof(string));
            dt_NetworkResults.Columns.Add("InternalName", typeof(string));
            dt_NetworkResults.Columns.Add("Hostname", typeof(string));

            dt_NetworkResults.Columns.Add("NetBiosHostname", typeof(string));
            dt_NetworkResults.Columns.Add("detectedSMBVersions", typeof(string));
            dt_NetworkResults.Columns.Add("detectedServicePorts", typeof(string));

            dt_NetworkResults.Columns.Add("SNMPSysName", typeof(string));
            dt_NetworkResults.Columns.Add("SNMPInfos", typeof(string));           
            //dt_NetworkResults.Columns.Add("SNMPSysDesc", typeof(string));
            //dt_NetworkResults.Columns.Add("SNMPLocation", typeof(string));

            dt_NetworkResults.Columns.Add("IPCamName", typeof(string));
            dt_NetworkResults.Columns.Add("IPCamXAddress", typeof(string));
            dt_NetworkResults.Columns.Add("Domain", typeof(string));
            dt_NetworkResults.Columns.Add("Aliases", typeof(string));
            dt_NetworkResults.Columns.Add("LookUpStatus", typeof(byte[]));
            //dt_NetworkResults.Columns.Add("MatchedWithInternal", typeof(byte[]));
            dt_NetworkResults.Columns.Add("LookUpIPs", typeof(string));
            dt_NetworkResults.Columns.Add("TCP_Ports", typeof(string));
            //dt_NetworkResults.Columns.Add("OpenUDP_Ports", typeof(string));
            dt_NetworkResults.Columns.Add("Comment", typeof(string));
            dt_NetworkResults.Columns.Add("Mac", typeof(string));
            dt_NetworkResults.Columns.Add("Vendor", typeof(string));
            dt_NetworkResults.Columns.Add("Exception", typeof(string));
            dt_NetworkResults.Columns.Add("DNSServers", typeof(string));
            dt_NetworkResults.Columns.Add("NMGatewayIP", typeof(string));
            dt_NetworkResults.Columns.Add("NMGatewayPort", typeof(string));
            //dt_NetworkResults.Columns.Add("SendAlert", typeof(bool));
            dt_NetworkResults.Columns.Add("IPToSort", typeof(string));
        }

        public DataTable dt_NetworkResults = new DataTable();

        public DataTable ResultTable 
        { 
            get { return dt_NetworkResults; }
            set { dt_NetworkResults = value; }
        }
    }


    public class PortCollection
    {
        public PortCollection()
        {
            dt_Ports.TableName = "TableOfPortsToScan";
            dt_Ports.Columns.Add("Ports", typeof(int));
            dt_Ports.Columns.Add("TCPScan", typeof(bool));
            dt_Ports.Columns.Add("UDPScan", typeof(bool));
            dt_Ports.Columns.Add("Description", typeof(string));

            dt_Ports.Rows.Add(7, true, true, "ICMP Echo Service Ping");
            dt_Ports.Rows.Add(9, true, true, "Zero service for test purposes");
            dt_Ports.Rows.Add(20, true, false, "FTP data transfer");
            dt_Ports.Rows.Add(21, true, true, "FTP connection");
            dt_Ports.Rows.Add(22, true, true, "SSH");
            dt_Ports.Rows.Add(23, true, false, "Telnet");
            dt_Ports.Rows.Add(25, true, false, "smtp");
            dt_Ports.Rows.Add(42, true, true, "nameserver");
            dt_Ports.Rows.Add(43, true, false, "WHOIS directory service");
            dt_Ports.Rows.Add(53, true, true, "DNS name resolver");
            dt_Ports.Rows.Add(67, false, true, "DHCP");
            dt_Ports.Rows.Add(68, false, true, "DHCP");
            dt_Ports.Rows.Add(80, true, false, "http");
            dt_Ports.Rows.Add(88, true, true, "kerberos Network authentication system");
            dt_Ports.Rows.Add(101, true, false, "hostname NIC host name");
            dt_Ports.Rows.Add(115, true, false, "sftp Simple file transfer protocol");
            dt_Ports.Rows.Add(117, false, true, "uucp-path File transfer between Unix systems");
            dt_Ports.Rows.Add(119, false, true, "nntp Transfer of messages in news groups");
            dt_Ports.Rows.Add(123, false, true, "ntp Time synchronization service");
            dt_Ports.Rows.Add(135, true, false, "Transact-SQL-Debugger oder net send ersatz für 139");
            dt_Ports.Rows.Add(137, true, true, "netbios-ns NETBIOS name service");
            dt_Ports.Rows.Add(138, true, true, "netbios-dgm NETBIOS datagram service");
            dt_Ports.Rows.Add(139, true, true, "netbios-ssn NETBIOS session service");
            dt_Ports.Rows.Add(161, false, true, "SNMP");
            dt_Ports.Rows.Add(162, false, true, "SNMP");
            dt_Ports.Rows.Add(194, true, true, "irc Internet relay chat");
            dt_Ports.Rows.Add(199, true, true, "smux SNMP UNIX multiplexer");
            dt_Ports.Rows.Add(443, true, false, "https HTTPS (HTTP over SSL/TLS)");
            dt_Ports.Rows.Add(445, true, false, "microsoft-ds SMB over TCP/IP");
            dt_Ports.Rows.Add(515, true, false, "Printer Service");
            dt_Ports.Rows.Add(520, false, true, "Routing Information Protocol");
            dt_Ports.Rows.Add(521, false, true, "Routing Information Protocol Next Generation (RIPng)");
            dt_Ports.Rows.Add(525, false, true, "Timeserver");
            dt_Ports.Rows.Add(631, true, true, "Internet Printing Protocol (IPP)");
            dt_Ports.Rows.Add(666, true, false, "Doom");
            dt_Ports.Rows.Add(873, true, false, "rsync file synchronization protocol");
            dt_Ports.Rows.Add(989, false, true, "FTPS Protocol (data), FTP over TLS/SSL");
            dt_Ports.Rows.Add(990, false, true, "FTPS Protocol (control), FTP over TLS/SSL");
            dt_Ports.Rows.Add(992, true, true, "Telnet protocol over TLS/SSL");
            dt_Ports.Rows.Add(996, false, true, "Central Point Software Xtree License Server");
            dt_Ports.Rows.Add(1040, true, true, "Netarx");
            dt_Ports.Rows.Add(1043, false, true, "BOINC Client Control");
            dt_Ports.Rows.Add(1067, true, false, "Installation Bootstrap Proto. Serv.");
            dt_Ports.Rows.Add(1089, true, false, "FF Annunciation");
            dt_Ports.Rows.Add(1300, true, false, "H323 Host Call Secure");
            dt_Ports.Rows.Add(1433, true, false, "SQL Standard Instanz");
            dt_Ports.Rows.Add(1434, false, true, "SQL Server Browserdienst");
            dt_Ports.Rows.Add(1900, false, true, "SSDP UPnP");
            dt_Ports.Rows.Add(2179, true, false, "Microsoft RDP for virtual machines");
            dt_Ports.Rows.Add(3000, true, true, "User-level ppp daemon");
            dt_Ports.Rows.Add(3001, true, false, "Miralix Phone Monitor (Unofficial)");
            dt_Ports.Rows.Add(3306, true, true, "MySQL");
            dt_Ports.Rows.Add(4321, true, false, "Remote Who Is");
            dt_Ports.Rows.Add(4840, true, false, "OPC UA TCP Protocol");
            dt_Ports.Rows.Add(5000, true, false, "UPnP - Windows network device interoperability");
            dt_Ports.Rows.Add(5001, true, false, "");
            dt_Ports.Rows.Add(5060, true, false, "SID Phone");
            dt_Ports.Rows.Add(5357, true, false, "Web Services for Devices (WSDAPI)");
            dt_Ports.Rows.Add(5432, true, false, "Postgre SQL Database");

            dt_Ports.Rows.Add(5900, true, false, "UltraVNC");
            dt_Ports.Rows.Add(5901, true, false, "UltraVNC");
            dt_Ports.Rows.Add(5902, true, false, "UltraVNC");
            dt_Ports.Rows.Add(5903, true, false, "UltraVNC");
            dt_Ports.Rows.Add(5904, true, false, "UltraVNC");
            dt_Ports.Rows.Add(5905, true, false, "UltraVNC");
            dt_Ports.Rows.Add(5906, true, false, "UltraVNC");
            dt_Ports.Rows.Add(5907, true, false, "UltraVNC");
            dt_Ports.Rows.Add(5908, true, false, "UltraVNC");
            dt_Ports.Rows.Add(5909, true, false, "UltraVNC");
            dt_Ports.Rows.Add(5910, true, false, "UltraVNC");

            dt_Ports.Rows.Add(8080, true, false, "HTTP Alternate (see port 80)");
            dt_Ports.Rows.Add(8443, true, false, "HTTPS Alternate (see port 443)");
            dt_Ports.Rows.Add(9998, true, true, "Distinct32");
            dt_Ports.Rows.Add(33434, true, true, "traceroute");
        }

        private DataTable dt_Ports = new DataTable();
        public DataTable TableOfPortsToScan { get { return dt_Ports; } set { dt_Ports = value; } }

        public List<int> TCPPorts
        {
            get
            {
                List<int> ports = new List<int>();

                ports = dt_Ports.AsEnumerable().Where(row => (bool)row["TCPScan"] == true).Select(r => r.Field<int>("Ports")).ToList(); ;

                return ports;
            }
        }

        public List<int> UDPPorts
        {
            get
            {
                List<int> ports = new List<int>();

                ports = dt_Ports.AsEnumerable().Where(row => (bool)row["UDPScan"] == true).Select(r => r.Field<int>("Ports")).ToList(); ;

                return ports;
            }
        }
    }


    public class IPGroupData
    {
        public IPGroupData()
        {
            dt.TableName = "IPGroups";

            dt.Columns.Add("IsActive", typeof(bool));
            dt.Columns.Add("IPGroupDescription", typeof(string));
            dt.Columns.Add("DeviceDescription", typeof(string));
            dt.Columns.Add("FirstIP", typeof(string));
            dt.Columns.Add("LastIP", typeof(string));
            dt.Columns.Add("Domain", typeof(string));
            dt.Columns.Add("DNSServers", typeof(string));                    
            dt.Columns.Add("NMGatewayIP", typeof(string));
            dt.Columns.Add("NMGatewayPort", typeof(string));
            dt.Columns.Add("AutomaticScan", typeof(bool));
            dt.Columns.Add("ScanIntervalMinutes", typeof(string));
        }

        
        private DataTable dt = new DataTable();

        public DataTable IPGroupsDT
        {
            get { return dt; }
            set { dt = value; }
        }

        public bool LoadIPGroups()
        {
            return true;
        }

        public bool SaveIPGroups()
        {
            return true;
        }
    }



    public class InternalDeviceNames
    {
        public InternalDeviceNames()
        {
            dt.TableName = "InternalDeviceNames";

            dt.Columns.Add("InternalName", typeof(string));
            dt.Columns.Add("Hostname", typeof(string));
            dt.Columns.Add("MAC", typeof(string));
            dt.Columns.Add("StaticIP", typeof(string));           
        }

        private DataTable dt = new DataTable();

        public DataTable InternalNames
        {
            get { return dt; }
            set { dt = value; }
        }
    }
}
