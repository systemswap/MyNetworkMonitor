using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    public class ScanResults
    {
        public ScanResults()
        {
            dt_NetworkResults.Columns.Add("IPGroup", typeof(string));
            dt_NetworkResults.Columns.Add("DeviceGroup", typeof(string));            
            dt_NetworkResults.Columns.Add("PingStatus", typeof(byte[]));
            dt_NetworkResults.Columns.Add("ARPStatus", typeof(byte[]));
            dt_NetworkResults.Columns.Add("SSDPStatus", typeof(byte[]));
            //dt_NetworkResults.Columns.Add("SendAlert", typeof(bool));
            dt_NetworkResults.Columns.Add("IP", typeof(string));
            dt_NetworkResults.Columns.Add("ResponseTime", typeof(string));
            dt_NetworkResults.Columns.Add("InternalName", typeof(string));
            dt_NetworkResults.Columns.Add("Hostname", typeof(string));            
            dt_NetworkResults.Columns.Add("Aliases", typeof(string));
            dt_NetworkResults.Columns.Add("ReverseLookUpStatus", typeof(byte[]));
            dt_NetworkResults.Columns.Add("ReverseLookUpIPs", typeof(string));
            dt_NetworkResults.Columns.Add("TCP_Ports", typeof(string));
            dt_NetworkResults.Columns.Add("OpenUDP_Ports", typeof(string));
            dt_NetworkResults.Columns.Add("Comment", typeof(string));
            dt_NetworkResults.Columns.Add("Mac", typeof(string));
            dt_NetworkResults.Columns.Add("Vendor", typeof(string));
            dt_NetworkResults.Columns.Add("Exception", typeof(string));
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
            dt_Ports.Columns.Add("Ports", typeof(int));
            dt_Ports.Columns.Add("UseAtTCP", typeof(bool));
            dt_Ports.Columns.Add("UseAtUDP", typeof(bool));
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
            dt_Ports.Rows.Add(80, true, false, "http");
            dt_Ports.Rows.Add(88, true, true, "kerberos Network authentication system");
            dt_Ports.Rows.Add(101, true, false, "hostname NIC host name");
            dt_Ports.Rows.Add(115, true, false, "sftp Simple file transfer protocol");
            dt_Ports.Rows.Add(117, false, true, "uucp-path File transfer between Unix systems");
            dt_Ports.Rows.Add(119, false, true, "nntp Transfer of messages in news groups");
            dt_Ports.Rows.Add(123, false, true, "ntp Time synchronization service");
            dt_Ports.Rows.Add(135, true, false, "net send ersatz für 139");
            dt_Ports.Rows.Add(137, true, true, "netbios-ns NETBIOS name service");
            dt_Ports.Rows.Add(138, true, true, "netbios-dgm NETBIOS datagram service");
            dt_Ports.Rows.Add(139, true, true, "netbios-ssn NETBIOS session service");
            dt_Ports.Rows.Add(194, true, true, "irc Internet relay chat");
            dt_Ports.Rows.Add(199, true, true, "smux SNMP UNIX multiplexer");
            dt_Ports.Rows.Add(443, true, false, "https HTTPS (HTTP over SSL/TLS)");
            dt_Ports.Rows.Add(445, true, false, "microsoft-ds SMB over TCP/IP");
            dt_Ports.Rows.Add(515, true, false, "");
            dt_Ports.Rows.Add(520, false, true, "");
            dt_Ports.Rows.Add(521, false, true, "");
            dt_Ports.Rows.Add(525, false, true, "");
            dt_Ports.Rows.Add(631, true, true, "");
            dt_Ports.Rows.Add(666, true, false, "");
            dt_Ports.Rows.Add(873, true, false, "");
            dt_Ports.Rows.Add(989, false, true, "");
            dt_Ports.Rows.Add(990, false, true, "");
            dt_Ports.Rows.Add(992, true, true, "");
            dt_Ports.Rows.Add(996, false, true, "");
            dt_Ports.Rows.Add(1040, true, true, "");
            dt_Ports.Rows.Add(1043, false, true, "");
            dt_Ports.Rows.Add(1067, true, false, "");
            dt_Ports.Rows.Add(1089, true, false, "");
            dt_Ports.Rows.Add(1300, true, false, "");
            dt_Ports.Rows.Add(1433, true, false, "");
            dt_Ports.Rows.Add(1900, false, true, "");
            dt_Ports.Rows.Add(2179, true, false, "");
            dt_Ports.Rows.Add(3000, true, true, "");
            dt_Ports.Rows.Add(3001, true, false, "");
            dt_Ports.Rows.Add(3306, true, true, "");
            dt_Ports.Rows.Add(4321, true, false, "");
            dt_Ports.Rows.Add(4840, true, false, "");
            dt_Ports.Rows.Add(5000, true, false, "");
            dt_Ports.Rows.Add(5001, true, false, "");
            dt_Ports.Rows.Add(5060, true, false, "");
            dt_Ports.Rows.Add(5357, true, false, "");
            dt_Ports.Rows.Add(8080, true, false, "");
            dt_Ports.Rows.Add(8443, true, false, "");
            dt_Ports.Rows.Add(9998, true, true, "");
            dt_Ports.Rows.Add(33434, true, true, "");
            dt_Ports.Rows.Add(33434, true, true, "");
        }

        private DataTable dt_Ports = new DataTable();

        public List<int> TCPPorts
        {
            get
            {
                List<int> ports = new List<int>();

                ports = dt_Ports.AsEnumerable().Where(row => (bool)row["UseAtTCP"] == true).Select(r => r.Field<int>("Ports")).ToList(); ;

                return ports;
            }
        }

        public List<int> UDPPorts
        {
            get
            {
                List<int> ports = new List<int>();

                ports = dt_Ports.AsEnumerable().Where(row => (bool)row["UseAtUDP"] == true).Select(r => r.Field<int>("Ports")).ToList(); ;

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
            dt.Columns.Add("GroupDescription", typeof(string));
            dt.Columns.Add("DeviceDescription", typeof(string));
            dt.Columns.Add("FirstIP", typeof(string));
            dt.Columns.Add("LastIP", typeof(string));
            dt.Columns.Add("DNSServer", typeof(string));
            dt.Columns.Add("AutomaticScan", typeof(bool));
            dt.Columns.Add("ScanIntervalMinutes", typeof(string));            
            dt.Columns.Add("GatewayIP", typeof(string));
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
}
