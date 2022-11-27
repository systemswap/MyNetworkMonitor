using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Media;
using System.Windows.Threading;
using System.Net;
using System.Text;
using Rssdp.Infrastructure;
using static System.Net.Mime.MediaTypeNames;
using System.Security.Cryptography;

namespace MyNetworkMonitor
{
    internal class ScanningMethode_Sockets_Ports
    {
        //https://www.codeproject.com/Articles/1415/Introduction-to-TCP-client-server-in-C

        public ScanningMethode_Sockets_Ports()
        {

        }

        public event EventHandler<TcpPortScan_Task_FinishedEventArgs>? TcpPortScan_Task_Finished;
        public event EventHandler<TcpPortScan_Finished_EventArgs>? TcpPortScan_Finished;

        public event EventHandler<UDPPortScan_Task_FinishedEventArgs>? UDPPortScan_Task_Finished;
        public event EventHandler<UDPPortScan_Finished_EventArgs>? UDPPortScan_Finished;

        private CancellationToken _clt = new CancellationToken(false);
        public CancellationToken CancelPortScan
        {
            get { return _clt; }
            set { _clt = value; }
        }


        public async void ScanTCPPorts(List<string> IPs)
        {
            var tasks = new List<Task>();

            foreach (var ip in IPs)
            {
                //var task = ScanTCPPorts_Task(ip, new small_TCP_PortScan().Ports);
                var task = ScanTCPPorts_Task(ip, new Ports().TCPPorts);
                tasks.Add(task);
            }

            await Task.WhenAll(tasks);

            if (TcpPortScan_Finished != null) TcpPortScan_Finished(this, new TcpPortScan_Finished_EventArgs(true));
        }


        public async void ScanTCPPorts(List<string> IPs, List<int> TCP_Ports)
        {
            var tasks = new List<Task>();

            foreach (var ip in IPs)
            {
                var task = ScanTCPPorts_Task(ip, TCP_Ports);
                tasks.Add(task);
            }

            await Task.WhenAll(tasks);

            if (TcpPortScan_Finished != null) TcpPortScan_Finished(this, new TcpPortScan_Finished_EventArgs(true));
        }




        private async Task ScanTCPPorts_Task(string IP, List<int> Ports)
        {
            List<int> _tcpPorts = new List<int>();

            OpenPorts openPorts = new OpenPorts();

            openPorts.IP = IP;

            var tasks = new List<Task>();

            Parallel.ForEach(Ports, port =>
            {
                if (!string.IsNullOrEmpty(IP))
                {
                    var task = ScanTCP_Port(IP, port);
                    if (task.Result != -1) _tcpPorts.Add(task.Result);
                    tasks.Add(task);
                }
            });

            await Task.WhenAll(tasks);
            _tcpPorts.Sort();
            openPorts.openPorts = _tcpPorts;

            if (TcpPortScan_Task_Finished != null) TcpPortScan_Task_Finished(this, new TcpPortScan_Task_FinishedEventArgs(openPorts));
        }


        private async Task<int> ScanTCP_Port(string IP, int port)
        {
            //try
            //{
            //    using (var client = new TcpClient())
            //    {
            //        var result = client.BeginConnect(IP, port, null, null);
            //        var success = result.AsyncWaitHandle.WaitOne(50);
            //        client.EndConnect(result);
            //        return port;
            //    }
            //}
            //catch
            //{
            //    return -1;
            //}

            try
            {
                using (TcpClient tcpclnt = new TcpClient())
                {
                    await Task.Run(() => tcpclnt.ConnectAsync(IP, port).Wait(new TimeSpan(0, 0, 0, 0, 500), _clt));

                    if (tcpclnt.Connected)
                    {
                        //tcpclnt.Close();
                        //tcpclnt.Dispose();
                        return port;
                    }
                }
            }
            catch (Exception e)
            {
                //Debug.WriteLine("Error Port: " + port);
            }
            return -1;
        }







        public async void ScanUDPPorts(List<string> IPs)
        {
            var tasks = new List<Task>();

            foreach (var ip in IPs)
            {
                var task = ScanUDPPorts_Task(ip, new small_UDP_PortScan().Ports);
                tasks.Add(task);
            }

            await Task.WhenAll(tasks);

            if (UDPPortScan_Finished != null) UDPPortScan_Finished(this, new UDPPortScan_Finished_EventArgs(true));
        }

        public async void ScanUDPPorts(List<string> IPs, List<int> UDP_Ports)
        {
            var tasks = new List<Task>();

            foreach (var ip in IPs)
            {
                var task = ScanUDPPorts_Task(ip, UDP_Ports);
                tasks.Add(task);
            }

            await Task.WhenAll(tasks);

            if (UDPPortScan_Finished != null) UDPPortScan_Finished(this, new UDPPortScan_Finished_EventArgs(true));
        }

        private async Task ScanUDPPorts_Task(string IP, List<int> Ports)
        {
            List<int> _UDPPorts = new List<int>();

            OpenPorts openPorts = new OpenPorts();

            openPorts.IP = IP;

            var tasks = new List<Task>();

            Parallel.ForEach(Ports, port =>
            {
                var task = ScanUDP_Port(IP, port);
                if (task.Result != -1) _UDPPorts.Add(task.Result);
                tasks.Add(task);
            });

            await Task.WhenAll(tasks);
            _UDPPorts.Sort();
            openPorts.openPorts = _UDPPorts;

            if (UDPPortScan_Task_Finished != null) UDPPortScan_Task_Finished(this, new UDPPortScan_Task_FinishedEventArgs(openPorts));
        }

        private async Task<int> ScanUDP_Port(string IP, int port)
        {
            try
            {
                UdpClient udp_clnt = new UdpClient();
                udp_clnt.Connect(new IPEndPoint(IPAddress.Parse(IP), port));

                return port;
            }
            catch (Exception e)
            {
                Debug.WriteLine($"Error Port: {port} {e.Message}");
            }
            return -1;
        }
    }


    public class OpenPorts
    {
        public string IP = string.Empty;
        public List<int> openPorts = new List<int>();
    }

    public class small_TCP_PortScan
    {
        public small_TCP_PortScan()
        {
            Ports.AddRange(_ports);
        }
        int[] _ports = { 7, 9, 20, 21, 22, 23, 25, 42, 43, 53, 80, 88, 101, 115, 135, 137, 138, 139, 443, 445, 515, 631, 666, 873, 992, 1040, 1067, 1089, 1300, 1433, 2179, 3000, 3001, 3306, 4321, 4840, 5000, 5001, 5060, 5357, 8080, 8443, 9998, 33434 };
        public List<int> Ports = new List<int>();
    }

    public class small_UDP_PortScan
    {
        public small_UDP_PortScan()
        {
            Ports.AddRange(_ports);
        }
        int[] _ports = { 7, 9, 21, 22, 42, 53, 88, 123, 199,137, 138, 139, 520, 521, 525, 631, 989, 990, 992, 996, 1040, 1443, 1900, 3000, 3306, 9998, 32769, 33434 };        
        public List<int> Ports = new List<int>();
    }
    
    public class Ports
    {
        public Ports()
        {
            dt.Columns.Add("Ports", typeof(int));
            dt.Columns.Add("UseAtTCP", typeof(bool));
            dt.Columns.Add("UseAtUDP", typeof(bool));
            dt.Columns.Add("Description", typeof(string));

            dt.Rows.Add(7, true, true, "ICMP Echo Service Ping");
            dt.Rows.Add(9, true, true, "Zero service for test purposes");
            dt.Rows.Add(20, true, false, "FTP data transfer");
            dt.Rows.Add(21, true, true, "FTP connection");
            dt.Rows.Add(22, true, true, "SSH");
            dt.Rows.Add(23, true, false, "Telnet");
            dt.Rows.Add(25, true, false, "smtp");
            dt.Rows.Add(42, true, true, "nameserver");
            dt.Rows.Add(43, true, false, "WHOIS directory service");
            dt.Rows.Add(53, true, true, "DNS name resolver");
            dt.Rows.Add(80, true, false, "http");
            dt.Rows.Add(88, true, true, "kerberos Network authentication system");
            dt.Rows.Add(101, true, false, "hostname NIC host name");
            dt.Rows.Add(115, true, false, "sftp Simple file transfer protocol");
            dt.Rows.Add(117, false, true, "uucp-path File transfer between Unix systems");
            dt.Rows.Add(119, false, true, "nntp Transfer of messages in news groups");
            dt.Rows.Add(123, false, true, "ntp Time synchronization service");
            dt.Rows.Add(135, true, false, "net send ersatz für 139");
            dt.Rows.Add(137, true, true, "netbios-ns NETBIOS name service");
            dt.Rows.Add(138, true, true, "netbios-dgm NETBIOS datagram service");
            dt.Rows.Add(139, true, true, "netbios-ssn NETBIOS session service");
            dt.Rows.Add(194, true, true, "irc Internet relay chat");
            dt.Rows.Add(199, true, true, "smux SNMP UNIX multiplexer");
            dt.Rows.Add(443, true, false, "https HTTPS (HTTP over SSL/TLS)");
            dt.Rows.Add(445, true, false, "microsoft-ds SMB over TCP/IP");
            dt.Rows.Add(515, true, false, "");
            dt.Rows.Add(520, false, true, "");
            dt.Rows.Add(521, false, true, "");
            dt.Rows.Add(525, false, true, "");
            dt.Rows.Add(631, true, true, "");
            dt.Rows.Add(666, true, false, "");
            dt.Rows.Add(873, true, false, "");
            dt.Rows.Add(989, false, true, "");
            dt.Rows.Add(990, false, true, "");
            dt.Rows.Add(992, true, true, "");
            dt.Rows.Add(996, false, true, "");
            dt.Rows.Add(1040, true, true, "");
            dt.Rows.Add(1043, false, true, "");
            dt.Rows.Add(1067, true, false, "");
            dt.Rows.Add(1089, true, false, "");
            dt.Rows.Add(1300, true, false, "");
            dt.Rows.Add(1433, true, false, "");
            dt.Rows.Add(1900, false, true, "");
            dt.Rows.Add(2179, true, false, "");
            dt.Rows.Add(3000, true, true, "");
            dt.Rows.Add(3001, true, false, "");
            dt.Rows.Add(3306, true, true, "");
            dt.Rows.Add(4321, true, false, "");
            dt.Rows.Add(4840, true, false, "");
            dt.Rows.Add(5000, true, false, "");
            dt.Rows.Add(5001, true, false, "");
            dt.Rows.Add(5060, true, false, "");
            dt.Rows.Add(5357, true, false, "");
            dt.Rows.Add(8080, true, false, "");
            dt.Rows.Add(8443, true, false, "");
            dt.Rows.Add(9998, true, true, "");
            dt.Rows.Add(33434, true, true, "");
            dt.Rows.Add(33434, true, true, "");
        }

        public DataTable dt = new DataTable();
        public List<int> TCPPorts 
        { 
            get 
            { 
                List<int> ports = new List<int>();

                ports = dt.AsEnumerable().Where(row => (bool)row["UseAtTCP"] == true).Select(r => r.Field<int>("Ports")).ToList(); ;

                return ports; 
            } 
        }

        public List<int> UDPPorts
        {
            get
            {
                List<int> ports = new List<int>();

                ports = dt.AsEnumerable().Where(row => (bool)row["UseAtUDP"] == true).Select(r => r.Field<int>("Ports")).ToList(); ;

                return ports;
            }
        }

    }



    /* ############# Events #################*/


    public class TcpPortScan_Task_FinishedEventArgs : EventArgs
    {
        public TcpPortScan_Task_FinishedEventArgs(OpenPorts openPorts)
        {
            _OpenPorts = openPorts;
        }

        private OpenPorts _OpenPorts;
        public OpenPorts OpenPorts { get { return _OpenPorts; } }
    }

    public class TcpPortScan_Finished_EventArgs : EventArgs
    {
        public TcpPortScan_Finished_EventArgs(bool Finished)
        {
            _finished = Finished;
        }
        private bool _finished = false;
        public bool Finished { get { return _finished; } }

    }

    public class UDPPortScan_Task_FinishedEventArgs : EventArgs
    {
        public UDPPortScan_Task_FinishedEventArgs(OpenPorts openPorts)
        {
            _OpenPorts = openPorts;
        }

        private OpenPorts _OpenPorts;
        public OpenPorts OpenPorts { get { return _OpenPorts; } }
    }

    public class UDPPortScan_Finished_EventArgs : EventArgs
    {
        public UDPPortScan_Finished_EventArgs(bool Finished)
        {
            _finished = Finished;
        }
        private bool _finished = false;
        public bool Finished { get { return _finished; } }

    }
}
