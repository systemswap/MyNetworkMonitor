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
using System.Windows;

namespace MyNetworkMonitor
{
    internal class ScanningMethode_Sockets_Ports
    {
        //https://www.codeproject.com/Articles/1415/Introduction-to-TCP-client-server-in-C

        public ScanningMethode_Sockets_Ports()
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

        public DataTable dt_Ports = new DataTable();
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


        public async void ScanTCPPorts(List<string> IPs, TimeSpan TimeOut)
        {
            var tasks = new List<Task>();

            foreach (var ip in IPs)
            {
                //var task = ScanTCPPorts_Task(ip, new small_TCP_PortScan().Ports);
                var task = ScanTCPPorts_Task(ip, TCPPorts, TimeOut);
                tasks.Add(task);
            }

            await Task.WhenAll(tasks);

            if (TcpPortScan_Finished != null) TcpPortScan_Finished(this, new TcpPortScan_Finished_EventArgs(true));
        }


        public async void ScanTCPPorts(List<string> IPs, List<int> TCP_Ports, TimeSpan TimeOut)
        {
            var tasks = new List<Task>();

            foreach (var ip in IPs)
            {
                var task = ScanTCPPorts_Task(ip, TCP_Ports, TimeOut);
                tasks.Add(task);
            }

            await Task.WhenAll(tasks);

            if (TcpPortScan_Finished != null) TcpPortScan_Finished(this, new TcpPortScan_Finished_EventArgs(true));
        }




        private async Task ScanTCPPorts_Task(string IP, List<int> Ports, TimeSpan TimeOut)
        {
            List<int> _tcpPorts = new List<int>();

            OpenPorts openPorts = new OpenPorts();

            openPorts.IP = IP;

            var tasks = new List<Task>();

            Parallel.ForEach(Ports, port =>
            {
                if (!string.IsNullOrEmpty(IP))
                {
                    var task = ScanTCP_Port(IP, port, TimeOut);
                    if (task.Result != -1) _tcpPorts.Add(task.Result);
                    tasks.Add(task);
                }
            });

            await Task.WhenAll(tasks);
            _tcpPorts.Sort();
            openPorts.openPorts = _tcpPorts;

            if (TcpPortScan_Task_Finished != null) TcpPortScan_Task_Finished(this, new TcpPortScan_Task_FinishedEventArgs(openPorts));
        }


        private async Task<int> ScanTCP_Port(string IP, int port, TimeSpan TimeOut)
        {
            //try
            //{
            //    using (var client = new TcpClient())
            //    {
            //        var result = client.BeginConnect(IP, port, null, null);
            //        var success = result.AsyncWaitHandle.WaitOne(TimeOut);
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
                    await Task.Run(() => tcpclnt.ConnectAsync(IP, port).Wait(TimeOut.Milliseconds, _clt));
                    
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
                var task = ScanUDPPorts_Task(ip, UDPPorts);
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

        
        UdpClient udp_clnt;
        private async Task<int> ScanUDP_Port(string IP, int port)
        {
            try
            {

                // This constructor arbitrarily assigns the local port number.
                UdpClient udpClient = new UdpClient(port);
                try
                {
                    udpClient.Connect(IP, port);

                    // Sends a message to the host to which you have connected.
                    Byte[] sendBytes = Encoding.ASCII.GetBytes("Is anybody there?");

                    udpClient.Send(sendBytes, sendBytes.Length);

                    //IPEndPoint object will allow us to read datagrams sent from any source.
                    IPEndPoint RemoteIpEndPoint = new IPEndPoint(IPAddress.Any, 0);

                    // Blocks until a message returns on this socket from a remote host.
                    Byte[] receiveBytes = udpClient.Receive(ref RemoteIpEndPoint);
                    string returnData = Encoding.ASCII.GetString(receiveBytes);

                    // Uses the IPEndPoint object to determine which of these two hosts responded.
                    Debug.WriteLine("This is the message you received " +
                                                 returnData.ToString());
                    Debug.WriteLine("This message was sent from " +
                                                RemoteIpEndPoint.Address.ToString() +
                                                " on their port number " +
                                                RemoteIpEndPoint.Port.ToString());

                    udpClient.Close();
                    //udpClientB.Close();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.ToString());
                }


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
