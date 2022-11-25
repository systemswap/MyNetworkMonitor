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
                var task = ScanTCPPorts_Task(ip, new small_TCP_PortScan().Ports);
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
            try
            {
                TcpClient tcpclnt = new TcpClient();

                await Task.Run(() => tcpclnt.ConnectAsync(IP, port).Wait(new TimeSpan(0, 0, 0, 0, 500), _clt));

                if (tcpclnt.Connected)
                {
                    tcpclnt.Close();
                    tcpclnt.Dispose();
                    return port;
                }
            }
            catch (Exception e)
            {
                Debug.WriteLine("Error Port: " + port);
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

                Task.Run(() => udp_clnt.Connect(new IPEndPoint(IPAddress.Parse(IP), port)));
                
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
        int[] _ports = { 7, 9, 20, 21, 22, 23, 25, 42, 43, 53, 80, 88, 101, 115, 135, 137, 138, 139, 443, 445, 515, 631, 666, 873, 992, 1040, 1433, 3000, 3306, 4321, 4840, 5000, 5060, 5357, 8080, 8443, 33434 };
        public List<int> Ports = new List<int>();
    }

    public class small_UDP_PortScan
    {
        public small_UDP_PortScan()
        {
            Ports.AddRange(_ports);
        }
        int[] _ports = { 7, 9, 21, 22, 42, 53, 88, 123, 137, 138, 139, 520, 521, 525, 631, 989, 990, 992, 1040, 1443, 3000, 3306, 33434 };
        public List<int> Ports = new List<int>();
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
