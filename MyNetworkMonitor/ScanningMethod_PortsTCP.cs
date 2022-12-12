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
using System.Text.RegularExpressions;
using System.Net.NetworkInformation;

namespace MyNetworkMonitor
{
    public class ScanningMethod_PortsTCP
    {
        //https://www.codeproject.com/Articles/1415/Introduction-to-TCP-client-server-in-C

        public ScanningMethod_PortsTCP()
        {

        }

        public event EventHandler<TcpPortScan_Task_FinishedEventArgs>? TcpPortScan_Task_Finished;
        public event EventHandler<TcpPortScan_Finished_EventArgs>? TcpPortScan_Finished;

        private CancellationToken _clt = new CancellationToken(false);




        public CancellationToken CancelPortScan
        {
            get { return _clt; }
            set { _clt = value; }
        }


        public async void ScanTCPPorts(List<IPToRefresh> ipsToRefresh, TimeSpan TimeOut)
        {
            var tasks = new List<Task>();
           
            foreach(IPToRefresh ip in ipsToRefresh)
            {
                {                   
                    var task = ScanTCPPorts_Task(ip, new PortCollection().TCPPorts, TimeOut);
                    if (task != null) tasks.Add(task);
                }
            }

            await Task.WhenAll(tasks);

            if (TcpPortScan_Finished != null) TcpPortScan_Finished(this, new TcpPortScan_Finished_EventArgs(true));
        }


        public async void ScanTCPPorts(List<IPToRefresh> IPs, List<int> TCP_Ports, TimeSpan TimeOut)
        {
            var tasks = new List<Task>();

            foreach (IPToRefresh ip in IPs)
            {
                var task = ScanTCPPorts_Task(ip, TCP_Ports, TimeOut);
                if (task != null) tasks.Add(task);
            }

            await Task.WhenAll(tasks);

            if (TcpPortScan_Finished != null) TcpPortScan_Finished(this, new TcpPortScan_Finished_EventArgs(true));
        }


        private async Task ScanTCPPorts_Task(IPToRefresh IP, List<int> Ports, TimeSpan TimeOut)
        {
            //List<int> _tcpPorts = new List<int>();

            ScannedPorts scannedPorts = new ScannedPorts();
            scannedPorts.IPGroupDescription = IP.IPGroupDescription;
            scannedPorts.DeviceDescription= IP.DeviceDescription;
            scannedPorts.IP = IP.IP;

            List<Task> tasks = new List<Task>();

            Parallel.ForEach(Ports, async port => 
            {
                if (!string.IsNullOrEmpty(IP.IP))
                {
                    //var task = ScanTCP_Port(IP, port, TimeOut);
                    try
                    {
                        PingReply reply =  new ScanningMethods_Ping().PingIPAsync(IP, TimeOut.Milliseconds).Result;
                        if (reply.Status == IPStatus.Success)
                        {
                            var task = ScanTCP_Port_via_Socket_Async(IP.IP, port, TimeOut);

                            switch (task.Result.PortState)
                            {
                                case PortScanState.PortIsOpen:
                                    scannedPorts.openPorts.Add((int)task.Result.Port);
                                    break;

                                case PortScanState.FirewallBlockedPort:
                                    scannedPorts.FirewallBlockedPorts.Add((int)task.Result.Port);
                                    break;

                                case PortScanState.TargetDeniedAccessToPort:
                                    scannedPorts.TargetDeniedAccessToPorts.Add((int)task.Result.Port);
                                    break;

                                case PortScanState.TargetNotReachable:
                                    break;

                                default:
                                    break;
                            }
                            if (task != null) tasks.Add(task);
                        }
                        else
                        {
                            string test = "";
                        }
                    }
                    catch (SocketException ex)
                    {
                        //throw;
                    }
                }
            });

            await Task.WhenAll(tasks);

            scannedPorts.openPorts.Sort();
            scannedPorts.FirewallBlockedPorts.Sort();
            scannedPorts.TargetDeniedAccessToPorts.Sort();

            if (TcpPortScan_Task_Finished != null)
            {
                int founded = scannedPorts.openPorts.Count + scannedPorts.FirewallBlockedPorts.Count + scannedPorts.TargetDeniedAccessToPorts.Count;

                if (founded > 0)
                {
                    TcpPortScan_Task_Finished(this, new TcpPortScan_Task_FinishedEventArgs(scannedPorts));
                }
                else
                {
                    TcpPortScan_Task_Finished(this, new TcpPortScan_Task_FinishedEventArgs(null));
                }

                //if (new SupportMethods().Is_Valid_IP(scannedPorts.IP))
                //{
                //    TcpPortScan_Task_Finished(this, new TcpPortScan_Task_FinishedEventArgs(scannedPorts));
                //}
            }
        }

        private async Task<PortScanResult> ScanTCP_Port(string IP, int port, TimeSpan TimeOut)
        {
            PortScanResult scanResult = new PortScanResult();
            scanResult.IP = IP;
            scanResult.Port = port;

            try
            {
                if (!new SupportMethods().Is_Valid_IP(IP))
                {
                    scanResult.PortState = PortScanState.TargetNotReachable;
                    return scanResult;
                }

                using (TcpClient tcpclnt = new TcpClient())
                {
                    await Task.Run(() => tcpclnt.ConnectAsync(IP, port).Wait(TimeOut.Milliseconds, _clt));
                    
                    if (tcpclnt.Connected)
                    {                        
                        scanResult.PortState = PortScanState.PortIsOpen;
                        return scanResult;
                    }
                }
            }
            catch (Exception ex)
            {
                //Debug.WriteLine("Error Port: " + port);
            }
            
            scanResult.PortState = PortScanState.TargetNotReachable;
            return scanResult;
        }


        public async Task<PortScanResult> ScanTCP_Port_via_Socket(string IP, int Port, TimeSpan TimeOut)
        {
            PortScanResult scanResult = new PortScanResult();

            scanResult.IP = IP;
            scanResult.Port = Port;

            using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                try
                {
                    Task.Run(() => socket.Connect(new IPEndPoint(IPAddress.Parse(IP), Port))).Wait(TimeOut);

                    //Debug.WriteLine("Connected to server.");

                    //if (PerformRST)
                    //{
                        //set the lingerstate to perform a reset
                        //socket.LingerState = new LingerOption(true, 0);
                    //}
                    //else
                    //{
                        socket.Close();
                    scanResult.PortState = PortScanState.PortIsOpen;
                    //}
                }
                catch (SocketException ex)
                {
                    //ex.ErrorCode 
                    //10013 Ausgehende Verbindung Blockiert durch Firewall
                    //10060 Host nicht erreichbar, Zeitüberschreitung
                    //10061 Host verweigert zugriff
                    if (ex.ErrorCode == 10013) scanResult.PortState |= PortScanState.FirewallBlockedPort;
                    if (ex.ErrorCode == 10060) scanResult.PortState = PortScanState.TargetNotReachable;
                    if (ex.ErrorCode == 10061) scanResult.PortState = PortScanState.TargetDeniedAccessToPort;

                    //throw ex;
                }
                return scanResult;
            }
        }


        public async Task<PortScanResult> ScanTCP_Port_via_Socket_Async(string IP, int Port, TimeSpan timeout)
        {
            PortScanResult scanResult = new PortScanResult();

            scanResult.IP = IP;
            scanResult.Port = Port;

            using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
            {
                try
                {
                    //IAsyncResult ar = socket.BeginConnect(new IPEndPoint(IPAddress.Parse(IP), Port), null, null);                    
                    //ar.AsyncWaitHandle.WaitOne(timeout.Milliseconds, true);

                    await socket.ConnectAsync(new IPEndPoint(IPAddress.Parse(IP), Port));
                    if (socket.Connected)
                    {
                        socket.Close();
                        scanResult.PortState = PortScanState.PortIsOpen;
                    }


                    //if (ar.IsCompleted)
                    //{
                        //Connected

                        //if (PerformRST)
                        //{
                        //set the lingerstate to perform a reset
                        //socket.LingerState = new LingerOption(true, 0);
                        //}
                        //else
                        //{
                        //socket.Close();
                        //}

                        //scanResult.PortState = PortScanState.PortIsOpen;                        
                    //}
                    //else
                    //{
                    //    socket.Close();
                    //    throw new SocketException(10060); // Connection timed out.
                    //}
                }
                catch (SocketException ex)
                {
                    //ex.ErrorCode 
                    //10013 Ausgehende Verbindung Blockiert durch Firewall
                    //10060 Host nicht erreichbar, Zeitüberschreitung
                    //10061 Host verweigert zugriff

                    if (ex.ErrorCode == 10013) scanResult.PortState = PortScanState.FirewallBlockedPort;
                    if (ex.ErrorCode == 10060) scanResult.PortState = PortScanState.TargetNotReachable;
                    if (ex.ErrorCode == 10061) scanResult.PortState = PortScanState.TargetDeniedAccessToPort;

                    //throw ex;
                }
                return scanResult;
            }
        }

        public enum PortScanState
        {
            PortIsOpen
         , FirewallBlockedPort
         , TargetDeniedAccessToPort
         , TargetNotReachable
        }

        public class PortScanResult
        {
            public PortScanResult()
            {

            }
            public string IP { get; set; }
            public PortScanState PortState { get; set; }
            public int? Port { get; set; }
        }

        public class ScannedPorts
        {
            public string IPGroupDescription = string.Empty;
            public string DeviceDescription = string.Empty;
            public string IP = string.Empty;
            public List<int> openPorts = new List<int>();
            public List<int> FirewallBlockedPorts = new List<int>();
            public List<int> TargetDeniedAccessToPorts = new List<int>();
        }





        /* ############# Events #################*/


        public class TcpPortScan_Task_FinishedEventArgs : EventArgs
        {
            public TcpPortScan_Task_FinishedEventArgs(ScannedPorts ScannedPorts)
            {
                _ScannedPorts = ScannedPorts;
            }

            private ScannedPorts _ScannedPorts;
            public ScannedPorts ScannedPorts { get { return _ScannedPorts; } }
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
    }
}

