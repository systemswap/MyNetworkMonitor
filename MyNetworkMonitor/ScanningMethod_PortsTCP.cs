using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

using System.Net;


namespace MyNetworkMonitor
{
    public class ScanningMethod_PortsTCP
    {
        //https://www.codeproject.com/Articles/1415/Introduction-to-TCP-client-server-in-C

        //    public ScanningMethod_PortsTCP()
        //    {

        //    }

        //    public event EventHandler<ScanTask_Finished_EventArgs>? TcpPortScan_Task_Finished;
        //    public event EventHandler<Method_Finished_EventArgs>? TcpPortScan_Finished;

        //    private CancellationToken _clt = new CancellationToken();

        //    public CancellationToken CancelPortScan
        //    {
        //        get { return _clt; }
        //        set { _clt = value; }
        //    }


        //    public async void ScanTCPPorts(List<IPToScan> IPs, TimeSpan TimeOut)
        //    {
        //        var tasks = new List<Task>();

        //        foreach (IPToScan ipToScan in IPs)
        //        {
        //            {
        //                var task = Task.Run(() => ScanTCPPorts_Task(ipToScan, new PortCollection().TCPPorts, TimeOut));
        //                if (task != null) tasks.Add(task);
        //            }
        //        }

        //        await Task.WhenAll(tasks.Where(t => t != null));

        //        if (TcpPortScan_Finished != null) TcpPortScan_Finished(this, new Method_Finished_EventArgs());
        //    }


        //    public async void ScanTCPPorts(List<IPToScan> IPs, List<int> TCP_Ports, TimeSpan TimeOut)
        //    {
        //        var tasks = new List<Task>();

        //        foreach (IPToScan ipToScan in IPs)
        //        {
        //            var task = Task.Run(() => ScanTCPPorts_Task(ipToScan, TCP_Ports, TimeOut));
        //            if (task != null) tasks.Add(task);
        //        }

        //        await Task.WhenAll(tasks.Where(t => t != null));

        //        if (TcpPortScan_Finished != null) TcpPortScan_Finished(this, new Method_Finished_EventArgs());
        //    }


        //    private async Task ScanTCPPorts_Task(IPToScan ipToScan, List<int> Ports, TimeSpan TimeOut)
        //    {
        //        List<Task> tasks = new List<Task>();

        //        Parallel.ForEach(Ports, port =>
        //        {
        //            if (_clt.IsCancellationRequested)
        //            {
        //                return;
        //            }

        //            if (!string.IsNullOrEmpty(ipToScan.IPorHostname))
        //            {
        //                try
        //                {

        //                    var task = ScanTCP_Port_via_Socket_Async(ipToScan.IPorHostname, port, TimeOut);

        //                    switch (task.Result.PortState)
        //                    {
        //                        case PortScanState.PortIsOpen:
        //                            ipToScan.TCP_OpenPorts.Add((int)task.Result.Port);
        //                            break;

        //                        case PortScanState.FirewallBlockedPort:
        //                            ipToScan.TCP_FirewallBlockedPorts.Add((int)task.Result.Port);
        //                            break;

        //                        case PortScanState.TargetDeniedAccessToPort:
        //                            ipToScan.TCP_TargetDeniedAccessToPorts.Add((int)task.Result.Port);
        //                            break;

        //                        case PortScanState.TargetNotReachable:
        //                            break;

        //                        default:
        //                            break;
        //                    }
        //                    if (task != null) tasks.Add(task);

        //                }
        //                catch (Exception ex)
        //                {
        //                    //throw;
        //                }
        //            }
        //        });

        //        await Task.WhenAll(tasks.Where(t => t != null));

        //        ipToScan.TCP_OpenPorts.Sort();
        //        ipToScan.TCP_FirewallBlockedPorts.Sort();
        //        ipToScan.TCP_TargetDeniedAccessToPorts.Sort();

        //        if (TcpPortScan_Task_Finished != null)
        //        {
        //            int founded = ipToScan.TCP_OpenPorts.Count + ipToScan.TCP_FirewallBlockedPorts.Count + ipToScan.TCP_TargetDeniedAccessToPorts.Count;

        //            if (founded > 0)
        //            {
        //                ipToScan.UsedScanMethod = ScanMethod.TCPPorts;

        //                ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs();
        //                scanTask_Finished.ipToScan = ipToScan;

        //                TcpPortScan_Task_Finished(this, scanTask_Finished);
        //            }
        //            else
        //            {
        //                TcpPortScan_Task_Finished(this, null);
        //            }
        //        }
        //    }


        //    public async Task<PortScanResult> ScanTCP_Port_via_Socket_Async(string IP, int Port, TimeSpan timeout)
        //    {
        //        PortScanResult scanResult = new PortScanResult();

        //        scanResult.IP = IP;
        //        scanResult.Port = Port;

        //        using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
        //        {
        //            try
        //            {

        //                for (int i = 0; i < 4; i++)
        //                {
        //                    socket.ConnectAsync(new IPEndPoint(IPAddress.Parse(IP), Port)).Wait(timeout, _clt);
        //                    if (socket.Connected) break;
        //                }


        //                if (socket.Connected)
        //                {
        //                    socket.Close();
        //                    scanResult.PortState = PortScanState.PortIsOpen;
        //                }
        //                else
        //                {
        //                    socket.Close();
        //                    throw new SocketException(10060);
        //                }
        //            }
        //            catch (SocketException ex)
        //            {
        //                if (ex.ErrorCode == 10013) scanResult.PortState = PortScanState.FirewallBlockedPort;
        //                if (ex.ErrorCode == 10060) scanResult.PortState = PortScanState.TargetNotReachable;
        //                if (ex.ErrorCode == 10061) scanResult.PortState = PortScanState.TargetDeniedAccessToPort;
        //            }
        //            return scanResult;
        //        }
        //    }

        //    public enum PortScanState
        //    {
        //        PortIsOpen,
        //        FirewallBlockedPort,
        //        TargetDeniedAccessToPort,
        //        TargetNotReachable
        //    }

        //    public class PortScanResult
        //    {
        //        public PortScanResult()
        //        {

        //        }
        //        public string IP { get; set; }
        //        public PortScanState PortState { get; set; }
        //        public int? Port { get; set; }
        //    }
        //}




        public ScanningMethod_PortsTCP() { }

        public event EventHandler<ScanTask_Finished_EventArgs>? TcpPortScan_Task_Finished;
        public event EventHandler<Method_Finished_EventArgs>? TcpPortScan_Finished;

        private CancellationTokenSource _cts = new CancellationTokenSource();
        public CancellationToken CancelPortScan
        {
            get => _cts.Token;
            set => _cts = CancellationTokenSource.CreateLinkedTokenSource(value);
        }

        public async Task ScanTCPPortsAsync(List<IPToScan> IPs, TimeSpan TimeOut)
        {
            await ScanTCPPortsAsync(IPs, new PortCollection().TCPPorts, TimeOut);
        }

        public async Task ScanTCPPortsAsync(List<IPToScan> IPs, List<int> TCP_Ports, TimeSpan TimeOut)
        {
            //var tasks = IPs
            //    .Where(ip => !string.IsNullOrEmpty(ip.IPorHostname))
            //    .Select(ip => ScanTCPPorts_Task(ip, TCP_Ports, TimeOut))
            //    .ToList();

            //await Task.WhenAll(tasks);

            //TcpPortScan_Finished?.Invoke(this, new Method_Finished_EventArgs());

            var tasks = new List<Task>();

            foreach (var ip in IPs.Where(ip => !string.IsNullOrEmpty(ip.IPorHostname)))
            {
                tasks.Add(ScanTCPPorts_Task(ip, TCP_Ports, TimeOut));
                await Task.Delay(20); // 20ms Verzögerung zwischen den IP-Scans
            }

            await Task.WhenAll(tasks);

            TcpPortScan_Finished?.Invoke(this, new Method_Finished_EventArgs());
        }

        private async Task ScanTCPPorts_Task(IPToScan ipToScan, List<int> Ports, TimeSpan TimeOut)
        {
            if (_cts.Token.IsCancellationRequested)
                return;

            ipToScan.UsedScanMethod = ScanMethod.TCPPorts;

            List<Task<PortScanResult>> tasks = new List<Task<PortScanResult>>();

            foreach (int port in Ports)
            {
                if (_cts.Token.IsCancellationRequested)
                    return;

                await Task.Delay(20);

                tasks.Add(ScanTCP_Port_via_Socket_Async(ipToScan.IPorHostname, port, TimeOut));
            }

            var results = await Task.WhenAll(tasks);

            foreach (var result in results)
            {
                switch (result.PortState)
                {
                    case PortScanState.PortIsOpen:
                        ipToScan.TCP_OpenPorts.Add(result.Port.Value);
                        break;
                    case PortScanState.FirewallBlockedPort:
                        ipToScan.TCP_FirewallBlockedPorts.Add(result.Port.Value);
                        break;
                    case PortScanState.TargetDeniedAccessToPort:
                        ipToScan.TCP_TargetDeniedAccessToPorts.Add(result.Port.Value);
                        break;
                }
            }

            ipToScan.TCP_OpenPorts.Sort();
            ipToScan.TCP_FirewallBlockedPorts.Sort();
            ipToScan.TCP_TargetDeniedAccessToPorts.Sort();

            TcpPortScan_Task_Finished?.Invoke(this, new ScanTask_Finished_EventArgs { ipToScan = ipToScan });
        }

        public async Task<PortScanResult> ScanTCP_Port_via_Socket_Async(string IP, int Port, TimeSpan timeout)
        {
            var scanResult = new PortScanResult { IP = IP, Port = Port };

            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)
            {
                Blocking = false
            };

            try
            {
                var connectTask = socket.ConnectAsync(new IPEndPoint(IPAddress.Parse(IP), Port));

                if (await Task.WhenAny(connectTask, Task.Delay(timeout, _cts.Token)) == connectTask)
                {
                    if (socket.Connected)
                    {
                        socket.Close();
                        scanResult.PortState = PortScanState.PortIsOpen;
                    }
                    else
                    {
                        scanResult.PortState = PortScanState.TargetNotReachable;
                    }
                }
                else
                {
                    scanResult.PortState = PortScanState.TargetNotReachable;
                }
            }
            catch (SocketException ex)
            {
                scanResult.PortState = ex.SocketErrorCode switch
                {
                    SocketError.AccessDenied => PortScanState.FirewallBlockedPort,
                    SocketError.TimedOut => PortScanState.TargetNotReachable,
                    SocketError.ConnectionRefused => PortScanState.TargetDeniedAccessToPort,
                    _ => PortScanState.TargetNotReachable
                };
            }

            return scanResult;
        }
    }

    public enum PortScanState
    {
        PortIsOpen,
        FirewallBlockedPort,
        TargetDeniedAccessToPort,
        TargetNotReachable
    }

    public class PortScanResult
    {
        public string IP { get; set; }
        public PortScanState PortState { get; set; }
        public int? Port { get; set; }
    }
}


