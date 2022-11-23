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

namespace MyNetworkMonitor
{
    internal class ScanningMethode_Sockets_Ports
    {
        //https://www.codeproject.com/Articles/1415/Introduction-to-TCP-client-server-in-C

        public ScanningMethode_Sockets_Ports(ScanResults scanResults)
        {
            _scannResults = scanResults;
        }

        ScanResults _scannResults;

        List<OpenPorts> all_open_TCP_Ports = new List<OpenPorts>();

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
            if(CustomEvent_TcpPortScanFinished != null) CustomEvent_TcpPortScanFinished(this, new TcpPortScannFinishedEventArgs(all_open_TCP_Ports));
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
            if (CustomEvent_TcpPortScanFinished != null) CustomEvent_TcpPortScanFinished(this, new TcpPortScannFinishedEventArgs(all_open_TCP_Ports));
        }

        

        public event EventHandler<TcpPortScannFinishedEventArgs>? CustomEvent_TcpPortScanFinished;
        public event EventHandler<TcpPortScanTaskFinishedEventArgs>? CustomEvent_TcpPortScanTaskFinished;

        public async Task<OpenPorts> ScanTCPPorts_Task(string IP, List<int> Ports)
        {
            OpenPorts ports = new OpenPorts();

            ports.IP = IP;

            var tasks = new List<Task>();

            Parallel.ForEach(Ports, port  =>
            {
                var task = Task<int>.Run(() => ScanTCP_Port(IP, port));
                if (task.Result != -1) _tcpPorts.Add(task.Result);
                tasks.Add(task);
            });

            await Task.WhenAll(tasks);
            ports.openPorts = _tcpPorts;
            all_open_TCP_Ports.Add(ports);

            DataRow[] rows = _scannResults.ResultTable.Select("IP = '" + IP + "'");
            if (rows.ToList().Count > 0)
            {
                int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);
                _scannResults.ResultTable.Rows[rowIndex]["OpenTCP_Ports"] = string.Join("; ", _tcpPorts);
            }
            else
            {
                DataRow row = _scannResults.ResultTable.NewRow();
                row["IP"] = IP;
                row["OpenTCP_Ports"] = string.Join("; ", _tcpPorts);
                _scannResults.ResultTable.Rows.Add(row);
            }
            return ports;
        }

        List<int> _tcpPorts= new List<int>();
        private async Task<int> ScanTCP_Port(string IP, int port)
        {
            try
            {
                TcpClient tcpclnt = new TcpClient();

                if (tcpclnt.ConnectAsync(IP, port).Wait(500))
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
        int[] _ports = { 7, 9, 20, 21, 22, 23, 25, 42, 43, 53, 80, 88, 101, 115, 137, 138, 139, 443, 445, 515, 631, 666, 873, 992, 1433, 3306, 4321, 4840, 8443, 33434 };
        public List<int> Ports = new List<int>();            
    }

    public class small_UDP_PortScan
    {
        public small_UDP_PortScan()
        {
            Ports.AddRange(_ports);
        }
        int[] _ports = { 7, 9, 21, 22, 42, 53, 88, 123, 137, 138, 139, 520, 521, 525, 631, 992, 1443, 3306, 33434 };
        public List<int> Ports = new List<int>();
    }


    /* ############# Events #################*/

    public class TcpPortScannFinishedEventArgs : EventArgs
    {
        private List<OpenPorts> _tcpResults = new List<OpenPorts>();
        public List<OpenPorts> PortScanResults { get { return _tcpResults; } }
        public TcpPortScannFinishedEventArgs(List<OpenPorts> PortScanResults)
        {
            _tcpResults = PortScanResults;
        }
    }


    public class TcpPortScanTaskFinishedEventArgs : EventArgs
    {
        private DataRow _row = new ScanResults().ResultTable.NewRow();
        public DataRow PingResultsRow { get { return _row; } }
        public TcpPortScanTaskFinishedEventArgs(DataRow Row)
        {
            _row = Row;
        }
    }
}
