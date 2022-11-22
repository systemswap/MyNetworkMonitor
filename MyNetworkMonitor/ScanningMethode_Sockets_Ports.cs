using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

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

        private CancellationToken _clt = new CancellationToken(false);
        public CancellationToken CancelPortScan
        {
            get { return _clt; }
            set { _clt = value; }
        }


        public async void ScanPorts(List<string> IPs, List<int> Ports)
        {
            var tasks = new List<Task>();

            foreach (var ip in IPs)
            {
                var task = ScanPorts_Task(ip, Ports);
                tasks.Add(task);
            }            

            await Task.WhenAll(tasks);           
        }

        public event EventHandler<PortScannFinishedEventArgs>? CustomEvent_PortScanFinished;
        public event EventHandler<PortScanTaskFinishedEventArgs>? CustomEvent_PingProgress;

        public async Task ScanPorts_Task(string IP, List<int> Ports)
        {
            try
            {
                TcpClient tcpclnt = new TcpClient();

                OpenPorts ports = new OpenPorts();
                ports.IP = IP;

                foreach (int port in Ports)
                {
                    if (_clt.IsCancellationRequested) return;

                    await tcpclnt.ConnectAsync(IP, port);

                    if (tcpclnt.Connected)
                    {
                        ports.openPorts.Add(port);
                        tcpclnt.Close();
                    }
                }
            }
            catch (Exception e)
            {
                Debug.WriteLine("Error..... " + e.StackTrace);
            }


        }
    }

    public class OpenPorts
    {
        public string IP = string.Empty;
        public List<int> openPorts = new List<int>();
    }


    /* ############# Events #################*/

    public class PortScannFinishedEventArgs : EventArgs
    {
        private DataTable _dt = new DataTable();
        public DataTable PortScanResults { get { return _dt; } }
        public PortScannFinishedEventArgs(DataTable PortScanResults)
        {
            _dt = PortScanResults;
        }
    }


    public class PortScanTaskFinishedEventArgs : EventArgs
    {
        private DataRow _row = new ScanResults().ResultTable.NewRow();
        public DataRow PingResultsRow { get { return _row; } }
        public PortScanTaskFinishedEventArgs(DataRow Row)
        {
            _row = Row;
        }
    }
}
