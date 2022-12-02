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


        public async void ScanTCPPorts(List<string> IPs, TimeSpan TimeOut)
        {
            var tasks = new List<Task>();
           
            foreach(string ip in IPs)
            {
                {                   
                    var task = ScanTCPPorts_Task(ip, new PortCollection().TCPPorts, TimeOut);
                    tasks.Add(task);
                }
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

            if (TcpPortScan_Task_Finished != null)
            {
                if (new SupportMethods().Is_Valid_IP(openPorts.IP)) 
                    TcpPortScan_Task_Finished(this, new TcpPortScan_Task_FinishedEventArgs(openPorts));
            }
        }


        private async Task<int> ScanTCP_Port(string IP, int port, TimeSpan TimeOut)
        {
            try
            {
                if (!new SupportMethods().Is_Valid_IP(IP)) return -1;

                using (TcpClient tcpclnt = new TcpClient())
                {
                    await Task.Run(() => tcpclnt.ConnectAsync(IP, port).Wait(TimeOut.Milliseconds, _clt));

                    if (tcpclnt.Connected)
                    {
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
    }
}
