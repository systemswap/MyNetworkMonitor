using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace MyNetworkMonitor
{
    internal class ScanningMethods_Ping
    {
        public ScanningMethods_Ping()
        {

        }

        public event EventHandler<PingScanFinishedEventArgs>? PingFinished;
        public event EventHandler<Ping_Task_Finished_EventArgs>? Ping_Task_Finished;


        /// <summary>
        /// to get the Ping result call the Propertie PingResults
        /// </summary>
        /// <param name="IPs"></param>
        /// <param name="DNS_Server_IP"></param>
        public async Task PingIPsAsync(List<IPsToRefresh> IPsToRefresh, bool ShowUnused = true)
        {
            var tasks = new List<Task>();

            Parallel.ForEach(IPsToRefresh, ip =>
            {                
                var task = PingTask(ip.IP, ip.TimeOut, ShowUnused);
                if (task != null) tasks.Add(task);
            });

            await Task.WhenAll(tasks);
            if (PingFinished != null)
            {
                PingFinished(this, new PingScanFinishedEventArgs(true));
            }
        }

        private async Task PingTask(string ip, int TimeOut, bool ShowUnused)
        {
            if (!new SupportMethods().Is_Valid_IP(ip)) return;

            try
            {
                
                string data = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
                byte[] buffer = Encoding.ASCII.GetBytes(data);

                PingOptions options = new PingOptions(200, true);

                Ping ping = new Ping();
                PingReply reply = await ping.SendPingAsync(ip, TimeOut, buffer, options);

                bool PingStatus = false;
                string IP = string.Empty;
                string ResponseTime = string.Empty;

                if (reply.Status == IPStatus.Success)
                {
                    PingStatus = true;
                    IP = reply.Address.ToString();
                    ResponseTime = reply.RoundtripTime.ToString();
                }
                else if (ShowUnused && reply.Status != IPStatus.Success)
                {
                    PingStatus = false;
                    IP = ip;
                    ResponseTime = string.Empty;
                }

                if (Ping_Task_Finished != null)
                {
                    Ping_Task_Finished(this, new Ping_Task_Finished_EventArgs(PingStatus, IP, ResponseTime));
                }
            }
            catch (Exception)
            {
                //throw;
            }

        }
    }


    /* ############# Events #################*/

    public class Ping_Task_Finished_EventArgs : EventArgs
    {
        public Ping_Task_Finished_EventArgs(bool PingStatus, string IP, string ResponseTime)
        {
            _PingStatus= PingStatus;
            _IP = IP;
            _ResponseTime = ResponseTime;
        }

        private bool _PingStatus = false;
        public bool PingStatus { get { return _PingStatus; } }

        private string _IP = string.Empty;
        public string IP { get { return _IP; } }

        private string _ResponseTime = string.Empty;
        public string ResponseTime { get { return _ResponseTime; } }
    }


    public class PingScanFinishedEventArgs : EventArgs
    {
        public PingScanFinishedEventArgs(bool Finished)
        {
            _finished = Finished;
        }

        private bool _finished = false;
        public bool PingResults { get { return _finished; } }        
    }
}
