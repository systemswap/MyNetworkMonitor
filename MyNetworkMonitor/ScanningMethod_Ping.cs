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
        public async Task PingIPsAsync(List<IPToRefresh> IPsToRefresh, bool ShowUnused = true)
        {
            var tasks = new List<Task>();

            Parallel.ForEach(IPsToRefresh, ip =>
            {                
                var task = PingTask(ip, ip.TimeOut, ShowUnused);
                if (task != null) tasks.Add(task);
            });

            await Task.WhenAll(tasks);
            if (PingFinished != null)
            {
                PingFinished(this, new PingScanFinishedEventArgs(true));
            }
        }

        private async Task PingTask(IPToRefresh ip, int TimeOut, bool ShowUnused)
        {
            if (!new SupportMethods().Is_Valid_IP(ip.IP)) return;

            try
            {                
                string data = "nothing less than the world domination pinky, nothing less!";
                byte[] buffer = Encoding.ASCII.GetBytes(data);

                PingOptions options = new PingOptions(200, true);

                Ping ping = new Ping();
                PingReply reply = await ping.SendPingAsync(ip.IP, TimeOut, buffer, options);

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
                    IP = ip.IP;
                    ResponseTime = string.Empty;
                }

                if (Ping_Task_Finished != null)
                {
                    Ping_Task_Finished(this, new Ping_Task_Finished_EventArgs(ip.IPGroupDescription, ip.DeviceDescription, IP, PingStatus, ResponseTime));
                }
            }
            catch (PingException ex)
            {
                throw;
            }
        }


        public async Task<PingReply> PingIPAsync(IPToRefresh ip, int TimeOut)
        {
            PingReply reply;
            try
            {
                string data = "nothing less than the world domination pinky, nothing less!";
                byte[] buffer = Encoding.ASCII.GetBytes(data);

                PingOptions options = new PingOptions(200, true);

                Ping ping = new Ping();
                reply = await ping.SendPingAsync(ip.IP, TimeOut, buffer, options);

                return reply;               
            }
            catch (PingException ex)
            {
                throw;
            }
        }
    }


    /* ############# Events #################*/

    public class Ping_Task_Finished_EventArgs : EventArgs
    {
        public Ping_Task_Finished_EventArgs(string IPGroupDescription, string DeviceDescription, string IP, bool PingStatus, string ResponseTime)
        {
            _IPGroupDescription = IPGroupDescription;
            _DeviceDescription = DeviceDescription;
            _IP = IP;
            _PingStatus = PingStatus;            
            _ResponseTime = ResponseTime;
        }

        private string _IPGroupDescription = string.Empty;
        public string IPGroupDescription { get { return _IPGroupDescription; } }

        private string _DeviceDescription = string.Empty;
        public string DeviceDescription { get { return _DeviceDescription; } }

        private string _IP = string.Empty;
        public string IP { get { return _IP; } }

        private bool _PingStatus = false;
        public bool PingStatus { get { return _PingStatus; } }        

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
