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
        
        //current, responsed, total
        public event Action<int, int, int> ProgressUpdated;
        public event EventHandler<ScanTask_Finished_EventArgs>? Ping_Task_Finished;
        public event EventHandler<Method_Finished_EventArgs>? PingFinished;
        private int current = 0;
        private int responsed = 0;
        private int total = 0;

        /// <summary>
        /// to get the Ping result call the Propertie PingResults
        /// </summary>
        /// <param name="IPs"></param>
        /// <param name="DNS_Server_IP"></param>
        //public async Task PingIPsAsync(List<IPToScan> IPsToRefresh, bool ShowUnused = false)
        //{
        //    var tasks = new List<Task>();

        //    total = IPsToRefresh.Count;

        //    await Parallel.ForEach(IPsToRefresh, ip =>
        //    {
        //        ++current;
        //        ProgressUpdated?.Invoke(current, responsed, total);

        //        var task = PingTask(ip, ip.TimeOut, ShowUnused);
        //        if (task != null) tasks.Add(task);
        //    });

        //    await Task.WhenAll(tasks.Where(t => t != null));
        //    if (PingFinished != null)
        //    {
        //        PingFinished(this, new Method_Finished_EventArgs());
        //    }
        //}

        public async Task PingIPsAsync(List<IPToScan> IPsToRefresh, bool ShowUnused = false)
        {
            current = 0;
            responsed = 0;
            total = IPsToRefresh.Count;

            await Parallel.ForEachAsync(IPsToRefresh, async (ip, token) =>
            {
                int currentValue = Interlocked.Increment(ref current);
                ProgressUpdated?.Invoke(current, responsed, total); 

                await PingTask(ip, ip.TimeOut, ShowUnused);
            });

            PingFinished?.Invoke(this, new Method_Finished_EventArgs());
        }


        private async Task PingTask(IPToScan ipToScan, int TimeOut, bool ShowUnused)
        {
            if (!new SupportMethods().Is_Valid_IP(ipToScan.IPorHostname)) return;            

            bool sendResult = false;

            try
            {
                string data = "nothing less than the world domination pinky, nothing less!";
                byte[] buffer = Encoding.ASCII.GetBytes(data);

                PingOptions options = new PingOptions(200, true);

                Ping ping = new Ping();
                

                
                PingReply reply = null;
                for (int i = 0; i < 5; i++)
                {
                    reply = await ping.SendPingAsync(ipToScan.IPorHostname, TimeOut, buffer, options);
                    if (reply.Status == IPStatus.Success) break;
                }
                    bool PingStatus = false;
                //string IP = string.Empty;
                string ResponseTime = string.Empty;

                if (reply.Status == IPStatus.Success)
                {
                    PingStatus = true;
                    //IP = reply.Address.ToString();
                    ResponseTime = reply.RoundtripTime.ToString();
                    sendResult = true;
                }
                else if (ShowUnused && reply.Status != IPStatus.Success)
                {
                    PingStatus = false;
                    sendResult = true;
                    //IP = ipToScan.IP;
                    //ResponseTime = string.Empty;
                }

                if(!sendResult) { return; }

                if (Ping_Task_Finished != null)
                {
                    //ipToScan.IP = IP;
                    ipToScan.ResponseTime = ResponseTime;
                    ipToScan.PingStatus = PingStatus;

                    ipToScan.UsedScanMethod = ScanMethod.Ping;

                    ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs();
                    scanTask_Finished.ipToScan = ipToScan;

                    ++responsed;
                    ProgressUpdated?.Invoke(current, responsed, total);

                    Ping_Task_Finished(this, scanTask_Finished);
                }
            }
            catch (PingException ex)
            {
                throw;
            }
        }


        public async Task<PingReply> PingIPAsync(IPToScan ipToScan, int TimeOut)
        {
            PingReply reply;
            try
            {
                string data = "nothing less than the world domination pinky, nothing less!";
                byte[] buffer = Encoding.ASCII.GetBytes(data);

                PingOptions options = new PingOptions(200, true);

                Ping ping = new Ping();
                reply = await ping.SendPingAsync(ipToScan.IPorHostname, TimeOut, buffer, options);

                return reply;
            }
            catch (PingException ex)
            {
                throw;
            }
        }
    }
}
