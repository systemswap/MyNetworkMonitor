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
        //    public ScanningMethods_Ping()
        //    {

        //    }

        //    //current, responsed, total
        //    public event Action<int, int, int> ProgressUpdated;
        //    public event EventHandler<ScanTask_Finished_EventArgs>? Ping_Task_Finished;
        //    public event EventHandler<Method_Finished_EventArgs>? PingFinished;
        //    private int current = 0;
        //    private int responsed = 0;
        //    private int total = 0;


        //    public async Task PingIPsAsync(List<IPToScan> IPsToRefresh, bool ShowUnused = false)
        //    {
        //        current = 0;
        //        responsed = 0;
        //        total = IPsToRefresh.Count;

        //        await Parallel.ForEachAsync(IPsToRefresh, async (ip, token) =>
        //        {
        //            int currentValue = Interlocked.Increment(ref current);
        //            ProgressUpdated?.Invoke(current, responsed, total);

        //            await PingTask(ip, ip.TimeOut, ShowUnused);
        //        });

        //        PingFinished?.Invoke(this, new Method_Finished_EventArgs());
        //    }


        //    private async Task PingTask(IPToScan ipToScan, int TimeOut, bool ShowUnused)
        //    {
        //        if (!new SupportMethods().Is_Valid_IP(ipToScan.IPorHostname)) return;

        //        bool sendResult = false;

        //        try
        //        {
        //            string data = "nothing less than the world domination pinky, nothing less!";
        //            byte[] buffer = Encoding.ASCII.GetBytes(data);

        //            PingOptions options = new PingOptions(200, true);

        //            Ping ping = new Ping();



        //            PingReply reply = null;
        //            for (int i = 0; i < 5; i++)
        //            {
        //                reply = await ping.SendPingAsync(ipToScan.IPorHostname, TimeOut, buffer, options);
        //                if (reply.Status == IPStatus.Success) break;
        //            }
        //            bool PingStatus = false;
        //            //string IP = string.Empty;
        //            string ResponseTime = string.Empty;

        //            if (reply.Status == IPStatus.Success)
        //            {
        //                PingStatus = true;
        //                //IP = reply.Address.ToString();
        //                ResponseTime = reply.RoundtripTime.ToString();
        //                sendResult = true;
        //            }
        //            else if (ShowUnused && reply.Status != IPStatus.Success)
        //            {
        //                PingStatus = false;
        //                sendResult = true;
        //                //IP = ipToScan.IP;
        //                //ResponseTime = string.Empty;
        //            }

        //            if (!sendResult) { return; }

        //            if (Ping_Task_Finished != null)
        //            {
        //                //ipToScan.IP = IP;
        //                ipToScan.ResponseTime = ResponseTime;
        //                ipToScan.PingStatus = PingStatus;

        //                ipToScan.UsedScanMethod = ScanMethod.Ping;

        //                ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs();
        //                scanTask_Finished.ipToScan = ipToScan;

        //                ++responsed;
        //                ProgressUpdated?.Invoke(current, responsed, total);

        //                Ping_Task_Finished(this, scanTask_Finished);
        //            }
        //        }
        //        catch (PingException ex)
        //        {
        //            throw;
        //        }
        //    }


        //    public async Task<PingReply> PingIPAsync(IPToScan ipToScan, int TimeOut)
        //    {
        //        PingReply reply;
        //        try
        //        {
        //            string data = "nothing less than the world domination pinky, nothing less!";
        //            byte[] buffer = Encoding.ASCII.GetBytes(data);

        //            PingOptions options = new PingOptions(200, true);

        //            Ping ping = new Ping();
        //            reply = await ping.SendPingAsync(ipToScan.IPorHostname, TimeOut, buffer, options);

        //            return reply;
        //        }
        //        catch (PingException ex)
        //        {
        //            throw;
        //        }
        //    }
        //}



        //    public ScanningMethods_Ping() { }

        //    public event Action<int, int, int> ProgressUpdated;
        //    public event EventHandler<ScanTask_Finished_EventArgs>? Ping_Task_Finished;
        //    public event EventHandler<Method_Finished_EventArgs>? PingFinished;

        //    private int current = 0;
        //    private int responsed = 0;
        //    private int total = 0;
        //    private readonly PingOptions pingOptions = new PingOptions(200, true);
        //    private readonly byte[] buffer = Encoding.ASCII.GetBytes("nothing less than the world domination pinky, nothing less!");

        //    public async Task PingIPsAsync(List<IPToScan> IPsToRefresh, bool ShowUnused = false)
        //    {
        //        current = 0;
        //        responsed = 0;
        //        total = IPsToRefresh.Count;

        //        var tasks = IPsToRefresh
        //            .Where(ip => !string.IsNullOrEmpty(ip.IPorHostname))
        //            .Select(ip => PingTask(ip, ip.TimeOut, ShowUnused))
        //            .ToList();

        //        await Task.WhenAll(tasks);

        //        PingFinished?.Invoke(this, new Method_Finished_EventArgs());
        //    }

        //    private async Task PingTask(IPToScan ipToScan, int timeout, bool showUnused)
        //    {
        //        if (!new SupportMethods().Is_Valid_IP(ipToScan.IPorHostname)) return;

        //        try
        //        {
        //            using Ping ping = new Ping();
        //            PingReply reply = await ping.SendPingAsync(ipToScan.IPorHostname, timeout, buffer, pingOptions);

        //            bool success = reply.Status == IPStatus.Success;
        //            bool sendResult = success || showUnused;

        //            if (!sendResult) return;

        //            ipToScan.ResponseTime = success ? reply.RoundtripTime.ToString() : string.Empty;
        //            ipToScan.PingStatus = success;
        //            ipToScan.UsedScanMethod = ScanMethod.Ping;

        //            Interlocked.Increment(ref responsed);
        //            ProgressUpdated?.Invoke(Interlocked.Increment(ref current), responsed, total);

        //            Ping_Task_Finished?.Invoke(this, new ScanTask_Finished_EventArgs { ipToScan = ipToScan });
        //        }
        //        catch (Exception ex) when (ex is PingException || ex is SocketException)
        //        {
        //            Console.WriteLine($"Ping Fehler für {ipToScan.IPorHostname}: {ex.Message}");
        //        }
        //    }

        //    public async Task<PingReply> PingIPAsync(IPToScan ipToScan, int timeout)
        //    {
        //        try
        //        {
        //            using Ping ping = new Ping();
        //            return await ping.SendPingAsync(ipToScan.IPorHostname, timeout, buffer, pingOptions);
        //        }
        //        catch (Exception ex) when (ex is PingException || ex is SocketException)
        //        {
        //            Console.WriteLine($"Ping Einzelanfrage Fehler für {ipToScan.IPorHostname}: {ex.Message}");
        //            return null;
        //        }
        //    }
        //}



        public ScanningMethods_Ping() { }

        public event Action<int, int, int> ProgressUpdated;
        public event EventHandler<ScanTask_Finished_EventArgs>? Ping_Task_Finished;
        public event EventHandler<Method_Finished_EventArgs>? PingFinished;

        private int current = 0;
        private int responsed = 0;
        private int total = 0;
        private readonly PingOptions pingOptions = new PingOptions(200, true);
        private readonly byte[] buffer = Encoding.ASCII.GetBytes("nothing less than the world domination pinky, nothing less!");

        private readonly SynchronizationContext syncContext = SynchronizationContext.Current;

        public async Task PingIPsAsync(List<IPToScan> IPsToRefresh, bool ShowUnused = false)
        {
            current = 0;
            responsed = 0;
            total = IPsToRefresh.Count;

            //await Task.Run(async () =>
            //{
            //    var tasks = IPsToRefresh
            //        .Where(ip => !string.IsNullOrEmpty(ip.IPorHostname))
            //        .Select(ip => PingTask(ip, ip.TimeOut, ShowUnused))
            //        .ToList();

            //    await Task.WhenAll(tasks);
            //});

            await Task.Run(async () =>
            {
                var tasks = new List<Task>();

                foreach (var ip in IPsToRefresh.Where(ip => !string.IsNullOrEmpty(ip.IPorHostname)))
                {
                    tasks.Add(PingTask(ip, ip.TimeOut, ShowUnused));
                    await Task.Delay(20); // 20 ms Pause zwischen jedem Ping-Start
                }

                await Task.WhenAll(tasks);
            });


            PingFinished?.Invoke(this, new Method_Finished_EventArgs());
        }


        private async Task PingTask(IPToScan ipToScan, int timeout, bool showUnused)
        {
            if (!new SupportMethods().Is_Valid_IP(ipToScan.IPorHostname)) return;

            try
            {
                using Ping ping = new Ping();
                PingReply reply = null;
                bool success = false;

                // Fortschritt aktualisieren → UI-Thread nutzen
                int currentCount = Interlocked.Increment(ref current);
                syncContext.Post(_ => ProgressUpdated?.Invoke(currentCount, responsed, total), null);

                // Bis zu 3 Versuche mit steigenden Timeouts
                for (int attempt = 1; attempt <= 3; attempt++)
                {
                    reply = await ping.SendPingAsync(ipToScan.IPorHostname, timeout * attempt, buffer, pingOptions);

                    if (reply != null && reply.Status == IPStatus.Success)
                    {
                        success = true;
                        break; // Erfolgreich, keine weiteren Versuche nötig
                    }

                    if (attempt < 3) await Task.Delay(100);
                }

                if (!success && !showUnused) return;

                ipToScan.ResponseTime = success ? reply?.RoundtripTime.ToString() : string.Empty;
                ipToScan.PingStatus = success;
                ipToScan.UsedScanMethod = ScanMethod.Ping;

                // Fortschritt für erfolgreiche Pings aktualisieren → UI-Thread nutzen
                int responsedCount = Interlocked.Increment(ref responsed);
                syncContext.Post(_ => ProgressUpdated?.Invoke(currentCount, responsedCount, total), null);

                // Event auslösen
                syncContext.Post(_ => Ping_Task_Finished?.Invoke(this, new ScanTask_Finished_EventArgs { ipToScan = ipToScan }), null);
            }
            catch (Exception ex) when (ex is PingException || ex is SocketException)
            {
                Console.WriteLine($"Ping Fehler für {ipToScan.IPorHostname}: {ex.Message}");
            }
        }

        //public async Task<PingReply> PingIPAsync(IPToScan ipToScan, int timeout)
        //{
        //    try
        //    {
        //        using Ping ping = new Ping();
        //        PingReply reply = null;

        //        for (int attempt = 1; attempt <= 3; attempt++)
        //        {
        //            reply = await ping.SendPingAsync(ipToScan.IPorHostname, timeout * attempt, buffer, pingOptions);

        //            if (reply.Status == IPStatus.Success)
        //            {
        //                return reply;
        //            }

        //            await Task.Delay(100);
        //        }

        //        return reply;
        //    }
        //    catch (Exception ex) when (ex is PingException || ex is SocketException)
        //    {
        //        Console.WriteLine($"Ping Einzelanfrage Fehler für {ipToScan.IPorHostname}: {ex.Message}");
        //        return null;
        //    }
        //}
    }
}
