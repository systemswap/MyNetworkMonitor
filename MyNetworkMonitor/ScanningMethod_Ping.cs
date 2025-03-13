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
        public ScanningMethods_Ping() { }

        public event Action<int, int, int, ScanStatus> ProgressUpdated;
        public event EventHandler<ScanTask_Finished_EventArgs>? Ping_Task_Finished;
        public event EventHandler<Method_Finished_EventArgs>? PingFinished;

       
        private readonly PingOptions pingOptions = new PingOptions(200, true);
        private readonly byte[] buffer = Encoding.ASCII.GetBytes("nothing less than the world domination pinky, nothing less!");


        private int current = 0;
        private int responded = 0;
        private int total = 0;

        private CancellationTokenSource _cts = new CancellationTokenSource(); // 🔹 Ermöglicht das Abbrechen

        //int currentValue = Interlocked.Increment(ref current);
        //ProgressUpdated?.Invoke(currentValue, responded, total, ScanStatus.running);

        //int respondedValue = Interlocked.Increment(ref responded);
        //ProgressUpdated?.Invoke(current, respondedValue, total, ScanStatus.running);

        //ProgressUpdated?.Invoke(current, responded, total, ScanStatus.finished);

        public void StopScan()
        {
            if (_cts != null && !_cts.IsCancellationRequested)
            {
                _cts.Cancel(); // 🔹 Scan abbrechen
                _cts.Dispose();
                _cts = new CancellationTokenSource();
            }

            // 🔹 Zähler zurücksetzen
            current = 0;
            responded = 0;
            total = 0;

            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.stopped); // 🔹 UI auf 0 setzen
        }

        private void StartNewScan()
        {
            if (_cts != null)
            {
                if (!_cts.IsCancellationRequested)
                {
                    _cts.Cancel();
                }
                _cts.Dispose();
            }
            _cts = new CancellationTokenSource();

            // 🔹 Zähler zurücksetzen
            current = 0;
            responded = 0;
            total = 0;
        }





        public async Task PingIPsAsync(List<IPToScan> IPsToRefresh, bool ShowUnused = false)
        {
            StartNewScan(); // `_cts` wird hier zurückgesetzt

            current = 0;
            responded = 0;
            total = IPsToRefresh.Count;

            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.running);

            try
            {
                var tasks = new List<Task>();
                var ipListCopy = IPsToRefresh.ToList(); // 🔹 Erstelle eine Kopie der Liste

                foreach (var ip in ipListCopy.Where(ip => !string.IsNullOrEmpty(ip.IPorHostname)))
                {
                    if (_cts.Token.IsCancellationRequested) break;

                    tasks.Add(PingTask(ip, ip.TimeOut, ShowUnused));

                    try
                    {
                        await Task.Delay(20, _cts.Token);
                    }
                    catch (TaskCanceledException)
                    {
                        break;
                    }
                }

                await Task.WhenAll(tasks);
            }
            catch (OperationCanceledException)
            {
                Debug.WriteLine("Ping-Scan wurde abgebrochen!");
            }
            finally
            {
                ProgressUpdated?.Invoke(current, responded, total, ScanStatus.finished);
                PingFinished?.Invoke(this, new Method_Finished_EventArgs());
            }
        }



        private async Task PingTask(IPToScan ipToScan, int timeout, bool showUnused)
        {
            if (_cts.Token.IsCancellationRequested) return; // 🔹 Falls Scan abgebrochen, sofort raus

            if (!new SupportMethods().Is_Valid_IP(ipToScan.IPorHostname)) return;


            try
            {
                using Ping ping = new Ping();
                PingReply reply = null;
                bool success = false;

                // Fortschritt aktualisieren → UI-Thread nutzen
                int currentCount = Interlocked.Increment(ref current);
                ProgressUpdated?.Invoke(currentCount, responded, total, ScanStatus.running);

                // Bis zu 3 Versuche mit steigenden Timeouts
                for (int attempt = 1; attempt <= 3; attempt++)
                {
                    _cts.Token.ThrowIfCancellationRequested(); // 🔹 Falls gestoppt, sofort beenden

                    reply = await ping.SendPingAsync(ipToScan.IPorHostname, timeout * attempt, buffer, pingOptions);

                    if (reply != null && reply.Status == IPStatus.Success)
                    {
                        success = true;
                        break; // Erfolgreich, keine weiteren Versuche nötig
                    }

                    if (attempt < 3)
                    {
                        try
                        {
                            await Task.Delay(100, _cts.Token); // 🔹 Falls gestoppt, bricht es sofort ab
                        }
                        catch (TaskCanceledException)
                        {
                            return; // 🔹 Falls Scan gestoppt, sofort raus
                        }
                    }
                }

                if (!success && !showUnused) return;

                ipToScan.ResponseTime = success ? reply?.RoundtripTime.ToString() : string.Empty;
                ipToScan.PingStatus = success;
                ipToScan.UsedScanMethod = ScanMethod.Ping;

                // Fortschritt für erfolgreiche Pings aktualisieren → UI-Thread nutzen
                int responsedCount = Interlocked.Increment(ref responded);
                ProgressUpdated?.Invoke(currentCount, responsedCount, total, ScanStatus.running);

                // Event auslösen
                Ping_Task_Finished?.Invoke(this, new ScanTask_Finished_EventArgs { ipToScan = ipToScan });
            }
            catch (OperationCanceledException)
            {
                Debug.WriteLine($"Ping für {ipToScan.IPorHostname} wurde abgebrochen.");
            }
            catch (Exception ex) when (ex is PingException || ex is SocketException)
            {
                Console.WriteLine($"Ping Fehler für {ipToScan.IPorHostname}: {ex.Message}");
            }
        }
    }
}
