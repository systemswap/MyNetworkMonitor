using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    public class ScanningMethods_Ping
    {
        public ScanningMethods_Ping() { }

        public event Action<int, int, int, ScanStatus> ProgressUpdated;
        public event EventHandler<ScanTask_Finished_EventArgs>? Ping_Task_Finished;
        public event Action<ScanStatus>? PingFinished;

       
        private readonly PingOptions pingOptions = new PingOptions(200, true);
        private readonly byte[] buffer = Encoding.ASCII.GetBytes("nothing less than the world domination pinky, nothing less!");


        private int current = 0;
        private int responded = 0;
        private int total = 0;

        private CancellationTokenSource _cts = new CancellationTokenSource(); // 🔹 Ermöglicht das Abbrechen

        //int currentValue = Interlocked.Increment(ref current);
        //Task.Run(() => ProgressUpdated?.Invoke(currentValue, responded, total, ScanStatus.running));

        //int respondedValue = Interlocked.Increment(ref responded);
        //Task.Run(() => ProgressUpdated?.Invoke(current, respondedValue, total, ScanStatus.running));

        //Task.Run(() => ProgressUpdated?.Invoke(current, responded, total, ScanStatus.finished));

        public void StopScan()
        {
            if (_cts != null && !_cts.IsCancellationRequested)
            {
                _cts.Cancel(); // 🔹 Scan abbrechen
                // Hier NICHT aufraeumen und ersetzen: die Schleifen lesen _cts ueber
                // das Feld. Ein frisches CTS an dieser Stelle meldet ihnen wieder
                // "nicht abgebrochen", und der Lauf geht weiter, statt zu enden.
                // Das Zuruecksetzen erledigt StartNewScan beim naechsten Lauf.
            }
           
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
                //ProgressUpdated?.Invoke(current, responded, total, ScanStatus.finished);
                PingFinished?.Invoke(ScanStatus.finished);
            }
        }



        private async Task PingTask(IPToScan ipToScan, int timeout, bool showUnused)
        {
            if (_cts.Token.IsCancellationRequested) return; // 🔹 Falls Scan abgebrochen, sofort raus

            if (!new SupportMethods().Is_Valid_IP(ipToScan.IPorHostname)) 
            { 
                return; 
            }


            // Gezaehlt wird die abgeschickte Anfrage, nicht die fertige Probe.
            // Die Anzeige nennt drei Zahlen - gesendet, geantwortet, gesamt -,
            // und darin ist "254 / 160 / 254" eine sinnvolle Aussage: alles
            // raus, 160 Antworten da, auf den Rest wird noch gewartet. Nur mit
            // zwei Zahlen waere daraus ein irrefuehrendes "fertig" geworden.
            int sentCount = Interlocked.Increment(ref current);
            ProgressUpdated?.Invoke(sentCount, responded, total, ScanStatus.running);

            try
            {
                using Ping ping = new Ping();
                PingReply reply = null;
                bool success = false;

                // Bis zu 3 Versuche mit steigenden Timeouts
                for (int attempt = 1; attempt <= 3; attempt++)
                {
                    _cts.Token.ThrowIfCancellationRequested(); // 🔹 Falls gestoppt, sofort beenden

                    // Mit Token: ohne ihn laeuft die angefangene Probe bis zu
                    // ihrem Timeout weiter, und beim dritten Versuch ist das
                    // das Dreifache. Genau daran hing, dass "Stop" erst nach
                    // vielen Sekunden wirkte.
                    reply = await ping.SendPingAsync(
                        ipToScan.IPorHostname,
                        TimeSpan.FromMilliseconds(timeout * attempt),
                        buffer,
                        pingOptions,
                        _cts.Token);

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

                // Die Rest-TTL der Antwort. Sie liegt ohnehin im Paket - sie
                // nicht zu lesen hiesse, eine Auskunft ueber das Betriebssystem
                // wegzuwerfen, die nichts kostet. Auswertung in TtlFingerprint.
                if (success) ipToScan.TTL = reply?.Options?.Ttl ?? 0;

                // Nur eine echte Antwort zaehlt als Antwort. Mit "show unused"
                // laeuft auch ein stummes Ziel bis hierher - es mitzuzaehlen
                // machte aus der mittleren Zahl eine zweite Kopie der ersten
                // und damit die ganze Anzeige wertlos.
                if (success)
                {
                    int responsedCount = Interlocked.Increment(ref responded);
                    ProgressUpdated?.Invoke(current, responsedCount, total, ScanStatus.running);
                }

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
