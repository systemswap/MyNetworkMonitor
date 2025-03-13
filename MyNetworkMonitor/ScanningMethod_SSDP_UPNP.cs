using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.Threading;
using System.Windows;
using System.Net.NetworkInformation;

namespace MyNetworkMonitor
{
    internal class ScanningMethod_SSDP_UPNP
    {

       

        public ScanningMethod_SSDP_UPNP()
        {

        }

        AsyncTimer timer = new AsyncTimer();
        public event Action<int, int, int, ScanStatus> ProgressUpdated;
        public event EventHandler<ScanTask_Finished_EventArgs>? SSDP_foundNewDevice;
        public event EventHandler<Method_Finished_EventArgs>? SSDP_Scan_Finished;


        

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
                _cts.Dispose();
                _cts = new CancellationTokenSource();
            }

            Task.Run(() => ProgressUpdated?.Invoke(current, responded, total, ScanStatus.stopped)); // 🔹 UI auf 0 setzen
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




        public class SSDPDeviceInfo
        {
            public string IP { get; set; } = string.Empty;  // IP-Adresse des Geräts
            public string Server { get; set; } = string.Empty;
            public string Location { get; set; } = string.Empty;
            public string FriendlyName { get; set; } = string.Empty;
            public string Manufacturer { get; set; } = string.Empty;
            public string ModelDescription { get; set; } = string.Empty;
            public string ModelName { get; set; } = string.Empty;
            public string ModelNumber { get; set; } = string.Empty;
            public string ModelType { get; set; } = string.Empty;
            public string URLBase { get; set; } = string.Empty;
            public string PresentationURL { get; set; } = string.Empty;

            public override string ToString()
            {
                return $"📡 SSDP-Gerät gefunden:\n" +
                       $"IP: {IP}\nServer: {Server}\nLocation: {Location}\n" +
                       $"FriendlyName: {FriendlyName}\nManufacturer: {Manufacturer}\n" +
                       $"ModelDescription: {ModelDescription}\nModelName: {ModelName}\n" +
                       $"ModelNumber: {ModelNumber}\nModelType: {ModelType}\n" +
                       $"URLBase: {URLBase}\nPresentationURL: {PresentationURL}\n";
            }
        }



        private readonly string SSDP_IP = "239.255.255.250"; // SSDP Multicast-Adresse
        private readonly int SSDP_PORT = 1900;               // Standard-SSDP-Port
    
        
        /// <summary>
        /// Führt einen SSDP-Scan durch, empfängt Antworten und extrahiert Geräteinformationen.
        /// </summary>
        /// <param name="scanDuration">in milliseconds</param>
        public async void Scan_for_SSDP_devices_async(int scanDuration = 5000)
        {
            StartNewScan();

            current = 0;
            responded = 0;
            total = 0;

            List<SSDPDeviceInfo> devices = new List<SSDPDeviceInfo>();

            using (UdpClient udpClient = new UdpClient())
            {
                udpClient.EnableBroadcast = true;
                udpClient.MulticastLoopback = true;

                IPEndPoint multicastEP = new IPEndPoint(IPAddress.Parse(SSDP_IP), SSDP_PORT);

                // SSDP-M-SEARCH Anfrage erstellen
                string ssdpRequest =
                    "M-SEARCH * HTTP/1.1\r\n" +
                    $"HOST: {SSDP_IP}:{SSDP_PORT}\r\n" +
                    "MAN: \"ssdp:discover\"\r\n" +
                    "MX: 3\r\n" +  // Maximale Wartezeit für Antworten
                    "ST: ssdp:all\r\n" +  // Suche nach allen UPnP-Geräten
                    "\r\n";

                byte[] requestBytes = Encoding.UTF8.GetBytes(ssdpRequest);
                await udpClient.SendAsync(requestBytes, requestBytes.Length, multicastEP);

                //Console.WriteLine("📡 SSDP-Scan gesendet... Warte auf Antworten...");

                // Antworten empfangen
                //var endpoint = new IPEndPoint(IPAddress.Any, SSDP_PORT);
                var endpoint = new IPEndPoint(SupportMethods.SelectedNetworkInterfaceInfos.IPv4, SSDP_PORT);
                udpClient.Client.ReceiveTimeout = scanDuration; // Timeout für Antworten (5 Sekunden)

                try
                {
                    // Starte den Timer und warte nicht auf seine Beendigung
                    var timerTask = timer.StartAsync(scanDuration, 1000, async () => { });

                    while (timer.IsRunning)
                    {
                        if (_cts.Token.IsCancellationRequested) break; // 🔹 Abbruchprüfung

                        var receiveTask = udpClient.ReceiveAsync();
                        var completedTask = await Task.WhenAny(receiveTask, Task.Delay(10, _cts.Token));

                        if (_cts.Token.IsCancellationRequested) break; // 🔹 Falls während `Task.WhenAny()` ein Abbruch passiert

                        if (completedTask == receiveTask && !_cts.Token.IsCancellationRequested) // Antwort erhalten
                        {
                            UdpReceiveResult result = receiveTask.Result;
                            string response = Encoding.UTF8.GetString(result.Buffer);


                            var device = await ParseSSDPResponseAsync(response, result.RemoteEndPoint.Address.ToString());

                            if (device != null && !devices.Any(d => d.IP == device.IP))
                            {
                                devices.Add(device);

                                IPToScan ipToScan = new IPToScan
                                {
                                    SSDPStatus = true,
                                    IPorHostname = device.IP,
                                    IPGroupDescription = "not specified",
                                    DeviceDescription = "not specified",
                                    UsedScanMethod = ScanMethod.SSDP
                                };

                                ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs
                                {
                                    ipToScan = ipToScan
                                };

                                

                                if (!_cts.Token.IsCancellationRequested)
                                {
                                    // Event im UI-Thread aufrufen
                                    Application.Current.Dispatcher.Invoke(() =>
                                    {
                                        Task.Run(() => SSDP_foundNewDevice?.Invoke(this, scanTask_Finished));
                                    });

                                    int respondedValue = Interlocked.Increment(ref responded);
                                    Task.Run(() => ProgressUpdated?.Invoke(current, respondedValue, total, ScanStatus.running));
                                }
                            }
                        }
                    }
                }
                catch (SocketException)
                {
                    //Console.WriteLine("⚠ Keine Antwort erhalten. Beende Scan.");
                }
                finally
                {
                    //Console.WriteLine("✅ SSDP-Scan abgeschlossen.");

                    // Sicherstellen, dass das Event auf dem UI-Thread aufgerufen wird

                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        SSDP_Scan_Finished?.Invoke(this, new Method_Finished_EventArgs() { ScanStatus = ScanStatus.finished });
                    });

                }
            }
            //return devices;        
        }











        /// <summary>
        /// Analysiert eine SSDP-Antwort und lädt die XML-Datei zur weiteren Verarbeitung.
        /// </summary>
        private async Task<SSDPDeviceInfo?> ParseSSDPResponseAsync(string ssdpResponse, string ipAddress)
        {
            var device = new SSDPDeviceInfo
            {
                IP = ipAddress,  // Speichert die IP-Adresse des Geräts
                Server = ExtractValue(ssdpResponse, @"SERVER:\s*(.+)"),
                Location = ExtractValue(ssdpResponse, @"LOCATION:\s*(.+)")
            };

            // Falls eine Location gefunden wurde, lade die XML-Datei und parse sie
            if (!string.IsNullOrEmpty(device.Location))
            {
                await ParseXMLFromURL(device, device.Location);
            }

            return device;
        }

        /// <summary>
        /// Extrahiert Werte aus einer SSDP-Antwort mithilfe von Regex.
        /// </summary>
        private static string ExtractValue(string input, string pattern)
        {
            var match = Regex.Match(input, pattern, RegexOptions.IgnoreCase);
            return match.Success ? match.Groups[1].Value.Trim() : string.Empty;
        }
      

        private static async Task ParseXMLFromURL(SSDPDeviceInfo device, string url)
        {
            try
            {
                using HttpClient client = new HttpClient();
                string xmlContent = await client.GetStringAsync(url);

                // XML in XDocument laden
                XDocument doc = XDocument.Parse(xmlContent);

                // Prüfen, ob es ein Default-Namespace gibt
                XNamespace ns = doc.Root?.GetDefaultNamespace() ?? XNamespace.None;

                XElement deviceElement = doc.Descendants(ns + "device").FirstOrDefault();

                if (deviceElement != null)
                {
                    device.FriendlyName = deviceElement.Element(ns + "friendlyName")?.Value ?? string.Empty;
                    device.Manufacturer = deviceElement.Element(ns + "manufacturer")?.Value ?? string.Empty;
                    device.ModelDescription = deviceElement.Element(ns + "modelDescription")?.Value ?? string.Empty;
                    device.ModelName = deviceElement.Element(ns + "modelName")?.Value ?? string.Empty;
                    device.ModelNumber = deviceElement.Element(ns + "modelNumber")?.Value ?? string.Empty;
                    device.ModelType = deviceElement.Element(ns + "modelType")?.Value ?? string.Empty;
                    device.URLBase = doc.Root?.Element(ns + "URLBase")?.Value ?? string.Empty;
                    device.PresentationURL = deviceElement.Element(ns + "presentationURL")?.Value ?? string.Empty;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠ Fehler beim Abrufen oder Parsen der XML: {ex.Message}");
            }
        }

    }
}

public class AsyncTimer
{
    private CancellationTokenSource _cts;
    public bool IsRunning { get; private set; } = false;

    public async Task StartAsync(int durationMs, int intervalMs, Func<Task> onTick)
    {
        if (IsRunning) return; // Verhindert mehrfaches Starten
        IsRunning = true;
        _cts = new CancellationTokenSource();

        try
        {
            int elapsed = 0;
            while (elapsed < durationMs && !_cts.Token.IsCancellationRequested)
            {
                await onTick(); // Callback ausführen
                await Task.Delay(intervalMs, _cts.Token);
                elapsed += intervalMs;
            }
        }
        catch (TaskCanceledException)
        {
            Console.WriteLine("⏹ Timer gestoppt.");
        }
        finally
        {
            IsRunning = false;
        }
    }

    public void Stop()
    {
        _cts?.Cancel();
    }
}