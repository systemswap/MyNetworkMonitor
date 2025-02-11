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
        public event EventHandler<ScanTask_Finished_EventArgs>? SSDP_foundNewDevice;
        public event EventHandler<Method_Finished_EventArgs>? SSDP_Scan_Finished;


        public event Action<int, int, int> ProgressUpdated;
        int current = 0;
        int responsed = 0;
        int total = 0;



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
        bool allowWhile = true;
        public static Task<bool> ReturnFalseAfter(int timeoutMs) => Task.Delay(timeoutMs).ContinueWith(_ => false);


        /// <summary>
        /// Führt einen SSDP-Scan durch, empfängt Antworten und extrahiert Geräteinformationen.
        /// </summary>
        /// <param name="scanDuration">in milliseconds</param>
        //public async void Scan_for_SSDP_devices_async(int scanDuration = 5000)
        //{

        //    current = 0;
        //    responsed = 0;
        //    total = 0;

        //    List<SSDPDeviceInfo> devices = new List<SSDPDeviceInfo>();

        //    using (UdpClient udpClient = new UdpClient())
        //    {
        //        udpClient.EnableBroadcast = true;
        //        udpClient.MulticastLoopback = true;

        //        IPEndPoint multicastEP = new IPEndPoint(IPAddress.Parse(SSDP_IP), SSDP_PORT);

        //        // SSDP-M-SEARCH Anfrage erstellen
        //        string ssdpRequest =
        //            "M-SEARCH * HTTP/1.1\r\n" +
        //            $"HOST: {SSDP_IP}:{SSDP_PORT}\r\n" +
        //            "MAN: \"ssdp:discover\"\r\n" +
        //            "MX: 3\r\n" +  // Maximale Wartezeit für Antworten
        //            "ST: ssdp:all\r\n" +  // Suche nach allen UPnP-Geräten
        //            "\r\n";

        //        byte[] requestBytes = Encoding.UTF8.GetBytes(ssdpRequest);
        //        await udpClient.SendAsync(requestBytes, requestBytes.Length, multicastEP);

        //        //Console.WriteLine("📡 SSDP-Scan gesendet... Warte auf Antworten...");

        //        // Antworten empfangen
        //        var endpoint = new IPEndPoint(IPAddress.Any, SSDP_PORT);
        //        udpClient.Client.ReceiveTimeout = scanDuration; // Timeout für Antworten (5 Sekunden)

        //        try
        //        {
        //            // Starte den Timer und warte nicht auf seine Beendigung
        //            var timerTask = timer.StartAsync(scanDuration, 1000, async () => { });

        //            while (timer.IsRunning)
        //            {
        //                var receiveTask = udpClient.ReceiveAsync();
        //                var completedTask = await Task.WhenAny(receiveTask, Task.Delay(100));

        //                if (completedTask == receiveTask) // Antwort erhalten
        //                {
        //                    UdpReceiveResult result = receiveTask.Result;
        //                    string response = Encoding.UTF8.GetString(result.Buffer);

        //                    var device = await ParseSSDPResponseAsync(response, result.RemoteEndPoint.Address.ToString());

        //                    if (device != null && !devices.Any(d => d.IP == device.IP))
        //                    {
        //                        devices.Add(device);

        //                        IPToScan ipToScan = new IPToScan
        //                        {
        //                            SSDPStatus = true,
        //                            IPorHostname = device.IP,
        //                            IPGroupDescription = "not specified",
        //                            DeviceDescription = "not specified",
        //                            UsedScanMethod = ScanMethod.SSDP
        //                        };

        //                        ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs
        //                        {
        //                            ipToScan = ipToScan
        //                        };

        //                        // Event im UI-Thread aufrufen
        //                        Application.Current.Dispatcher.Invoke(() =>
        //                        {
        //                            SSDP_foundNewDevice?.Invoke(this, scanTask_Finished);
        //                        });

        //                        int responsedValue = Interlocked.Increment(ref responsed);
        //                        ProgressUpdated?.Invoke(current, responsedValue, total);
        //                    }
        //                }
        //            }
        //        }
        //        catch (SocketException)
        //        {
        //            //Console.WriteLine("⚠ Keine Antwort erhalten. Beende Scan.");
        //        }
        //        finally
        //        {
        //            //Console.WriteLine("✅ SSDP-Scan abgeschlossen.");

        //            // Sicherstellen, dass das Event auf dem UI-Thread aufgerufen wird
        //            Application.Current.Dispatcher.Invoke(() =>
        //            {
        //                SSDP_Scan_Finished?.Invoke(this, new Method_Finished_EventArgs());
        //            });
        //        }
        //    }
        //    //return devices;        
        //}

        



        public async void Scan_for_SSDP_devices_async(int scanDuration = 5000)
        {
            current = 0;
            responsed = 0;
            total = 0;

            List<SSDPDeviceInfo> devices = new List<SSDPDeviceInfo>();
           
                using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                    socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, true);
                    socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 2);

                //IPEndPoint localEndPoint = new IPEndPoint(IPAddress.Any, SSDP_PORT);
                IPEndPoint localEndPoint = new IPEndPoint(SupportMethods.SelectedNetworkInterfaceInfos.IPv4, SSDP_PORT);
                try
                {
                    socket.Bind(localEndPoint);
                }
                catch
                {
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        SSDP_Scan_Finished?.Invoke(this, new Method_Finished_EventArgs() { ScanStatus = MainWindow.ScanStatus.wrongNetworkInterfaceSelected });
                    });
                    socket.Close();
                    return;
                }
                    IPEndPoint multicastEP = new IPEndPoint(IPAddress.Parse(SSDP_IP), SSDP_PORT);

                    // SSDP-M-SEARCH Anfrage erstellen
                    string ssdpRequest =
                        "M-SEARCH * HTTP/1.1\r\n" +
                        $"HOST: {SSDP_IP}:{SSDP_PORT}\r\n" +
                        "MAN: \"ssdp:discover\"\r\n" +
                        "MX: 3\r\n" +
                        "ST: ssdp:all\r\n" +
                        "\r\n";

                    byte[] requestBytes = Encoding.UTF8.GetBytes(ssdpRequest);

                try
                {
                    socket.SendTo(requestBytes, multicastEP);
                    Console.WriteLine("📡 SSDP-Scan gesendet... Warte auf Antworten...");
                }
                catch (Exception ex)
                {
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        SSDP_Scan_Finished?.Invoke(this, new Method_Finished_EventArgs() { ScanStatus = MainWindow.ScanStatus.AnotherLocalAppUsedThePort});                        
                    });
                    socket.Close();
                    return;
                }
               
                    

                    DateTime startTime = DateTime.Now;

                    try
                    {
                        while ((DateTime.Now - startTime).TotalMilliseconds < scanDuration)
                        {
                            if (socket.Poll(100000, SelectMode.SelectRead))  // 100 ms warten, ob Daten verfügbar sind
                            {
                                byte[] buffer = new byte[2048];
                                EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
                                int receivedBytes = socket.ReceiveFrom(buffer, ref remoteEndPoint);

                                if (receivedBytes > 0)
                                {
                                    string response = Encoding.UTF8.GetString(buffer, 0, receivedBytes);
                                    var device = await ParseSSDPResponseAsync(response, ((IPEndPoint)remoteEndPoint).Address.ToString());

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

                                        // Event im UI-Thread aufrufen
                                        Application.Current.Dispatcher.Invoke(() =>
                                        {
                                            SSDP_foundNewDevice?.Invoke(this, scanTask_Finished);
                                        });

                                        int responsedValue = Interlocked.Increment(ref responsed);
                                        ProgressUpdated?.Invoke(current, responsedValue, total);
                                    }
                                }
                            }
                            await Task.Delay(100);  // CPU-Last reduzieren
                        }
                    }
                    catch (SocketException ex)
                    {
                        Console.WriteLine($"⚠ Fehler beim Empfang: {ex.Message}");
                    socket.Close();
                    return;
                }
                    finally
                    {
                        Console.WriteLine("✅ SSDP-Scan abgeschlossen.");
                        Application.Current.Dispatcher.Invoke(() =>
                        {
                            SSDP_Scan_Finished?.Invoke(this, new Method_Finished_EventArgs() { ScanStatus = MainWindow.ScanStatus.finished});
                        });
                    }
                }            
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

        ///// <summary>
        ///// Lädt die XML-Datei von der angegebenen URL und extrahiert wichtige Informationen.
        ///// </summary>
        //private static async Task ParseXMLFromURL(SSDPDeviceInfo device, string url)
        //{
        //    try
        //    {
        //        using HttpClient client = new HttpClient();
        //        string xmlContent = await client.GetStringAsync(url);

        //        // XML in ein XElement laden
        //        XDocument doc = XDocument.Parse(xmlContent);
        //        XElement deviceElement = doc.Root?.Element("device");

        //        if (deviceElement != null)
        //        {
        //            device.FriendlyName = deviceElement.Element("friendlyName")?.Value ?? string.Empty;
        //            device.Manufacturer = deviceElement.Element("manufacturer")?.Value ?? string.Empty;
        //            device.ModelDescription = deviceElement.Element("modelDescription")?.Value ?? string.Empty;
        //            device.ModelName = deviceElement.Element("modelName")?.Value ?? string.Empty;
        //            device.ModelNumber = deviceElement.Element("modelNumber")?.Value ?? string.Empty;
        //            device.ModelType = deviceElement.Element("modelType")?.Value ?? string.Empty;
        //            device.URLBase = deviceElement.Element("serviceList")?.Element("service")?.Element("URLBase")?.Value ?? string.Empty;
        //            device.PresentationURL = deviceElement.Element("presentationURL")?.Value ?? string.Empty;
        //        }
        //    }
        //    catch (Exception ex)
        //    {
        //        Console.WriteLine($"⚠ Fehler beim Abrufen oder Parsen der XML: {ex.Message}");
        //    }
        //}

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