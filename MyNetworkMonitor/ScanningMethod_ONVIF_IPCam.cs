using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.Xml;
using System.Xml.XPath;
using System.Threading;
using System.Windows;
using System.Net.Http;
using System.Net.NetworkInformation;

namespace MyNetworkMonitor
{
    internal class ScanningMethod_ONVIF_IPCam
    {
        private readonly string ONVIF_MULTICAST_IP = "239.255.255.250";
        private readonly int ONVIF_PORT = 3702;
        private readonly TimeSpan DISCOVERY_TIMEOUT = TimeSpan.FromSeconds(5);


        public event Action<int, int, int, ScanStatus> ProgressUpdated;
        public event EventHandler<ScanTask_Finished_EventArgs>? new_ONVIF_IP_Camera_Found_Task_Finished;
        public event EventHandler<Method_Finished_EventArgs>? ONVIF_IP_Camera_Scan_Finished;
        

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


        //public async void Discover(List<IPToScan> IPs)
        //{
        //    List<IPCamInfos> discoveredCameras = new List<IPCamInfos>();

        //    using (UdpClient udpClient = new UdpClient())
        //    {
        //        udpClient.EnableBroadcast = true;
        //        udpClient.MulticastLoopback = false;
        //        IPEndPoint multicastEP = new IPEndPoint(IPAddress.Parse(ONVIF_MULTICAST_IP), ONVIF_PORT);

        //        string soapRequest = CreateSoapRequest();
        //        byte[] requestBytes = Encoding.UTF8.GetBytes(soapRequest);
        //        await udpClient.SendAsync(requestBytes, requestBytes.Length, multicastEP);

        //        var endpoint = new IPEndPoint(IPAddress.Any, ONVIF_PORT);
        //        udpClient.Client.ReceiveTimeout = (int)DISCOVERY_TIMEOUT.TotalMilliseconds;

        //        try
        //        {
        //            DateTime startTime = DateTime.UtcNow;
        //            while (DateTime.UtcNow - startTime < DISCOVERY_TIMEOUT)
        //            {
        //                var receiveTask = udpClient.ReceiveAsync();
        //                var completedTask = await Task.WhenAny(receiveTask, Task.Delay(100));

        //                if (completedTask == receiveTask) // Antwort erhalten
        //                {
        //                    UdpReceiveResult result = receiveTask.Result;
        //                    string response = Encoding.UTF8.GetString(result.Buffer);
        //                    var cameraInfo = await ParseONVIFResponseAsync(response, result.RemoteEndPoint.Address.ToString());

        //                    if (cameraInfo != null && !discoveredCameras.Any(d => d.UUID == cameraInfo.UUID))
        //                    {
        //                        discoveredCameras.Add(cameraInfo);

        //                        IPToScan ipToScan = new IPToScan
        //                        {
        //                            UsedScanMethod = ScanMethod.ONVIF_IPCam,
        //                            IsIPCam = true,
        //                            IPorHostname = cameraInfo.IPv4Address,
        //                            IPCamName = cameraInfo.Name,  // **Kamera-Name hinzugefügt**
        //                            IPCamXAddress = cameraInfo.XAddress.Replace("/onvif/device_service", string.Empty)
        //                        };

        //                        ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs
        //                        {
        //                            ipToScan = ipToScan
        //                        };

        //                        Application.Current.Dispatcher.Invoke(() =>
        //                        {
        //                            new_ONVIF_IP_Camera_Found_Task_Finished?.Invoke(this, scanTask_Finished);
        //                        });

        //                        int respondedValue = Interlocked.Increment(ref responded);
        //                        ProgressUpdated?.Invoke(current, responded, total);
        //                    }
        //                }
        //            }
        //        }
        //        catch (SocketException) { }
        //        finally
        //        {
        //            Application.Current.Dispatcher.Invoke(() =>
        //            {
        //                ONVIF_IP_Camera_Scan_Finished?.Invoke(this, new Method_Finished_EventArgs());
        //            });
        //        }
        //    }
        //}






        public async void Discover(List<IPToScan> IPs)
        {
            StartNewScan();

            List<IPCamInfos> discoveredCameras = new List<IPCamInfos>();
            string soapRequest = CreateSoapRequest();
            byte[] requestBytes = Encoding.UTF8.GetBytes(soapRequest); // 📌 **Hier außerhalb definiert!**

            using (UdpClient udpClient = new UdpClient())
            {
                udpClient.EnableBroadcast = true;
                udpClient.MulticastLoopback = false;
                IPEndPoint multicastEP = new IPEndPoint(IPAddress.Parse(ONVIF_MULTICAST_IP), ONVIF_PORT);

                // Mehrfache Multicast-Anfragen senden (3 Versuche mit Pause)
                for (int i = 0; i < 3; i++)
                {
                    await udpClient.SendAsync(requestBytes, requestBytes.Length, multicastEP);
                    await Task.Delay(500); // 500ms Pause zwischen den Anfragen
                }

                //var endpoint = new IPEndPoint(IPAddress.Any, ONVIF_PORT);
                var endpoint = new IPEndPoint(SupportMethods.SelectedNetworkInterfaceInfos.IPv4, ONVIF_PORT);
                udpClient.Client.ReceiveTimeout = 5000; // 📌 5 Sekunden Empfangszeit

                try
                {
                    DateTime startTime = DateTime.UtcNow;
                    while (DateTime.UtcNow - startTime < DISCOVERY_TIMEOUT)
                    {
                        var receiveTask = udpClient.ReceiveAsync();
                        var completedTask = await Task.WhenAny(receiveTask, Task.Delay(100));

                        if (completedTask == receiveTask) // Antwort erhalten
                        {
                            UdpReceiveResult result = receiveTask.Result;
                            string response = Encoding.UTF8.GetString(result.Buffer);
                            var cameraInfo = await ParseONVIFResponseAsync(response, result.RemoteEndPoint.Address.ToString());

                            if (cameraInfo != null && !discoveredCameras.Any(d => d.UUID == cameraInfo.UUID))
                            {
                                discoveredCameras.Add(cameraInfo);

                                IPToScan ipToScan = new IPToScan
                                {
                                    UsedScanMethod = ScanMethod.ONVIF_IPCam,
                                    IsIPCam = true,
                                    IPorHostname = cameraInfo.IPv4Address,
                                    IPCamName = cameraInfo.Name,
                                    IPCamXAddress = cameraInfo.XAddress.Replace("/onvif/device_service", string.Empty)
                                };

                                ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs
                                {
                                    ipToScan = ipToScan
                                };

                                Application.Current.Dispatcher.Invoke(() =>
                                {
                                    new_ONVIF_IP_Camera_Found_Task_Finished?.Invoke(this, scanTask_Finished);
                                });

                                int respondedValue = Interlocked.Increment(ref responded);
                                ProgressUpdated?.Invoke(current, respondedValue, total, ScanStatus.running);
                            }
                        }
                    }
                }
                catch (SocketException) { }
                finally
                {
                    
                }
            }





            //**📌 Unicast - Fallback(falls Multicast nicht alle Geräte erreicht) * *
            //kommt vieleicht später

            //responded = 0;


            Application.Current.Dispatcher.Invoke(() =>
            {
                ONVIF_IP_Camera_Scan_Finished?.Invoke(this, new Method_Finished_EventArgs() { ScanStatus = ScanStatus.finished });
            });
        }





        private string CreateSoapRequest()
        {
            Guid messageId = Guid.NewGuid();
            return $@"
            <?xml version=""1.0"" encoding=""UTF-8""?>
            <e:Envelope xmlns:e=""http://www.w3.org/2003/05/soap-envelope""
            xmlns:w=""http://schemas.xmlsoap.org/ws/2004/08/addressing""
            xmlns:d=""http://schemas.xmlsoap.org/ws/2005/04/discovery""
            xmlns:dn=""http://www.onvif.org/ver10/device/wsdl"">
            <e:Header>
            <w:MessageID>uuid:{messageId}</w:MessageID>
            <w:To e:mustUnderstand=""true"">urn:schemas-xmlsoap-org:ws:2005:04/discovery</w:To>
            <w:Action e:mustUnderstand=""true"">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
            </e:Header>
            <e:Body>
            <d:Probe>
            <d:Types>dn:Device</d:Types>
            </d:Probe>
            </e:Body>
            </e:Envelope>";
        }

        private async Task<IPCamInfos?> ParseONVIFResponseAsync(string soapMessage, string ipAddress)
        {
            try
            {
                XDocument xDoc = XDocument.Parse(soapMessage);

                // Namespace-Manager für XPath-Abfragen
                var nsManager = new XmlNamespaceManager(new NameTable());
                nsManager.AddNamespace("SOAP-ENV", "http://www.w3.org/2003/05/soap-envelope");
                nsManager.AddNamespace("wsa", "http://schemas.xmlsoap.org/ws/2004/08/addressing");
                nsManager.AddNamespace("wsdd", "http://schemas.xmlsoap.org/ws/2005/04/discovery");
                nsManager.AddNamespace("dn", "http://www.onvif.org/ver10/network/wsdl");

                var UUID = xDoc.XPathSelectElement("//wsa:Address", nsManager)?.Value;
                var XAddrs = xDoc.XPathSelectElement("//wsdd:XAddrs", nsManager)?.Value;
                var Scopes = xDoc.XPathSelectElement("//wsdd:Scopes", nsManager)?.Value;
                var MetadataVersion = xDoc.XPathSelectElement("//wsdd:MetadataVersion", nsManager)?.Value;

                if (UUID == null || XAddrs == null || Scopes == null || MetadataVersion == null)
                    return null;

                var camera = new IPCamInfos
                {
                    IPv4Address = ipAddress,
                    Port = new Uri(XAddrs).Port.ToString(),
                    XAddress = XAddrs,
                    UUID = UUID.Split(':').Last(),
                    MetaVersion = MetadataVersion,
                    Name = ExtractCameraName(Scopes)  // Kamera-Name extrahieren
                };

                // **Lade Streaming- & MAC-Adresse**
                await camera.LoadStreamingAndMACInfo();

                return camera;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠ Fehler beim Parsen der ONVIF-Kamera-Antwort: {ex.Message}");
                return null;
            }
        }

        private static string ExtractCameraName(string scopes)
        {
            if (string.IsNullOrEmpty(scopes))
                return "Unknown";

            return scopes.Split(' ')
                         .FirstOrDefault(scope => scope.Contains("/name/"))?
                         .Split('/')
                         .Last() ?? "Unknown";
        }        
    }

    public class IPCamInfos
    {
        public string IPv4Address { get; set; }
        public string Port { get; set; }
        public string XAddress { get; set; }
        public string UUID { get; set; }
        public string MetaVersion { get; set; }

        // **Kamera-Infos**
        public string Name { get; set; } = "Unknown";

        // **Streaming-Infos**
        public string RTSPStreamURL { get; set; } = "Unknown";
        public string VideoEncoder { get; set; } = "Unknown";
        public string Resolution { get; set; } = "Unknown";
        public string FPS { get; set; } = "Unknown";

        // **Netzwerk**
        public string MACAddress { get; set; } = "Unknown";

        public async Task LoadStreamingAndMACInfo()
        {
            using HttpClient client = new HttpClient();
            try
            {
                string mediaUrl = $"{XAddress}/media_service";
                string xmlContent = await client.GetStringAsync(mediaUrl);
                XDocument doc = XDocument.Parse(xmlContent);

                VideoEncoder = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Encoding")?.Value ?? "Unknown";
                Resolution = $"{doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Width")?.Value}x" +
                             $"{doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Height")?.Value}" ?? "Unknown";
                FPS = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "FrameRate")?.Value ?? "Unknown";
                RTSPStreamURL = $"{XAddress}/media?stream=1";

                string networkUrl = $"{XAddress}/network_service";
                string networkContent = await client.GetStringAsync(networkUrl);
                XDocument networkDoc = XDocument.Parse(networkContent);
                MACAddress = networkDoc.Descendants().FirstOrDefault(e => e.Name.LocalName == "HwAddress")?.Value ?? "Unknown";
            }
            catch (Exception) { }
        }
    }
}
