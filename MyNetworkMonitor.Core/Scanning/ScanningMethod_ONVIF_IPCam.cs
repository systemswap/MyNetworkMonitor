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
using System.Net.Http;
using System.Net.NetworkInformation;

namespace MyNetworkMonitor
{
    /// <summary>
    /// Finds ONVIF IP cameras by WS-Discovery probe (multicast 239.255.255.250, port 3702) and
    /// reads their stream and network details.
    /// </summary>
    public class ScanningMethod_ONVIF_IPCam
    {
        private readonly string ONVIF_MULTICAST_IP = "239.255.255.250";
        private readonly int ONVIF_PORT = 3702;
        private readonly TimeSpan DISCOVERY_TIMEOUT = TimeSpan.FromSeconds(5);


        /// <summary>Reports progress as (processed, responded, total, status).</summary>
        public event Action<int, int, int, ScanStatus> ProgressUpdated;

        /// <summary>Raised for every camera found, on a background thread.</summary>
        public event EventHandler<ScanTask_Finished_EventArgs>? new_ONVIF_IP_Camera_Found_Task_Finished;

        /// <summary>Raised when the discovery has finished.</summary>
        public event Action<ScanStatus>? ONVIF_IP_Camera_Scan_Finished;
        

        private int current = 0;
        private int responded = 0;
        private int total = 0;

        private CancellationTokenSource _cts = new CancellationTokenSource(); // Allows the scan to be cancelled.

        /// <summary>
        /// Cancels the running discovery and reports <see cref="ScanStatus.stopped"/>.
        /// </summary>
        public void StopScan()
        {
            if (_cts != null && !_cts.IsCancellationRequested)
            {
                _cts.Cancel();
                // Do NOT dispose and replace the source here: the loops read _cts through the
                // field. A fresh source at this point would report "not cancelled" to them and
                // the run would continue instead of ending. StartNewScan resets it for the next run.
            }

            ProgressUpdated?.Invoke(current, responded, total, ScanStatus.stopped); // Resets the progress display.
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

            // Reset the counters.
            current = 0;
            responded = 0;
            total = 0;
        }








        /// <summary>
        /// Sends the WS-Discovery probe three times on the selected interface and collects the
        /// answers of ONVIF devices for <see cref="DISCOVERY_TIMEOUT"/>.
        /// </summary>
        /// <param name="IPs">Not evaluated; the probe is sent by multicast.</param>
        /// <remarks>
        /// Returns <see cref="Task"/>, not <c>async void</c>, for the reason given at
        /// <see cref="ScanningMethod_SSDP_UPNP.Scan_for_SSDP_devices_async"/>.
        /// </remarks>
        public async Task Discover(List<IPToScan> IPs)
        {
            StartNewScan();

            List<IPCamInfos> discoveredCameras = new List<IPCamInfos>();
            string soapRequest = CreateSoapRequest();
            byte[] requestBytes = Encoding.UTF8.GetBytes(soapRequest); // Built once for all attempts.

            using (UdpClient udpClient = new UdpClient())
            {
                udpClient.EnableBroadcast = true;
                udpClient.MulticastLoopback = false;

                // Without this option the probe leaves through the default route of the operating
                // system, not through the selected interface; the same applies to SSDP.
                if (SupportMethods.SelectedNetworkInterfaceInfos.IPv4 is { } selectedInterface)
                {
                    udpClient.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface,
                        selectedInterface.GetAddressBytes());
                }

                IPEndPoint multicastEP = new IPEndPoint(IPAddress.Parse(ONVIF_MULTICAST_IP), ONVIF_PORT);

                // Send the multicast probe three times with a pause in between.
                for (int i = 0; i < 3; i++)
                {
                    if (_cts.Token.IsCancellationRequested) break;
                    await udpClient.SendAsync(requestBytes, requestBytes.Length, multicastEP);
                    await Task.Delay(500, _cts.Token); // 500 ms between the probes
                }

                udpClient.Client.ReceiveTimeout = 5000; // 5 seconds receive time

                try
                {
                    DateTime startTime = DateTime.UtcNow;

                    // The loop checks _cts.Token: StopScan() only sets the cancellation, and a loop
                    // that does not read it keeps running until the full DISCOVERY_TIMEOUT.
                    while (DateTime.UtcNow - startTime < DISCOVERY_TIMEOUT
                           && !_cts.Token.IsCancellationRequested)
                    {
                        var receiveTask = udpClient.ReceiveAsync();
                        var completedTask = await Task.WhenAny(receiveTask, Task.Delay(100, _cts.Token));

                        if (completedTask == receiveTask) // Answer received
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

                                // Raised on the background thread; UI subscribers marshal to the UI
                                // thread themselves, so the core needs no UI dependency.
                                new_ONVIF_IP_Camera_Found_Task_Finished?.Invoke(this, scanTask_Finished);

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





            // There is no unicast fallback: devices the multicast probe does not reach are not found.



            ONVIF_IP_Camera_Scan_Finished?.Invoke(ScanStatus.finished);
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

                // Namespace manager for the XPath queries.
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
                    Name = ExtractCameraName(Scopes)  // Camera name from the "name" scope
                };

                // Load stream details and MAC address.
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

    /// <summary>
    /// What an ONVIF camera reported in its discovery answer and its service descriptions.
    /// </summary>
    public class IPCamInfos
    {
        /// <summary>The IPv4 address the answer came from.</summary>
        public string IPv4Address { get; set; }

        /// <summary>The port of the device service address.</summary>
        public string Port { get; set; }

        /// <summary>The device service address (XAddrs) from the answer.</summary>
        public string XAddress { get; set; }

        /// <summary>The device UUID from the endpoint reference.</summary>
        public string UUID { get; set; }

        /// <summary>The metadata version from the answer.</summary>
        public string MetaVersion { get; set; }

        /// <summary>The camera name from the "name" scope.</summary>
        public string Name { get; set; } = "Unknown";

        /// <summary>The RTSP stream address.</summary>
        public string RTSPStreamURL { get; set; } = "Unknown";

        /// <summary>The video encoding.</summary>
        public string VideoEncoder { get; set; } = "Unknown";

        /// <summary>The resolution as width x height.</summary>
        public string Resolution { get; set; } = "Unknown";

        /// <summary>The frame rate.</summary>
        public string FPS { get; set; } = "Unknown";

        /// <summary>The hardware address from the network service.</summary>
        public string MACAddress { get; set; } = "Unknown";

        /// <summary>
        /// Reads stream details from the media service and the MAC address from the network
        /// service of the camera; values that cannot be read stay "Unknown".
        /// </summary>
        public async Task LoadStreamingAndMACInfo()
        {
            // Called from the receive loop in Discover(): without its own time limit a single slow
            // camera would block here for up to the HttpClient default of 100 seconds, while the
            // loop no longer reacts to answers of other cameras.
            using HttpClient client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
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
