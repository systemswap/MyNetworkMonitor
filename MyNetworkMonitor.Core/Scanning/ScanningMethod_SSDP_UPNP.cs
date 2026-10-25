// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
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
using System.Net.NetworkInformation;

namespace MyNetworkMonitor
{
    /// <summary>
    /// Finds UPnP devices by SSDP M-SEARCH (multicast 239.255.255.250, port 1900) and reads their
    /// device descriptions.
    /// </summary>
    public class ScanningMethod_SSDP_UPNP
    {

       

        /// <summary>Creates the SSDP scanner.</summary>
        public ScanningMethod_SSDP_UPNP()
        {

        }

        AsyncTimer timer = new AsyncTimer();
        /// <summary>Reports progress as (processed, responded, total, status).</summary>
        public event Action<int, int, int, ScanStatus> ProgressUpdated;

        /// <summary>Raised for every device found, on a background thread.</summary>
        public event EventHandler<ScanTask_Finished_EventArgs>? SSDP_foundNewDevice;

        /// <summary>Raised when the scan has finished.</summary>
        public event Action<ScanStatus>? SSDP_Scan_Finished;


        

        private int current = 0;
        private int responded = 0;
        private int total = 0;

        private CancellationTokenSource _cts = new CancellationTokenSource(); // Allows the scan to be cancelled.

        /// <summary>
        /// Cancels the running scan and reports <see cref="ScanStatus.stopped"/>.
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
        /// What a device reported in its SSDP answer and its UPnP device description.
        /// </summary>
        public class SSDPDeviceInfo
        {
            /// <summary>The IP address of the device.</summary>
            public string IP { get; set; } = string.Empty;

            /// <summary>The SERVER header of the answer.</summary>
            public string Server { get; set; } = string.Empty;

            /// <summary>The LOCATION header: the address of the device description.</summary>
            public string Location { get; set; } = string.Empty;

            /// <summary>The friendlyName of the device description.</summary>
            public string FriendlyName { get; set; } = string.Empty;

            /// <summary>The manufacturer of the device description.</summary>
            public string Manufacturer { get; set; } = string.Empty;

            /// <summary>The modelDescription of the device description.</summary>
            public string ModelDescription { get; set; } = string.Empty;

            /// <summary>The modelName of the device description.</summary>
            public string ModelName { get; set; } = string.Empty;

            /// <summary>The modelNumber of the device description.</summary>
            public string ModelNumber { get; set; } = string.Empty;

            /// <summary>The modelType of the device description.</summary>
            public string ModelType { get; set; } = string.Empty;

            /// <summary>The URLBase of the device description.</summary>
            public string URLBase { get; set; } = string.Empty;

            /// <summary>The presentationURL of the device description.</summary>
            public string PresentationURL { get; set; } = string.Empty;

            /// <summary>Formats all values as multi-line text.</summary>
            /// <returns>The values, one per line.</returns>
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



        private readonly string SSDP_IP = "239.255.255.250"; // SSDP multicast address
        private readonly int SSDP_PORT = 1900;               // SSDP port
    
        
        /// <summary>
        /// Sends an SSDP M-SEARCH on the selected interface, receives the answers and reads the
        /// device description of every answering device.
        /// </summary>
        /// <param name="scanDuration">How long answers are received, in milliseconds.</param>
        /// <remarks>
        /// Returns <see cref="Task"/>, not <c>async void</c>: with <c>async void</c> an exception
        /// ends up unhandled on the thread pool and terminates the process, and no try/catch at the
        /// caller can prevent that (for example when no network adapter is selected yet). Callers
        /// using <c>Task.Run(() => ...)</c> await the returned task.
        /// </remarks>
        public async Task Scan_for_SSDP_devices_async(int scanDuration = 5000)
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

                // Without this option the M-SEARCH leaves through the default route of the operating
                // system, not through the selected interface. On a computer with several adapters
                // (VPN, Docker, a second network card) the request then comes from the wrong side and
                // the devices of the intended segment do not answer.
                if (SupportMethods.SelectedNetworkInterfaceInfos.IPv4 is { } selectedInterface)
                {
                    udpClient.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface,
                        selectedInterface.GetAddressBytes());
                }

                IPEndPoint multicastEP = new IPEndPoint(IPAddress.Parse(SSDP_IP), SSDP_PORT);

                // Build the SSDP M-SEARCH request.
                string ssdpRequest =
                    "M-SEARCH * HTTP/1.1\r\n" +
                    $"HOST: {SSDP_IP}:{SSDP_PORT}\r\n" +
                    "MAN: \"ssdp:discover\"\r\n" +
                    "MX: 3\r\n" +  // Maximum answer delay in seconds
                    "ST: ssdp:all\r\n" +  // Search for all UPnP devices and services
                    "\r\n";

                byte[] requestBytes = Encoding.UTF8.GetBytes(ssdpRequest);
                await udpClient.SendAsync(requestBytes, requestBytes.Length, multicastEP);


                udpClient.Client.ReceiveTimeout = scanDuration; // Receive timeout for answers

                try
                {
                    // Start the timer without waiting for it to end.
                    var timerTask = timer.StartAsync(scanDuration, 1000, async () => { });

                    while (timer.IsRunning)
                    {
                        if (_cts.Token.IsCancellationRequested) break;

                        var receiveTask = udpClient.ReceiveAsync();
                        var completedTask = await Task.WhenAny(receiveTask, Task.Delay(10, _cts.Token));

                        if (_cts.Token.IsCancellationRequested) break; // Cancelled during Task.WhenAny()

                        if (completedTask == receiveTask && !_cts.Token.IsCancellationRequested) // Answer received
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
                                    // Raised on the background thread; UI subscribers marshal to the UI
                                    // thread themselves, so the core needs no UI dependency.
                                    SSDP_foundNewDevice?.Invoke(this, scanTask_Finished);

                                    int respondedValue = Interlocked.Increment(ref responded);
                                    ProgressUpdated?.Invoke(current, respondedValue, total, ScanStatus.running);
                                }
                            }
                        }
                    }
                }
                catch (SocketException)
                {
                    // No further answer within the receive timeout: the scan ends.
                }
                finally
                {

                    SSDP_Scan_Finished?.Invoke(ScanStatus.finished);

                }
            }
        }











        /// <summary>
        /// Evaluates an SSDP answer and loads the device description it points to.
        /// </summary>
        private async Task<SSDPDeviceInfo?> ParseSSDPResponseAsync(string ssdpResponse, string ipAddress)
        {
            var device = new SSDPDeviceInfo
            {
                IP = ipAddress,
                Server = ExtractValue(ssdpResponse, @"SERVER:\s*(.+)"),
                Location = ExtractValue(ssdpResponse, @"LOCATION:\s*(.+)")
            };

            // If the answer has a LOCATION, load and parse the device description.
            if (!string.IsNullOrEmpty(device.Location))
            {
                await ParseXMLFromURL(device, device.Location);
            }

            return device;
        }

        /// <summary>
        /// Extracts a header value from an SSDP answer with a regular expression.
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
                // Without its own time limit a single slow or dead device would block here for up to
                // the HttpClient default of 100 seconds, while the receive loop does not run and the
                // answers of other devices stay unprocessed.
                using HttpClient client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                string xmlContent = await client.GetStringAsync(url);

                // Load the XML into an XDocument.
                XDocument doc = XDocument.Parse(xmlContent);

                // Use the default namespace, if there is one.
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

/// <summary>
/// Runs a callback at a fixed interval for a given duration.
/// </summary>
public class AsyncTimer
{
    private CancellationTokenSource _cts;

    /// <summary>Whether the timer is running.</summary>
    public bool IsRunning { get; private set; } = false;

    /// <summary>
    /// Calls <paramref name="onTick"/> every <paramref name="intervalMs"/> milliseconds until
    /// <paramref name="durationMs"/> has passed or <see cref="Stop"/> is called. A second call
    /// while the timer runs returns at once.
    /// </summary>
    /// <param name="durationMs">The total duration in milliseconds.</param>
    /// <param name="intervalMs">The interval between the calls in milliseconds.</param>
    /// <param name="onTick">The callback.</param>
    public async Task StartAsync(int durationMs, int intervalMs, Func<Task> onTick)
    {
        if (IsRunning) return; // Prevents a second start.
        IsRunning = true;
        _cts = new CancellationTokenSource();

        try
        {
            int elapsed = 0;
            while (elapsed < durationMs && !_cts.Token.IsCancellationRequested)
            {
                await onTick();
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

    /// <summary>Stops the timer.</summary>
    public void Stop()
    {
        _cts?.Cancel();
    }
}