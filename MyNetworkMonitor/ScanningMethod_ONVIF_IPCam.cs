//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Net.Sockets;
//using System.Net;
//using System.Text;
//using System.Threading.Tasks;
//using System.Diagnostics;
//using System.Net.Mail;
//using System.Windows.Threading;
//using System.Net.NetworkInformation;
//using System.Xml.Linq;
//using System.Xml;
//using System.Xml.XPath;
//using OnvifDiscovery;
//using System.Threading;
//using OnvifDiscovery.Models;
//using System.Data;
//using System.IO;
//using System.Xml.Serialization;

//namespace MyNetworkMonitor
//{
//    internal class ScanningMethod_ONVIF_IPCam
//    {
//        public ScanningMethod_ONVIF_IPCam() { }

//        public event EventHandler<ScanTask_Finished_EventArgs>? newIPCameraFound_Task_Finished;
//        public event EventHandler<Method_Finished_EventArgs>? IPCameraScan_Finished;

//        List<IPToScan> _IPs = new List<IPToScan>();
//        public async void Discover(List<IPToScan> IPs)
//        {
//            _IPs = IPs;
//            // Create a Discovery instance
//            var onvifDiscovery = new Discovery();

//            // You can call Discover with a callback (Action) and CancellationToken
//            CancellationTokenSource cancellation = new CancellationTokenSource();
//            await Task.Run(() => onvifDiscovery.Discover(5, OnNewDevice, cancellation.Token));

//            IPCameraScan_Finished(this, new Method_Finished_EventArgs());
//        }
//        private void OnNewDevice(DiscoveryDevice device)
//        {
//            IPToScan ipToScan = new IPToScan();

//            ipToScan.UsedScanMethod = ScanMethod.ONVIF_IPCam;
//            ipToScan.IsIPCam = true;
//            ipToScan.IPorHostname = device.Address;
//            ipToScan.IPCamName = device.Mfr;
//            ipToScan.IPCamXAddress = string.Join("\r\n", device.XAddresses).Replace("/onvif/device_service", string.Empty);

//            ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs();
//            scanTask_Finished.ipToScan = ipToScan;

//            newIPCameraFound_Task_Finished(this, scanTask_Finished);
//        }



//        public async Task<List<string>> GetSoapResponsesFromCamerasAsync(IPAddress IPForBroadcast, List<IPToScan> IPs)
//        {
//            var result = new List<string>();

//            using (var client = new UdpClient())
//            {
//                var ipEndpoint = new IPEndPoint(IPForBroadcast, 3702);
//                client.EnableBroadcast = true;
//                try
//                {
//                    var soapMessage = GetBytes(CreateSoapRequest());
//                    var timeout = DateTime.Now.AddSeconds(3);
//                    await client.SendAsync(soapMessage, soapMessage.Length, ipEndpoint);

//                    while (timeout > DateTime.Now)
//                    {
//                        if (client.Available > 0)
//                        {
//                            var receiveResult = await client.ReceiveAsync();
//                            var text = GetText(receiveResult.Buffer);
//                            var Infos = GetCamInfos(text);
//                            result.Add(Infos.IPv4Address);
//                        }
//                        else
//                        {
//                            await Task.Delay(10);
//                        }
//                    }
//                }
//                catch (Exception exception)
//                {
//                    Console.WriteLine(exception.Message);
//                }
//            }
//            return result;
//        }

//        private string CreateSoapRequest()
//        {
//            Guid messageId = Guid.NewGuid();
//            const string soap = @"
//            <?xml version=""1.0"" encoding=""UTF-8""?>
//            <e:Envelope xmlns:e=""http://www.w3.org/2003/05/soap-envelope""
//            xmlns:w=""http://schemas.xmlsoap.org/ws/2004/08/addressing""
//            xmlns:d=""http://schemas.xmlsoap.org/ws/2005/04/discovery""
//            xmlns:dn=""http://www.onvif.org/ver10/device/wsdl"">
//            <e:Header>
//            <w:MessageID>uuid:{0}</w:MessageID>
//            <w:To e:mustUnderstand=""true"">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
//            <w:Action a:mustUnderstand=""true"">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
//            </e:Header>
//            <e:Body>
//            <d:Probe>
//            <d:Types>dn:Device</d:Types>
//            </d:Probe>
//            </e:Body>
//            </e:Envelope>
//            ";

//            var result = string.Format(soap, messageId);
//            return result;
//        }

//        private byte[] GetBytes(string text)
//        {
//            return Encoding.ASCII.GetBytes(text);
//        }

//        private string GetText(byte[] bytes)
//        {
//            return Encoding.ASCII.GetString(bytes, 0, bytes.Length);
//        }

//        private IPCamInfos GetCamInfos(string soapMessage)
//        {
//            var xmlNamespaceManager = new XmlNamespaceManager(new NameTable());
//            xmlNamespaceManager.AddNamespace("wsa", "http://schemas.xmlsoap.org/ws/2004/08/addressing");
//            xmlNamespaceManager.AddNamespace("wsdd", "http://schemas.xmlsoap.org/ws/2005/04/discovery");


//            var xelement = XElement.Parse(soapMessage);
//            var UUID = XElement.Parse(soapMessage).XPathSelectElement("//wsa:Address[1]", xmlNamespaceManager);
//            var XAddrs = XElement.Parse(soapMessage).XPathSelectElement("//wsdd:XAddrs[1]", xmlNamespaceManager);
//            var Scopes = XElement.Parse(soapMessage).XPathSelectElement("//wsdd:Scopes[1]", xmlNamespaceManager);
//            var MetadataVersion = XElement.Parse(soapMessage).XPathSelectElement("//wsdd:MetadataVersion[1]", xmlNamespaceManager);

//            string Address = XAddrs.Value.Replace("http://",string.Empty);
//            string IPv4Address = Address.Remove(Address.IndexOf("/")).Split(":")[0];
//            string Port = Address.Remove(Address.IndexOf("/")).Split(":")[1];

//            List<string> lst_Scopes = Scopes.Value.Split(' ').ToList(); 
//            string name = lst_Scopes.Where(i => i.Contains("/name/")).First();
//            string hardware = lst_Scopes.Where(i => i.Contains("/hardware/")).First();
//            string location = lst_Scopes.Where(i => i.Contains("/location/")).First();

//            name = name.Substring(name.LastIndexOf('/') + 1);
//            hardware = hardware.Substring(hardware.LastIndexOf('/') + 1);
//            location = location.Substring(location.LastIndexOf('/') + 1);

//            string metadataVersion = MetadataVersion.Value;

//            string uuid = UUID.Value;
//            uuid = uuid.Remove(0, uuid.LastIndexOf(":") + 1);

//            IPCamInfos infos = new IPCamInfos();
//            infos.IPv4Address = IPv4Address;
//            infos.IPv6Address = string.Empty;
//            infos.Port = Port;
//            infos.Name = name;
//            infos.Hardware = hardware;
//            infos.Location = location;
//            infos.MetaVersion = metadataVersion;
//            infos.UUID = uuid;

//            return infos;
//        }
//    }

//    public class IPCamInfos
//    {
//        public string IPv4Address { get; set; }
//        public string IPv6Address { get; set; }
//        public string Port { get; set; }
//        public string Name { get; set; }
//        public string Hardware { get; set; }
//        public string Location { get; set; }
//        public string MetaVersion { get; set; }
//        public string UUID { get; set; }
//    }
//}









//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Net;
//using System.Net.Sockets;
//using System.Text;
//using System.Threading.Tasks;
//using System.Xml.Linq;
//using System.Xml;
//using System.Xml.XPath;
//using System.Threading;
//using System.Windows;

//namespace MyNetworkMonitor
//{
//    internal class ScanningMethod_ONVIF_IPCam
//    {
//        private readonly string ONVIF_MULTICAST_IP = "239.255.255.250";
//        private readonly int ONVIF_PORT = 3702;
//        private readonly TimeSpan DISCOVERY_TIMEOUT = TimeSpan.FromSeconds(5);

//        public event EventHandler<ScanTask_Finished_EventArgs>? newIPCameraFound_Task_Finished;
//        public event EventHandler<Method_Finished_EventArgs>? IPCameraScan_Finished;

//        public async void Discover(List<IPToScan> IPs)
//        {
//            List<IPCamInfos> discoveredCameras = new List<IPCamInfos>();

//            using (UdpClient udpClient = new UdpClient())
//            {
//                udpClient.EnableBroadcast = true;
//                udpClient.MulticastLoopback = false;
//                IPEndPoint multicastEP = new IPEndPoint(IPAddress.Parse(ONVIF_MULTICAST_IP), ONVIF_PORT);

//                string soapRequest = CreateSoapRequest();
//                byte[] requestBytes = Encoding.UTF8.GetBytes(soapRequest);
//                await udpClient.SendAsync(requestBytes, requestBytes.Length, multicastEP);

//                var endpoint = new IPEndPoint(IPAddress.Any, ONVIF_PORT);
//                udpClient.Client.ReceiveTimeout = (int)DISCOVERY_TIMEOUT.TotalMilliseconds;

//                try
//                {
//                    DateTime startTime = DateTime.UtcNow;
//                    while (DateTime.UtcNow - startTime < DISCOVERY_TIMEOUT)
//                    {
//                        var receiveTask = udpClient.ReceiveAsync();
//                        var completedTask = await Task.WhenAny(receiveTask, Task.Delay(100));

//                        if (completedTask == receiveTask) // Antwort erhalten
//                        {
//                            UdpReceiveResult result = receiveTask.Result;
//                            string response = Encoding.UTF8.GetString(result.Buffer);
//                            var cameraInfo = ParseONVIFResponse(response);

//                            if (cameraInfo != null && !discoveredCameras.Any(d => d.UUID == cameraInfo.UUID))
//                            {
//                                discoveredCameras.Add(cameraInfo);

//                                IPToScan ipToScan = new IPToScan
//                                {
//                                    UsedScanMethod = ScanMethod.ONVIF_IPCam,
//                                    IsIPCam = true,
//                                    IPorHostname = cameraInfo.IPv4Address,
//                                    IPCamName = cameraInfo.Name,
//                                    IPCamXAddress = cameraInfo.XAddress.Replace("/onvif/device_service", string.Empty)
//                                };

//                                ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs
//                                {
//                                    ipToScan = ipToScan
//                                };

//                                Application.Current.Dispatcher.Invoke(() =>
//                                {
//                                    newIPCameraFound_Task_Finished?.Invoke(this, scanTask_Finished);
//                                });
//                            }
//                        }
//                    }
//                }
//                catch (SocketException) { }
//                finally
//                {
//                    Application.Current.Dispatcher.Invoke(() =>
//                    {
//                        IPCameraScan_Finished?.Invoke(this, new Method_Finished_EventArgs());
//                    });
//                }
//            }
//        }

//        private string CreateSoapRequest()
//        {
//            Guid messageId = Guid.NewGuid();
//            const string soap = @"
//            <?xml version=""1.0"" encoding=""UTF-8""?>
//            <e:Envelope xmlns:e=""http://www.w3.org/2003/05/soap-envelope""
//            xmlns:w=""http://schemas.xmlsoap.org/ws/2004/08/addressing""
//            xmlns:d=""http://schemas.xmlsoap.org/ws/2005/04/discovery""
//            xmlns:dn=""http://www.onvif.org/ver10/device/wsdl"">
//            <e:Header>
//            <w:MessageID>uuid:{0}</w:MessageID>
//            <w:To e:mustUnderstand=""true"">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
//            <w:Action e:mustUnderstand=""true"">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
//            </e:Header>
//            <e:Body>
//            <d:Probe>
//            <d:Types>dn:Device</d:Types>
//            </d:Probe>
//            </e:Body>
//            </e:Envelope>
//            ";

//            return string.Format(soap, messageId);
//        }

//        private IPCamInfos? ParseONVIFResponse(string soapMessage)
//        {
//            try
//            {
//                XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(new NameTable());
//                xmlNamespaceManager.AddNamespace("wsa", "http://schemas.xmlsoap.org/ws/2004/08/addressing");
//                xmlNamespaceManager.AddNamespace("wsdd", "http://schemas.xmlsoap.org/ws/2005/04/discovery");

//                XElement xelement = XElement.Parse(soapMessage);
//                var UUID = xelement.XPathSelectElement("//wsa:Address[1]", xmlNamespaceManager);
//                var XAddrs = xelement.XPathSelectElement("//wsdd:XAddrs[1]", xmlNamespaceManager);
//                var Scopes = xelement.XPathSelectElement("//wsdd:Scopes[1]", xmlNamespaceManager);
//                var MetadataVersion = xelement.XPathSelectElement("//wsdd:MetadataVersion[1]", xmlNamespaceManager);

//                if (UUID == null || XAddrs == null || Scopes == null || MetadataVersion == null)
//                    return null;

//                string Address = XAddrs.Value.Replace("http://", string.Empty);
//                string IPv4Address = Address.Remove(Address.IndexOf("/")).Split(":")[0];
//                string Port = Address.Remove(Address.IndexOf("/")).Split(":")[1];

//                List<string> lst_Scopes = Scopes.Value.Split(' ').ToList();
//                string name = lst_Scopes.FirstOrDefault(i => i.Contains("/name/"))?.Split('/').Last() ?? "Unknown";
//                string hardware = lst_Scopes.FirstOrDefault(i => i.Contains("/hardware/"))?.Split('/').Last() ?? "Unknown";
//                string location = lst_Scopes.FirstOrDefault(i => i.Contains("/location/"))?.Split('/').Last() ?? "Unknown";

//                return new IPCamInfos
//                {
//                    IPv4Address = IPv4Address,
//                    Port = Port,
//                    Name = name,
//                    Hardware = hardware,
//                    Location = location,
//                    MetaVersion = MetadataVersion.Value,
//                    UUID = UUID.Value.Split(':').Last(),
//                    XAddress = XAddrs.Value
//                };
//            }
//            catch (Exception ex)
//            {
//                Console.WriteLine($"⚠ Fehler beim Parsen der ONVIF-Kamera-Antwort: {ex.Message}");
//                return null;
//            }
//        }
//    }

//    public class IPCamInfos
//    {
//        public string IPv4Address { get; set; }
//        public string Port { get; set; }
//        public string Name { get; set; }
//        public string Hardware { get; set; }
//        public string Location { get; set; }
//        public string MetaVersion { get; set; }
//        public string UUID { get; set; }
//        public string XAddress { get; set; }
//    }
//}






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

        public event EventHandler<ScanTask_Finished_EventArgs>? new_ONVIF_IP_Camera_Found_Task_Finished;
        public event EventHandler<Method_Finished_EventArgs>? ONVIF_IP_Camera_Scan_Finished;


        public event Action<int, int, int> ProgressUpdated;    

        private int current = 0;
        private int responded = 0;
        private int total = 0;


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






        //public async void Discover(List<IPToScan> IPs)
        //{
        //    List<IPCamInfos> discoveredCameras = new List<IPCamInfos>();
        //    string soapRequest = CreateSoapRequest();
        //    byte[] requestBytes = Encoding.UTF8.GetBytes(soapRequest); // 📌 **Hier außerhalb definiert!**

        //    using (UdpClient udpClient = new UdpClient())
        //    {
        //        udpClient.EnableBroadcast = true;
        //        udpClient.MulticastLoopback = false;
        //        IPEndPoint multicastEP = new IPEndPoint(IPAddress.Parse(ONVIF_MULTICAST_IP), ONVIF_PORT);

        //        // Mehrfache Multicast-Anfragen senden (3 Versuche mit Pause)
        //        for (int i = 0; i < 3; i++)
        //        {
        //            await udpClient.SendAsync(requestBytes, requestBytes.Length, multicastEP);
        //            await Task.Delay(500); // 500ms Pause zwischen den Anfragen
        //        }

        //        var endpoint = new IPEndPoint(IPAddress.Any, ONVIF_PORT);
        //        udpClient.Client.ReceiveTimeout = 5000; // 📌 5 Sekunden Empfangszeit

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
        //                            IPCamName = cameraInfo.Name,
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

        //    // **📌 Unicast-Fallback (falls Multicast nicht alle Geräte erreicht)**
        //    foreach (var ipToScan in IPs)
        //    {
        //        using (UdpClient unicastClient = new UdpClient())
        //        {
        //            IPEndPoint unicastEP = new IPEndPoint(IPAddress.Parse(ipToScan.IPorHostname), ONVIF_PORT);
        //            await unicastClient.SendAsync(requestBytes, requestBytes.Length, unicastEP);
        //        }
        //    }
        //}

     

        public async void Discover(List<IPToScan> IPs)
        {
            List<IPCamInfos> discoveredCameras = new List<IPCamInfos>();
            string soapRequest = CreateSoapRequest();
            byte[] requestBytes = Encoding.UTF8.GetBytes(soapRequest);

           

                using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                    socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, true);
                    socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 2);

                //IPEndPoint localEndPoint = new IPEndPoint(IPAddress.Any, ONVIF_PORT);
                IPEndPoint localEndPoint = new IPEndPoint(SupportMethods.SelectedNetworkInterfaceInfos.IPv4, ONVIF_PORT);
                try
                {
                    socket.Bind(localEndPoint);
                }
                catch 
                {
                    Application.Current.Dispatcher.Invoke(() =>
                    {
                        ONVIF_IP_Camera_Scan_Finished?.Invoke(this, new Method_Finished_EventArgs() { ScanStatus = MainWindow.ScanStatus.wrongNetworkInterfaceSelected});
                    });
                    return;
                }
                    IPEndPoint multicastEP = new IPEndPoint(IPAddress.Parse(ONVIF_MULTICAST_IP), ONVIF_PORT);

                    // Mehrfache Multicast-Anfragen senden (3 Versuche mit Pause)
                    for (int i = 0; i < 3; i++)
                    {
                        socket.SendTo(requestBytes, multicastEP);
                        await Task.Delay(500); // 500 ms Pause zwischen den Anfragen
                    }

                    Console.WriteLine("📡 Multicast-Anfragen gesendet... Warte auf Antworten...");

                    DateTime startTime = DateTime.UtcNow;
                    int discoveryTimeoutMs = 5000;

                    try
                    {
                        while ((DateTime.UtcNow - startTime).TotalMilliseconds < discoveryTimeoutMs)
                        {
                            if (socket.Poll(100000, SelectMode.SelectRead))  // 100 ms warten, ob Daten verfügbar sind
                            {
                                byte[] buffer = new byte[2048];
                                EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
                                int receivedBytes = socket.ReceiveFrom(buffer, ref remoteEndPoint);

                                if (receivedBytes > 0)
                                {
                                    string response = Encoding.UTF8.GetString(buffer, 0, receivedBytes);
                                    var cameraInfo = await ParseONVIFResponseAsync(response, ((IPEndPoint)remoteEndPoint).Address.ToString());

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

                                        // Event im UI-Thread aufrufen
                                        Application.Current.Dispatcher.Invoke(() =>
                                        {
                                            new_ONVIF_IP_Camera_Found_Task_Finished?.Invoke(this, scanTask_Finished);
                                        });

                                        int respondedValue = Interlocked.Increment(ref responded);
                                        ProgressUpdated?.Invoke(current, responded, total);
                                    }
                                }
                            }
                            await Task.Delay(100);  // CPU-Last reduzieren
                        }
                    }
                    catch (SocketException ex)
                    {
                        Console.WriteLine($"⚠ Fehler beim Empfang: {ex.Message}");
                    }
                    finally
                    {
                        Application.Current.Dispatcher.Invoke(() =>
                        {
                            ONVIF_IP_Camera_Scan_Finished?.Invoke(this, new Method_Finished_EventArgs() { ScanStatus = MainWindow.ScanStatus.finished});
                        });
                    }
                }
           

            // **Unicast-Fallback (falls Multicast nicht alle Geräte erreicht)**
            foreach (var ipToScan in IPs)
            {
                using (Socket unicastSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    IPEndPoint unicastEP = new IPEndPoint(IPAddress.Parse(ipToScan.IPorHostname), ONVIF_PORT);
                    unicastSocket.SendTo(requestBytes, unicastEP);
                }
            }
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
