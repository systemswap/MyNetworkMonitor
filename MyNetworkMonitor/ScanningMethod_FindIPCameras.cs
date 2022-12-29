using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Net.Mail;
using System.Windows.Threading;
using System.Net.NetworkInformation;
using System.Xml.Linq;
using System.Xml;
using System.Xml.XPath;
using OnvifDiscovery;
using System.Threading;
using OnvifDiscovery.Models;

namespace MyNetworkMonitor
{
    internal class ScanningMethod_FindIPCameras
    {
        public ScanningMethod_FindIPCameras() { }

        public event EventHandler<ScanTask_Finished_EventArgs>? newIPCameraFound_Task_Finished;
        public event EventHandler<Method_Finished_EventArgs>? IPCameraScan_Finished;

        List<IPToScan> _IPs = new List<IPToScan>();
    public void Discover(List<IPToScan> IPs)
        {
            _IPs = IPs;
            // Create a Discovery instance
            var onvifDiscovery = new Discovery();

            // You can call Discover with a callback (Action) and CancellationToken
            CancellationTokenSource cancellation = new CancellationTokenSource();
            Task.Run(() => onvifDiscovery.Discover(5, OnNewDevice, cancellation.Token));
        }

        private void OnNewDevice(DiscoveryDevice device)
        {
            IPToScan ipToScan = new IPToScan();

            ipToScan.UsedScanMethod = ScanMethod.FindIPCameras;
            ipToScan.IsIPCam = true;
            ipToScan.IPorHostname = device.Address;
            ipToScan.IPCamName = device.Mfr;

            ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs();
            scanTask_Finished.ipToScan = ipToScan;

            newIPCameraFound_Task_Finished(this, scanTask_Finished);
        }
        public async Task<List<string>> GetSoapResponsesFromCamerasAsync(IPAddress IPForBroadcast, List<IPToScan> IPs)
        {
            var result = new List<string>();

            using (var client = new UdpClient())
            {
                var ipEndpoint = new IPEndPoint(IPForBroadcast, 3702);
                client.EnableBroadcast = true;
                try
                {
                    var soapMessage = GetBytes(CreateSoapRequest());
                    var timeout = DateTime.Now.AddSeconds(3);
                    await client.SendAsync(soapMessage, soapMessage.Length, ipEndpoint);

                    while (timeout > DateTime.Now)
                    {
                        if (client.Available > 0)
                        {
                            var receiveResult = await client.ReceiveAsync();
                            var text = GetText(receiveResult.Buffer);
                            result.Add(text);
                        }
                        else
                        {
                            await Task.Delay(10);
                        }
                    }
                }
                catch (Exception exception)
                {
                    Console.WriteLine(exception.Message);
                }
            }
            return result;
        }

        private string CreateSoapRequest()
        {
            Guid messageId = Guid.NewGuid();
            const string soap = @"
            <?xml version=""1.0"" encoding=""UTF-8""?>
            <e:Envelope xmlns:e=""http://www.w3.org/2003/05/soap-envelope""
            xmlns:w=""http://schemas.xmlsoap.org/ws/2004/08/addressing""
            xmlns:d=""http://schemas.xmlsoap.org/ws/2005/04/discovery""
            xmlns:dn=""http://www.onvif.org/ver10/device/wsdl"">
            <e:Header>
            <w:MessageID>uuid:{0}</w:MessageID>
            <w:To e:mustUnderstand=""true"">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
            <w:Action a:mustUnderstand=""true"">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
            </e:Header>
            <e:Body>
            <d:Probe>
            <d:Types>dn:Device</d:Types>
            </d:Probe>
            </e:Body>
            </e:Envelope>
            ";

            var result = string.Format(soap, messageId);
            return result;
        }

        private byte[] GetBytes(string text)
        {
            return Encoding.ASCII.GetBytes(text);
        }

        private string GetText(byte[] bytes)
        {
            return Encoding.ASCII.GetString(bytes, 0, bytes.Length);
        }

        private string GetAddress(string soapMessage)
        {
            var xmlNamespaceManager = new XmlNamespaceManager(new NameTable());
            xmlNamespaceManager.AddNamespace("g", "http://schemas.xmlsoap.org/ws/2005/04/discovery");

            var element = XElement.Parse(soapMessage).XPathSelectElement("//g:XAddrs[1]", xmlNamespaceManager);
            return element?.Value ?? string.Empty;
        }

    }
}
