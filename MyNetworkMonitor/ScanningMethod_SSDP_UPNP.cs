using Rssdp;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    internal class ScanningMethod_SSDP_UPNP
    {
        public ScanningMethod_SSDP_UPNP()
        {

        }

        public event EventHandler<ScanTask_Finished_EventArgs>? SSDP_foundNewDevice;
        public event EventHandler<Method_Finished_EventArgs>? SSDP_Scan_Finished;


        public async void ScanForSSDP(List<IPToScan> IPs)
        {
            using (var deviceLocator = new SsdpDeviceLocator())
            {
                var foundDevices = await deviceLocator.SearchAsync();

                List<string> _ips = new List<string>();

                foreach (var foundDevice in foundDevices)
                {
                    string deviceIP = foundDevice.DescriptionLocation.Host;
                    if (SSDP_foundNewDevice != null && !_ips.Contains(deviceIP))
                    {
                        //need to check for duplicates
                        _ips.Add(deviceIP);

                        IPToScan ipToScan;
                        try
                        {
                            ipToScan = IPs.Where(i => string.Equals(i.IP, deviceIP)).ToList()[0];
                            ipToScan.SSDPStatus = true;
                        }
                        catch (Exception)
                        {
                            ipToScan = new IPToScan();
                            ipToScan.IPGroupDescription = "not specified";
                            ipToScan.DeviceDescription = "not specified";
                            ipToScan.IP = deviceIP;

                            ipToScan.SSDPStatus = true;
                        }

                        ipToScan.UsedScanMethod = ScanMethod.SSDP;

                        ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs();
                        scanTask_Finished.ipToScan = ipToScan;

                        SSDP_foundNewDevice(this, scanTask_Finished);
                    }
                }
            }

            if (SSDP_Scan_Finished != null)
            {
                SSDP_Scan_Finished(this, new Method_Finished_EventArgs());
            }
        }
    }
}