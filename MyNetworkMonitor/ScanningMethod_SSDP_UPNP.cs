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

        //public event EventHandler<SSDP_Device_EventArgs>? SSDP_NewDevice;
        public event EventHandler<ScanTask_Finished_EventArgs>? SSDP_foundNewDevice;

        //public event EventHandler<SSDP_Scan_FinishedEventArgs>? SSDP_Scan_Finished;
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


                        
                        
                        //try
                        //{
                        //    scanTask_Finished.ipToScan.IPGroupDescription = IPs.Where(i => string.Equals(i.IP, deviceIP)).Select(i => i.IPGroupDescription).ToList()[0];
                        //    scanTask_Finished.ipToScan.DeviceDescription = IPs.Where(i => string.Equals(i.IP, deviceIP)).Select(i => i.DeviceDescription).ToList()[0];
                        //    //scanTask_Finished.ipToScan.DNSServers = string.Join(',', IPs.Where(i => string.Equals(i.IP, deviceIP)).Select(i => i.DNSServerList).ToList());
                        //    scanTask_Finished.ipToScan.DNSServerList = IPs.Where(i => string.Equals(i.IP, deviceIP)).Select(i => i.DNSServerList).ToList()[0];
                        //}
                        //catch (Exception)
                        //{
                        //    scanTask_Finished.ipToScan.IPGroupDescription = "not specified";
                        //    scanTask_Finished.ipToScan.DeviceDescription = "not specified";
                        //}

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

                            ipToScan.ARPStatus = true;
                        }

                        

                        //SSDP_NewDevice(this, new SSDP_Device_EventArgs(true, deviceIP));

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

    //public class SSDP_Device_EventArgs : EventArgs
    //{
    //    public SSDP_Device_EventArgs(bool SSDPStatus, string IP)
    //    {
    //        _SSDPStatus = SSDPStatus;
    //        _IP = IP;
    //    }
    //    private bool _SSDPStatus = false;
    //    public bool SSDPStatus { get { return _SSDPStatus; } }

    //    private string _IP = string.Empty;
    //    public string IP { get { return _IP; } }
    //}

    //public class SSDP_Scan_FinishedEventArgs : EventArgs
    //{
    //    public SSDP_Scan_FinishedEventArgs(bool finished)
    //    {
    //        _finished = finished;
    //    }

    //    private bool _finished = false;
    //    public bool SSDP_Scan_Finished { get { return _finished; } }
    //}
}
