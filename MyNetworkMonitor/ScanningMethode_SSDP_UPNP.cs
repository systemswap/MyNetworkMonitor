using Rssdp;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    internal class ScanningMethode_SSDP_UPNP
    {
        public ScanningMethode_SSDP_UPNP()
        {
            
        }       

        public event EventHandler<SSDP_Scan_FinishedEventArgs>? SSDP_Scan_Finished;
        public event EventHandler<SSDP_Device_EventArgs>? SSDP_NewDevice;

        public async void ScanForSSDP()
        {
            using (var deviceLocator = new SsdpDeviceLocator())
            {
                var foundDevices = await deviceLocator.SearchAsync();

                List<string> _ips = new List<string>();

                foreach (var foundDevice in foundDevices)
                {
                    string deviceIP = foundDevice.DescriptionLocation.Host;
                    if (SSDP_NewDevice != null && !_ips.Contains(deviceIP))
                    {
                        _ips.Add(deviceIP);
                        SSDP_NewDevice(this, new SSDP_Device_EventArgs(true, deviceIP));
                    }
                }
            }

            if (SSDP_Scan_Finished != null)
            {                
                SSDP_Scan_Finished(this, new SSDP_Scan_FinishedEventArgs(true));
            }
        }
    }

    public class SSDP_Device_EventArgs : EventArgs
    {
        public SSDP_Device_EventArgs(bool SSDPStatus, string IP)
        {
            _SSDPStatus = SSDPStatus;
            _IP = IP;
        }
        private bool _SSDPStatus = false;
        public bool SSDPStatus { get { return _SSDPStatus; } }

        private string _IP = string.Empty;
        public string IP { get { return _IP; } }
    }

    public class SSDP_Scan_FinishedEventArgs : EventArgs
    {
        public SSDP_Scan_FinishedEventArgs(bool finished)
        {
            _finished = finished;
        }

        private bool _finished = false;
        public bool SSDP_Scan_Finished { get { return _finished; } }
    }
}
