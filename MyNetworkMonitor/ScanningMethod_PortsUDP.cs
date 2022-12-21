using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using static MyNetworkMonitor.ScanningMethod_PortsTCP;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace MyNetworkMonitor
{
    class ScanningMethod_PortsUDP
    {
        public ScanningMethod_PortsUDP()
        {

        }

        public event EventHandler<ScanTask_Finished_EventArgs>? UDPPortScan_Task_Finished;
        public event EventHandler<Method_Finished_EventArgs>? UDPPortScan_Finished;



        public void Get_UDP_Listener_In_Port_Range(int startPort, int endPort)
        {
            var startingAtPort = startPort;
            var maxNumberOfPortsToCheck = endPort;
            var range = Enumerable.Range(startingAtPort, maxNumberOfPortsToCheck);
            var portsInUse =
                from p in range
                join used in System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners()
            on p equals used.Port
                select p;

            var FirstFreeUDPPortInRange = range.Except(portsInUse).FirstOrDefault();
        }

        public bool Is_UDP_Port_In_Use(int Port)
        {
            return IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners().Any(p => p.Port == Port);
        }

        public List<IPEndPoint> Get_All_UPD_Listener()
        {
            return IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners().ToList();
        }


        public void Get_All_UPD_Listener_as_List(List<IPToScan> IPs)
        {
            List<IPEndPoint> endpoints = Task.Run(() => IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners().ToList()).Result;
            List<System.Linq.IGrouping<System.Net.IPAddress, System.Net.IPEndPoint>> groupedIPEndpoints = endpoints.GroupBy(s => s.Address).ToList();

            foreach (var item in groupedIPEndpoints)
            {
                IPToScan ipToScan;
                string ip = item.Key.ToString();
                try
                {
                    ipToScan = IPs.Where(i => string.Equals(i.IP, ip)).ToList()[0];
                    ipToScan.SSDPStatus = true;
                }
                catch (Exception)
                {
                    ipToScan = new IPToScan();
                    ipToScan.IPGroupDescription = "not specified";
                    ipToScan.DeviceDescription = "not specified";
                    ipToScan.IP = ip;

                    ipToScan.ARPStatus = true;
                }

                foreach (var ep in item)
                {
                    ipToScan.UDP_OpenPorts.Add(ep.Port);
                }

                ipToScan.UDP_ListenerFound = groupedIPEndpoints.Count;

                if (UDPPortScan_Task_Finished != null)
                {
                    ipToScan.UsedScanMethod = ScanMethod.UDPPorts;

                    ScanTask_Finished_EventArgs scanTask_Finished = new ScanTask_Finished_EventArgs();
                    scanTask_Finished.ipToScan = ipToScan;

                    if (new SupportMethods().Is_Valid_IP(scanTask_Finished.ipToScan.IP)) UDPPortScan_Task_Finished(this, scanTask_Finished);
                }
            }

            if (UDPPortScan_Finished != null) UDPPortScan_Finished(this, new Method_Finished_EventArgs());
        }
    }
}