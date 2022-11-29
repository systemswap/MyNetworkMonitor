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

namespace MyNetworkMonitor
{
    class ScanningMethod_PortsUDP
    {
        public ScanningMethod_PortsUDP()
        {

        }

        public event EventHandler<UDPPortScan_Task_FinishedEventArgs>? UDPPortScan_Task_Finished;
        public event EventHandler<UDPPortScan_Finished_EventArgs>? UDPPortScan_Finished;

      

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


        public List<OpenPorts> Get_All_UPD_Listener_as_List()
        {
            List<OpenPorts> openPorts = new List<OpenPorts>();
            List<IPEndPoint> endpoints = Task.Run(() => IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners().ToList()).Result;


            var bla = endpoints.GroupBy(s => s.Address).ToList();
            foreach (var item in bla)
            {
                OpenPorts devicePorts = new OpenPorts();
                devicePorts.IP = item.Key.ToString();

                foreach (var ep in item)
                {

                    devicePorts.Ports.Add(ep.Port);
                }
                openPorts.Add(devicePorts);
                if (UDPPortScan_Task_Finished != null)
                {
                    if (new SupportMethods().Is_Valid_IP(devicePorts.IP)) UDPPortScan_Task_Finished(this, new UDPPortScan_Task_FinishedEventArgs(devicePorts));
                }
                        
            }

            if (UDPPortScan_Finished != null) UDPPortScan_Finished(this, new UDPPortScan_Finished_EventArgs(true, bla.Count));

            return openPorts;
        }        
    }
}


public class OpenPorts
{
    public string IP = string.Empty;
    public List<int> Ports = new List<int>();
}



//######## Events ###############
public class UDPPortScan_Task_FinishedEventArgs : EventArgs
{
    public UDPPortScan_Task_FinishedEventArgs(OpenPorts openPorts)
    {
        _OpenPorts = openPorts;
    }

    private OpenPorts _OpenPorts;
    public OpenPorts OpenPorts { get { return _OpenPorts; } }
}

public class UDPPortScan_Finished_EventArgs : EventArgs
{
    public UDPPortScan_Finished_EventArgs(bool Finished, int UDPListener)
    {
        _finished = Finished;
        _listener = UDPListener;
    }
    private bool _finished = false;
    public bool Finished { get { return _finished; } }

    private int _listener = 0;
    public int UDPListener
    {
        get { return _listener; }
    }

}
