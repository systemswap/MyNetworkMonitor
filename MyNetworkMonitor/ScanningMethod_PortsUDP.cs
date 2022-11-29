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
            List<IPEndPoint> endpoints = IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners().ToList();


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
                if (UDPPortScan_Task_Finished != null) UDPPortScan_Task_Finished(this, new UDPPortScan_Task_FinishedEventArgs(devicePorts));
            }
            return openPorts;
        }














        public async void ScanUDPPorts(List<string> IPs)
        {
            var tasks = new List<Task>();

            foreach (var ip in IPs)
            {
                var task = ScanUDPPorts_Task(ip, new PortCollection().UDPPorts);
                tasks.Add(task);
            }

            await Task.WhenAll(tasks);

            if (UDPPortScan_Finished != null) UDPPortScan_Finished(this, new UDPPortScan_Finished_EventArgs(true));
        }

        public async void ScanUDPPorts(List<string> IPs, List<int> UDP_Ports)
        {
            var tasks = new List<Task>();

            foreach (var ip in IPs)
            {
                var task = ScanUDPPorts_Task(ip, UDP_Ports);
                tasks.Add(task);
            }

            await Task.WhenAll(tasks);

            if (UDPPortScan_Finished != null) UDPPortScan_Finished(this, new UDPPortScan_Finished_EventArgs(true));
        }

        private async Task ScanUDPPorts_Task(string IP, List<int> Ports)
        {
            List<int> _UDPPorts = new List<int>();

            OpenPorts openPorts = new OpenPorts();

            openPorts.IP = IP;

            var tasks = new List<Task>();

            Parallel.ForEach(Ports, port =>
            {
                var task = ScanUDP_Port(IP, port);
                if (task.Result != -1) _UDPPorts.Add(task.Result);
                tasks.Add(task);
            });

            await Task.WhenAll(tasks);
            _UDPPorts.Sort();
            openPorts.Ports = _UDPPorts;

            if (UDPPortScan_Task_Finished != null) UDPPortScan_Task_Finished(this, new UDPPortScan_Task_FinishedEventArgs(openPorts));
        }


        UdpClient udp_clnt;
        private async Task<int> ScanUDP_Port(string IP, int port)
        {
            try
            {

                // This constructor arbitrarily assigns the local port number.
                UdpClient udpClient = new UdpClient(port);
                try
                {
                    udpClient.Connect(IP, port);

                    // Sends a message to the host to which you have connected.
                    Byte[] sendBytes = Encoding.ASCII.GetBytes("Is anybody there?");

                    udpClient.Send(sendBytes, sendBytes.Length);

                    //IPEndPoint object will allow us to read datagrams sent from any source.
                    IPEndPoint RemoteIpEndPoint = new IPEndPoint(IPAddress.Any, 0);

                    // Blocks until a message returns on this socket from a remote host.
                    Byte[] receiveBytes = udpClient.Receive(ref RemoteIpEndPoint);
                    string returnData = Encoding.ASCII.GetString(receiveBytes);

                    // Uses the IPEndPoint object to determine which of these two hosts responded.
                    Debug.WriteLine("This is the message you received " +
                                                 returnData.ToString());
                    Debug.WriteLine("This message was sent from " +
                                                RemoteIpEndPoint.Address.ToString() +
                                                " on their port number " +
                                                RemoteIpEndPoint.Port.ToString());

                    udpClient.Close();
                    //udpClientB.Close();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.ToString());
                }


            }
            catch (Exception e)
            {
                Debug.WriteLine($"Error Port: {port} {e.Message}");
            }
            return -1;
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
    public UDPPortScan_Finished_EventArgs(bool Finished)
    {
        _finished = Finished;
    }
    private bool _finished = false;
    public bool Finished { get { return _finished; } }

}
