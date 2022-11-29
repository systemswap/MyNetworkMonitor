using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    class ScanningMethod_UDP_Port
    {

        public void GetUDPListener(int startPort, int endPort)
        {
            var startingAtPort = 5000;
            var maxNumberOfPortsToCheck = 500;
            var range = Enumerable.Range(startingAtPort, maxNumberOfPortsToCheck);
            var portsInUse =
                from p in range
                join used in System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners()
            on p equals used.Port
                select p;

            var FirstFreeUDPPortInRange = range.Except(portsInUse).FirstOrDefault();

            if (FirstFreeUDPPortInRange > 0)
            {
                // do stuff
                Console.WriteLine(FirstFreeUDPPortInRange);
            }
            else
            {
                // complain about lack of free ports?
            }
        }

        public bool IsUDPPortInUse(int Port)
        {
            return IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners().Any(p => p.Port == Port);
        }

        public List<IPEndPoint> GetUPDPortListener(int Port)
        {
            return IPGlobalProperties.GetIPGlobalProperties().GetActiveUdpListeners().ToList();            
        }
    }
}
