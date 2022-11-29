using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    internal class ScanningMethod_PortsExample
    {
        public bool IsPortOpen(string host_or_ip, int port, TimeSpan timeout)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    var result = client.BeginConnect(host_or_ip, port, null, null);
                    var success = result.AsyncWaitHandle.WaitOne(timeout);
                    client.EndConnect(result);
                    return success;
                }
            }
            catch
            {
                return false;
            }
        }



    }
}
