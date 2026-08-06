using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace MyNetworkMonitor
{
    public class ScanTask_Finished_EventArgs : EventArgs
    {
        private IPToScan _ipToScan = new IPToScan();
        public IPToScan ipToScan { get { return _ipToScan; } set { _ipToScan = value; } }       
    }
}
