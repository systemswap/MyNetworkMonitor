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
        public ScanningMethode_SSDP_UPNP(ScanResults scanResults)
        {
            _scannResults = scanResults;
        }

        ScanResults _scannResults;

        public event EventHandler<SSDP_Scan_FinishedEventArgs>? CustomEvent_SSDP_Scan_Finished;

        public async void ScanForSSDP()
        {
            using (var deviceLocator = new SsdpDeviceLocator())
            {
                var foundDevices = await deviceLocator.SearchAsync();

                foreach (var foundDevice in foundDevices)
                {
                    DataRow row = _scannResults.ResultTable.NewRow();
                    List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + foundDevice.DescriptionLocation.Host + "'").ToList();

                    if (rows.Count() == 0)
                    {
                        row["SendAlert"] = false;
                        row["SSDP"] = Properties.Resources.green_dot;
                        row["IP"] = foundDevice.DescriptionLocation.Host;
                        row["ResponseTime"] = "";

                        _scannResults.ResultTable.Rows.Add(row);
                    }
                    else
                    {
                        int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);
                        _scannResults.ResultTable.Rows[rowIndex]["SSDP"] = Properties.Resources.green_dot;
                    }
                }
            }

            if (CustomEvent_SSDP_Scan_Finished != null)
            {
                //the User Gui can be freeze if a event fires to fast
                CustomEvent_SSDP_Scan_Finished(this, new SSDP_Scan_FinishedEventArgs(true));
            }
        }

      
    }

    public class SSDP_Scan_FinishedEventArgs : EventArgs
    {
        private bool _finished = false;
        public bool SSDP_Scan_Finished { get { return _finished; } }
        public SSDP_Scan_FinishedEventArgs(bool finished)
        {
            _finished = finished;
        }
    }
}
