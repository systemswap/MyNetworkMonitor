using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace MyNetworkMonitor
{
    internal class ScanningMethods_Ping
    {
        public ScanningMethods_Ping(ScanResults scanResults)
        {
            _scannResults = scanResults;
        }

        ScanResults _scannResults;

        public event EventHandler<PingFinishedEventArgs>? CustomEvent_PingFinished;
        public event EventHandler<PingProgressEventArgs>? CustomEvent_PingProgress;
               

        /// <summary>
        /// to get the Ping result call the Propertie PingResults
        /// </summary>
        /// <param name="IPs"></param>
        /// <param name="DNS_Server_IP"></param>
        public async void PingIPsAsync(List<string> IPs, string DNS_Server_IP, int Timeout, bool ShowUnused = true)
        {
            var tasks = new List<Task>();

            foreach (var ip in IPs)
            {
                System.Net.NetworkInformation.Ping p = new System.Net.NetworkInformation.Ping();
                var task = PingTask(p, ip, Timeout, ShowUnused);
                tasks.Add(task);
            }
            //await Task.WhenAll(tasks).ContinueWith(_ => 
            //{
            //    if (CustomEvent_PingFinished != null)
            //    {
            //        //the User Gui can be freeze if a event fires to fast
            //        CustomEvent_PingFinished(this, new PingFinishedEventArgs(_scannResults.ResultTable));
            //    }
            //});

            await Task.WhenAll(tasks);
            if (CustomEvent_PingFinished != null)
            {
                //the User Gui can be freeze if a event fires to fast
                CustomEvent_PingFinished(this, new PingFinishedEventArgs(_scannResults.ResultTable));
            }
        }

        private async Task PingTask(Ping ping, string ip, int TimeOut, bool ShowUnused)
        {
            PingReply reply = await ping.SendPingAsync(ip, TimeOut);
            DataRow row = _scannResults.ResultTable.NewRow();

            row["SendAlert"] = false;

            if (reply.Status == IPStatus.Success)
            {
                row["Ping"] = Properties.Resources.green_dot;
                row["IP"] = reply.Address.ToString();
                
                row["ResponseTime"] = reply.RoundtripTime.ToString();

                List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + reply.Address.ToString() + "'").ToList();

                if (rows.Count == 0)
                {
                    _scannResults.ResultTable.Rows.Add(row);
                }
                else
                {
                    int rowIndex = _scannResults.ResultTable.Rows.IndexOf(rows[0]);
                    _scannResults.ResultTable.Rows[rowIndex]["Ping"] = Properties.Resources.green_dot;
                    _scannResults.ResultTable.Rows[rowIndex]["IP"] = reply.Address.ToString();

                    _scannResults.ResultTable.Rows[_scannResults.ResultTable.Rows.IndexOf(rows[0])]["ResponseTime"] = reply.RoundtripTime.ToString();
                }
                
            }
            else if (ShowUnused && reply.Status != IPStatus.Success)
            {
                row["Ping"] = Properties.Resources.red_dot;
                row["IP"] = ip;
                row["ResponseTime"] = string.Empty;

                List<DataRow> rows = _scannResults.ResultTable.Select("IP = '" + reply.Address.ToString() + "'").ToList();

                if (rows.Count == 0)
                {
                    _scannResults.ResultTable.Rows.Add(row);
                }
                else
                {
                    _scannResults.ResultTable.Rows[_scannResults.ResultTable.Rows.IndexOf(rows[0])]["Ping"] = Properties.Resources.red_dot;
                    _scannResults.ResultTable.Rows[_scannResults.ResultTable.Rows.IndexOf(rows[0])]["IP"] = ip;
                    _scannResults.ResultTable.Rows[_scannResults.ResultTable.Rows.IndexOf(rows[0])]["ResponseTime"] = string.Empty;
                }
            }

            if (CustomEvent_PingProgress != null)
            {
                //the User Gui can be freeze if a event fires to fast
                CustomEvent_PingProgress(this, new PingProgressEventArgs(row));
            }
        }       
    }


    /* ############# Events #################*/

    public class PingFinishedEventArgs : EventArgs
    {
        private DataTable _dt = new DataTable();
        public DataTable PingResults { get { return _dt; } }
        public PingFinishedEventArgs(DataTable PingResults)
        {
            _dt = PingResults;
        }
    }


    public class PingProgressEventArgs : EventArgs
    {
        private DataRow _row = new ScanResults().ResultTable.NewRow();
        public DataRow PingResultsRow { get { return _row; } }
        public PingProgressEventArgs(DataRow Row)
        {
            _row = Row;
        }
    }
}
