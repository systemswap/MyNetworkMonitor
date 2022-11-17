using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;
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
        public ScanningMethods_Ping()
        {
            dt_NetworkResults.Columns.Add("SSDP", typeof(byte[]));
            dt_NetworkResults.Columns.Add("Ping", typeof(byte[]));
            dt_NetworkResults.Columns.Add("SendAlert", typeof(bool));
            dt_NetworkResults.Columns.Add("IP", typeof(string));
            dt_NetworkResults.Columns.Add("Hostname", typeof(string));
            dt_NetworkResults.Columns.Add("ResponseTime", typeof(string));
            dt_NetworkResults.Columns.Add("Ports", typeof(string));
            dt_NetworkResults.Columns.Add("Comment", typeof(string));
            dt_NetworkResults.Columns.Add("Mac", typeof(string));
            dt_NetworkResults.Columns.Add("Vendor", typeof(string));
            dt_NetworkResults.Columns.Add("Exception", typeof(string));            

        }

        // in .Net Core above need the Install of this nuget Package: Install-Package System.Drawing.Common
  

        DataTable dt_NetworkResults = new DataTable();

        List<PingReply> pingReply = new List<PingReply>();

        public event EventHandler<PingFinishedEventArgs>? CustomEvent_PingFinished;
        public event EventHandler<PingProgressEventArgs>? CustomEvent_PingProgress;

        private List<PingReply> PingResults
        {
            get { return pingReply; }
        }

        public DataTable NetworkResultsTable
        {
            get { return dt_NetworkResults; }
        }

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
                var task = PingAndUpdateAsync(p, ip, Timeout, ShowUnused);
                tasks.Add(task);
            }           
            await Task.WhenAll(tasks);

            if (CustomEvent_PingFinished != null)
            {
                //the User Gui can be freeze if a event fires to fast
                CustomEvent_PingFinished(this, new PingFinishedEventArgs(dt_NetworkResults));
            }
        }

        private async Task PingAndUpdateAsync(System.Net.NetworkInformation.Ping ping, string ip, int TimeOut, bool ShowUnused)
        {
            PingReply reply = await ping.SendPingAsync(ip, TimeOut);
            DataRow row = dt_NetworkResults.NewRow();

            row["SendAlert"] = false;

            if (reply.Status == IPStatus.Success)
            {
                pingReply.Add(reply);

                //row["SSDP"] = null;
                row["Ping"] = Properties.Resources.green_dot;
                row["IP"] = reply.Address.ToString();
                row["ResponseTime"] = reply.RoundtripTime.ToString();
                dt_NetworkResults.Rows.Add(row);
            }
            else if (ShowUnused && reply.Status != IPStatus.Success)
            {
                //row["SSDP"] = null;
                row["Ping"] = Properties.Resources.red_dot;
                row["IP"] = ip;
                row["ResponseTime"] = string.Empty;
                dt_NetworkResults.Rows.Add(row);
            }

            if (CustomEvent_PingFinished != null)
            {
                //the User Gui can be freeze if a event fires to fast
                CustomEvent_PingProgress(this, new PingProgressEventArgs(row));
            }
        }



        private bool IsPortOpen(string host_or_ip, int port, TimeSpan timeout)
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

        public string GetLocalIPv4(NetworkInterfaceType _type)
        {
            string output = "";
            foreach (NetworkInterface item in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (item.NetworkInterfaceType == _type && item.OperationalStatus == OperationalStatus.Up)
                {
                    foreach (UnicastIPAddressInformation ip in item.GetIPProperties().UnicastAddresses)
                    {
                        if (ip.Address.AddressFamily == AddressFamily.InterNetwork)
                        {
                            output = ip.Address.ToString();
                        }
                    }
                }
            }
            return output;
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
        private DataRow _row = new ScanningMethods_Ping().NetworkResultsTable.NewRow();
        public DataRow PingResultsRow { get { return _row; } }
        public PingProgressEventArgs(DataRow Row)
        {
            _row = Row;
        }
    }
}
