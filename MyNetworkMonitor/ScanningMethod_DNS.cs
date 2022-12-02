
using System;
using System.Collections.Generic;
using System.Data;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using System.Threading.Tasks.Dataflow;

namespace MyNetworkMonitor
{
    internal class ScanningMethod_DNS
    {
        public ScanningMethod_DNS()
        {

        }



        int _countedHosts = 0;
        int _currentHostCount = 0;

        public event EventHandler<GetHostAndAliasFromIP_Task_Finished_EventArgs>? GetHostAndAliasFromIP_Task_Finished;
        public event EventHandler<GetHostAndAliasFromIP_Finished_EventArgs>? GetHostAndAliasFromIP_Finished;

        public async Task Get_Host_and_Alias_From_IP(List<string> IPs)
        {
            if (IPs.Count == 0)
            {
                return;
            }

            var tasks = new List<Task>();

            Parallel.ForEach(IPs, ip =>
                    {
                        _countedHosts++;
                        var task = GetHostAndAliasFromIP_Task(ip);
                        tasks.Add(task);
                    });

            await Task.WhenAll(tasks);

            if (GetHostAndAliasFromIP_Finished != null)
            {
                GetHostAndAliasFromIP_Finished(this, new GetHostAndAliasFromIP_Finished_EventArgs(true));
            }
        }



        private async Task GetHostAndAliasFromIP_Task(string ip)
        {
            IPHostEntry entry = new IPHostEntry();

            try
            {

                entry = Dns.GetHostEntryAsync(ip.ToString(), System.Net.Sockets.AddressFamily.InterNetwork).Result;
                if (GetHostAndAliasFromIP_Task_Finished != null)
                {
                    GetHostAndAliasFromIP_Task_Finished(this, new GetHostAndAliasFromIP_Task_Finished_EventArgs(ip, entry.HostName, string.Join("\r\n", entry.Aliases)));
                }
            }
            catch (Exception ex)
            {
                GetHostAndAliasFromIP_Task_Finished(this, new GetHostAndAliasFromIP_Task_Finished_EventArgs(string.Empty, string.Empty, string.Empty));
            }
        }
    }

    public class GetHostAndAliasFromIP_Task_Finished_EventArgs : EventArgs
    {
        //public GetHostAndAliasFromIP_Task_Finished_EventArgs(string IP, string Hostname, string Aliases, int CurrentHostnamesCount, int CountedHostnames)
        //{
        //    _resultRow = results.ResultTable.NewRow();
        //    _resultRow["IP"] = _IP = IP;
        //    _resultRow["Hostname"] = _Hostname = Hostname;
        //    _resultRow["Aliases"] = _Aliases = Aliases;

        //    _currentHostnamesCount = CurrentHostnamesCount;
        //    _countedHostnames = CountedHostnames;
        //}

        public GetHostAndAliasFromIP_Task_Finished_EventArgs(string IP, string Hostname, string Aliases)
        {
            _resultRow = results.ResultTable.NewRow();
            _resultRow["IP"] = _IP = IP;
            _resultRow["Hostname"] = _Hostname = Hostname;
            _resultRow["Aliases"] = _Aliases = Aliases;

            //_currentHostnamesCount = CurrentHostnamesCount;
            //_countedHostnames = CountedHostnames;
        }

        ScanResults results = new ScanResults();

        private DataRow _resultRow;
        public DataRow ResultRow { get { return _resultRow; } }


        private string _IP = string.Empty;
        public string IP { get { return _IP; } }


        private string _Hostname = string.Empty;
        public string Hostname { get { return _Hostname; } }

        private string _Aliases = string.Empty;
        public string Aliases { get { return _Aliases; } }


        //private int _countedHostnames = 0;
        //public int CountedHostnames { get { return _countedHostnames; } }


        //private int _currentHostnamesCount = 0;
        //public int CurrentHostnamesCount { get { return _currentHostnamesCount; } }
    }

    public class GetHostAndAliasFromIP_Finished_EventArgs : EventArgs
    {
        private bool _finished = false;
        public bool FinishedDNSQuery { get { return _finished; } }
        public GetHostAndAliasFromIP_Finished_EventArgs(bool Finished_DNS_Query)
        {
            _finished = Finished_DNS_Query;
        }
    }
}
