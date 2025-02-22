using System;
using System.IO;
using System.Net;
using System.Text;
using System.Diagnostics;
using System.Data;
using System.Linq;
using Newtonsoft.Json;
using System.Threading;
using System.Collections.Generic;
using System.Windows;
using Microsoft.Web.WebView2.Core;

namespace MyNetworkMonitor
{
    public partial class VisualizeTopologieWindow : Window
    {
        private readonly DataTable dt_NetworkResults;
        private readonly string basePath;
        private readonly string jsonFilePath;
        private readonly string htmlFilePath;

        // Statische Variable, damit der Webserver nur einmal gestartet wird.
        private static bool _serverStarted = false;

        public VisualizeTopologieWindow(string GraphPath, DataTable resultTable)
        {
            InitializeComponent();
            dt_NetworkResults = resultTable ?? throw new ArgumentNullException(nameof(resultTable));

            if (!Directory.Exists(GraphPath)) Directory.CreateDirectory(GraphPath);

            //basePath = AppDomain.CurrentDomain.BaseDirectory;
            basePath = GraphPath;
            jsonFilePath = Path.Combine(basePath, "graph_data.json");
            htmlFilePath = Path.Combine(basePath, "network_topology.html");

            GenerateJSON();
            GenerateHTML();

            // Starte den Webserver nur, wenn er noch nicht gestartet wurde.
            if (!_serverStarted)
            {
                StartWebServer(8080);
                _serverStarted = true;
            }

            InitializeWebView2();
        }

        //private void GenerateJSON()
        //{
        //    var nodes = dt_NetworkResults.AsEnumerable()
        //        .Select(row => new
        //        {
        //            id = row["IP"].ToString(),
        //            group = row["IPGroupDescription"].ToString(),
        //            label = row["DeviceDescription"].ToString()
        //        })
        //        .ToList();

        //    var nodeIds = new HashSet<string>(nodes.Select(n => n.id));

        //    var links = dt_NetworkResults.AsEnumerable()
        //        .GroupBy(row => row["IPGroupDescription"].ToString())
        //        .SelectMany(group =>
        //        {
        //            var devices = group.Select(row => row["IP"].ToString())
        //                               .Where(ip => nodeIds.Contains(ip))
        //                               .ToList();
        //            return devices.Skip(1)
        //                          .Select(ip => new { source = devices.First(), target = ip });
        //        })
        //        .ToList();

        //    var graphData = new { nodes, links };

        //    string json = JsonConvert.SerializeObject(graphData, Formatting.Indented);
        //    File.WriteAllText(jsonFilePath, json, new UTF8Encoding(false));
        //    Debug.WriteLine("✅ JSON erfolgreich erstellt: " + jsonFilePath);
        //}





        //private void GenerateJSON()
        //{
        //    var nodes = dt_NetworkResults.AsEnumerable()
        //        .Select(row => new
        //        {
        //            id = row["IP"].ToString(),
        //            group = row["IPGroupDescription"].ToString(),
        //            label = row["DeviceDescription"].ToString()
        //        })
        //        .ToList();

        //    var nodeIds = new HashSet<string>(nodes.Select(n => n.id));

        //    var links = new List<object>();

        //    foreach (DataRow row in dt_NetworkResults.Rows)
        //    {
        //        string ip = row["IP"].ToString();
        //        string group = row["IPGroupDescription"].ToString();

        //        // Verknüpfungen innerhalb der Gruppen
        //        var groupDevices = dt_NetworkResults.AsEnumerable()
        //            .Where(r => r["IPGroupDescription"].ToString() == group)
        //            .Select(r => r["IP"].ToString())
        //            .Where(ip => nodeIds.Contains(ip))
        //            .ToList();

        //        links.AddRange(groupDevices.Skip(1).Select(targetIp => new { source = groupDevices.First(), target = targetIp }));

        //        // Verknüpfungen aus LookUpIPs hinzufügen
        //        if (row["LookUpIPs"] != DBNull.Value)
        //        {
        //            string lookupIps = row["LookUpIPs"].ToString();
        //            var lookupIpList = lookupIps
        //                .Split(new[] { '\n', '\r', ',' }, StringSplitOptions.RemoveEmptyEntries)
        //                .Select(ip => ip.Trim())
        //                .Where(ip => nodeIds.Contains(ip)) // Nur existierende IPs verbinden
        //                .ToList();

        //            foreach (var lookupIp in lookupIpList)
        //            {
        //                links.Add(new { source = ip, target = lookupIp });
        //            }
        //        }
        //    }

        //    var graphData = new { nodes, links };

        //    string json = JsonConvert.SerializeObject(graphData, Formatting.Indented);
        //    File.WriteAllText(jsonFilePath, json, new UTF8Encoding(false));
        //    Debug.WriteLine("✅ JSON erfolgreich erstellt: " + jsonFilePath);
        //}




        //private void GenerateJSON()
        //{
        //    var nodes = dt_NetworkResults.AsEnumerable()
        //        .Select(row => new
        //        {
        //            id = row["IP"].ToString(),
        //            group = row["IPGroupDescription"].ToString(),
        //            label = row["DeviceDescription"].ToString()
        //        })
        //        .ToList();

        //    var nodeIds = new HashSet<string>(nodes.Select(n => n.id));

        //    var links = new List<object>();

        //    foreach (DataRow row in dt_NetworkResults.Rows)
        //    {
        //        string ip = row["IP"].ToString();
        //        string group = row["IPGroupDescription"].ToString();

        //        // Verknüpfungen innerhalb der Gruppen
        //        var groupDevices = dt_NetworkResults.AsEnumerable()
        //            .Where(r => r["IPGroupDescription"].ToString() == group)
        //            .Select(r => r["IP"].ToString())
        //            .Where(ip => nodeIds.Contains(ip))
        //            .ToList();

        //        links.AddRange(groupDevices.Skip(1).Select(targetIp => new { source = groupDevices.First(), target = targetIp }));

        //        // Verknüpfungen aus LookUpIPs hinzufügen (wenn LookUpIP nicht gleich IP ist)
        //        if (row["LookUpIPs"] != DBNull.Value)
        //        {
        //            string lookupIps = row["LookUpIPs"].ToString();
        //            var lookupIpList = lookupIps
        //                .Split(new[] { '\n', '\r', ',' }, StringSplitOptions.RemoveEmptyEntries)
        //                .Select(ip => ip.Trim())
        //                .Where(lookupIp => lookupIp != ip) // Ignoriert LookUpIP, wenn sie mit IP in der gleichen Zeile übereinstimmt
        //                .Where(lookupIp => nodeIds.Contains(lookupIp)) // Nur existierende IPs verbinden
        //                .ToList();

        //            foreach (var lookupIp in lookupIpList)
        //            {
        //                links.Add(new { source = ip, target = lookupIp });
        //            }
        //        }
        //    }

        //    var graphData = new { nodes, links };

        //    string json = JsonConvert.SerializeObject(graphData, Formatting.Indented);
        //    File.WriteAllText(jsonFilePath, json, new UTF8Encoding(false));
        //    Debug.WriteLine("✅ JSON erfolgreich erstellt: " + jsonFilePath);
        //}


        private void GenerateJSON()
        {
            var nodes = dt_NetworkResults.AsEnumerable()
                .Select(row => new
                {
                    id = row["IP"].ToString(),
                    group = row["IPGroupDescription"].ToString(),
                    label = row["DeviceDescription"].ToString()
                })
                .ToList();

            var nodeIds = new HashSet<string>(nodes.Select(n => n.id));
            var links = new HashSet<(string source, string target)>();

            foreach (DataRow row in dt_NetworkResults.Rows)
            {
                string ip = row["IP"].ToString();
                string group = row["IPGroupDescription"].ToString();

                // Find other devices in the same group
                var groupDevices = dt_NetworkResults.AsEnumerable()
                    .Where(r => r["IPGroupDescription"].ToString() == group)
                    .Select(r => r["IP"].ToString())
                    .Where(ip => nodeIds.Contains(ip))
                    .ToList();

                if (groupDevices.Count > 1)
                {
                    string firstDevice = groupDevices.First();
                    foreach (var targetIp in groupDevices.Skip(1))
                    {
                        links.Add((firstDevice, targetIp));
                    }
                }

                // Process LookUpIPs
                if (row["LookUpIPs"] != DBNull.Value)
                {
                    string lookupIps = row["LookUpIPs"].ToString();
                    var lookupIpList = lookupIps
                        .Split(new[] { '\n', '\r', ',' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(ip => ip.Trim())
                        .Where(lookupIp => lookupIp != ip) // Avoid self-referencing
                        .Where(lookupIp => nodeIds.Contains(lookupIp)) // Only link existing nodes
                        .ToList();

                    foreach (var lookupIp in lookupIpList)
                    {
                        links.Add((ip, lookupIp));
                    }
                }
            }

            var graphData = new
            {
                nodes,
                links = links.Select(l => new { source = l.source, target = l.target }).ToList()
            };

            string json = JsonConvert.SerializeObject(graphData, Formatting.Indented);
            File.WriteAllText(jsonFilePath, json, new UTF8Encoding(false));
            Debug.WriteLine("✅ JSON erfolgreich erstellt: " + jsonFilePath);
        }












        private void GenerateHTML()
        {
            string htmlContent = @"
<!DOCTYPE html>
<html lang=""de"">
<head>
    <meta charset=""UTF-8"">
    <title>Netzwerk Topologie</title>
    <script src=""https://unpkg.com/3d-force-graph""></script>
    <style>
        body { margin: 0; overflow: hidden; }
        #3d-graph { width: 100vw; height: 100vh; position: absolute; }
    </style>
</head>
<body>
    <div id=""3d-graph""></div>
    <script>
        function resizeGraph() {
            const graphElement = document.getElementById('3d-graph');
            graphElement.style.width = window.innerWidth + 'px';
            graphElement.style.height = window.innerHeight + 'px';
            if (Graph) {
                Graph.width(window.innerWidth).height(window.innerHeight);
            }
        }

        let Graph;
        fetch('graph_data.json')
            .then(response => response.json())
            .then(data => {
                console.log('✅ JSON erfolgreich geladen:', data);

                Graph = ForceGraph3D()(document.getElementById('3d-graph'))
                    .graphData(data)
                    .nodeAutoColorBy('group')
                    .nodeLabel(node => node.group + ' # ' + node.label + ' # ' + node.id)
                    .linkDirectionalParticles(2)
                    .linkDirectionalParticleSpeed(0.02);

                // Verzögere den Zoom-Aufruf, damit sich das Layout stabilisieren kann
                setTimeout(() => {
                    Graph.zoomToFit(500, 100);
                }, 1000);

                resizeGraph();
            })
            .catch(error => console.error('❌ Fehler beim Laden der JSON-Datei:', error));

        window.addEventListener('resize', resizeGraph);
    </script>
</body>
</html>
";
            File.WriteAllText(htmlFilePath, htmlContent, Encoding.UTF8);
            Debug.WriteLine("✅ HTML erfolgreich erstellt: " + htmlFilePath);
        }

        private void StartWebServer(int port)
        {
            Thread serverThread = new Thread(() =>
            {
                HttpListener listener = new HttpListener();
                listener.Prefixes.Add($"http://localhost:{port}/");
                listener.Start();
                Debug.WriteLine($"✅ Webserver gestartet auf http://localhost:{port}/");

                while (true)
                {
                    var context = listener.GetContext();
                    var request = context.Request;
                    var response = context.Response;

                    string filePath = Path.Combine(basePath, request.Url.AbsolutePath.TrimStart('/'));
                    if (filePath == basePath)
                        filePath = htmlFilePath; // Standardseite

                    if (File.Exists(filePath))
                    {
                        byte[] buffer = File.ReadAllBytes(filePath);
                        response.ContentType = GetMimeType(filePath);
                        response.ContentEncoding = Encoding.UTF8;
                        response.ContentLength64 = buffer.Length;
                        response.OutputStream.Write(buffer, 0, buffer.Length);
                    }
                    else
                    {
                        response.StatusCode = (int)HttpStatusCode.NotFound;
                    }
                    response.OutputStream.Close();
                }
            });
            serverThread.IsBackground = true;
            serverThread.Start();
        }

        private string GetMimeType(string filePath)
        {
            string extension = Path.GetExtension(filePath).ToLower();
            return extension switch
            {
                ".html" => "text/html; charset=UTF-8",
                ".json" => "application/json; charset=UTF-8",
                ".js" => "application/javascript",
                _ => "application/octet-stream"
            };
        }

        private async void InitializeWebView2()
        {
            await webView.EnsureCoreWebView2Async(null);
            webView.CoreWebView2.Navigate("http://localhost:8080");
        }
    }
}
