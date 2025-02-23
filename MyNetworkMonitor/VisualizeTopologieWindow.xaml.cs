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
using System.Xml.Linq;
using static System.Net.WebRequestMethods;
using System.Reflection;

namespace MyNetworkMonitor
{
    //1. 3d-force-graph.min.js
    //    Download: https://unpkg.com/browse/3d-force-graph@1.76.1/dist/

    //2. accessor-fn.min.js 
    //    Download: https://unpkg.com/browse/accessor-fn@1.5.1/dist/

    //3. kapsule.min.js 
    //    Download: https://unpkg.com/browse/kapsule@1.16.0/dist/

    //4. three(Empfohlenes Modul) 
    //    Empfohlenes Modul(ESM):
    //    import* as THREE from 'https://unpkg.com/three@latest/build/three.module.js';

    //    Falls eine ältere min.js benötigt wird:
    //        Letzte Version mit three.min.js: https://unpkg.com/three@0.160.1/build/three.min.js
    //        Neuere ESM-Version: https://unpkg.com/browse/three@0.173.0/build/three.module.js

    //5. three-forcegraph.min.js 
    //    Download: https://unpkg.com/browse/three-forcegraph@1.42.12/dist/

    //6. three-render-objects.min.js
    //    Download: https://unpkg.com/browse/three-render-objects@1.39.0/dist/


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
            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            jsonFilePath = Path.Combine(basePath, $"graph_data_{timestamp}.json");
            htmlFilePath = Path.Combine(basePath, $"network_topology_{timestamp}.html");

            GenerateJSON();
            GenerateHTML();

            // JSON-Datei löschen
            try
            {
                if (System.IO.File.Exists(jsonFilePath))
                {
                    System.IO.File.Delete(jsonFilePath);
                    Debug.WriteLine("🗑️ JSON-Datei gelöscht: " + jsonFilePath);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("⚠️ Fehler beim Löschen der JSON-Datei: " + ex.Message);
            }

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
            // Erstelle Knoten – jeder Zeile wird ein eindeutiger numerischer Index als ID zugewiesen.
            var nodes = dt_NetworkResults.AsEnumerable()
                .Select((row, index) => new
                {
                    id = index.ToString(), // Eindeutige Nummer als ID
                    group = row["IPGroupDescription"].ToString(),
                    label = row["DeviceDescription"].ToString(),
                    hostname = row.Table.Columns.Contains("Hostname") ? row["Hostname"].ToString() : "Unbekannt",
                    ip = row["IP"].ToString(),
                    mac = row["Mac"].ToString(), // MAC-Adresse
                    lookupIPs = row["LookUpIPs"] != DBNull.Value ? row["LookUpIPs"].ToString() : ""
                })
                .ToList();

            var links = new HashSet<(string source, string target, bool isLookup, bool isDuplicate)>();

            // 🔹 Gruppeninterne Verbindungen: Knoten, die zur selben IPGroupDescription gehören, werden verbunden.
            foreach (var group in nodes.GroupBy(n => n.group))
            {
                var groupNodes = group.ToList();
                if (groupNodes.Count > 1)
                {
                    var firstNode = groupNodes.First();
                    foreach (var node in groupNodes.Skip(1))
                    {
                        links.Add((firstNode.id, node.id, false, false));
                    }
                }
            }

            // 🔹 LookUpIPs-Verbindungen: Für jede Zeile wird, falls vorhanden, der LookUpIPs-Text verarbeitet.
            foreach (var node in nodes)
            {
                if (!string.IsNullOrEmpty(node.lookupIPs))
                {
                    var lookupList = node.lookupIPs
                        .Split(new[] { '\n', '\r', ',' }, StringSplitOptions.RemoveEmptyEntries)
                        .Select(ip => ip.Trim())
                        .Where(lookupIp => lookupIp != node.ip) // Nur einzelne IPs, die gleich der aktuellen IP sind, werden ausgeschlossen
                        .ToList();

                    foreach (var lookupIp in lookupList)
                    {
                        var targetNodes = nodes.Where(n => n.ip == lookupIp).ToList();
                        foreach (var target in targetNodes)
                        {
                            if (target.id != node.id)
                            {
                                links.Add((target.id, node.id, true, false));
                            }
                        }
                    }
                }
            }

            // Hilfsset um Duplikat-Paare nur einmal zu erfassen
            var duplicatePairs = new HashSet<(string, string)>();

            // 🔹 Duplikate basierend auf IP – nur wenn der Hostname nicht leer ist.
            foreach (var group in nodes.GroupBy(n => n.ip))
            {
                //var groupNodes = group.Where(n => !string.IsNullOrWhiteSpace(n.hostname)).ToList();
                var groupNodes = group.ToList(); // Kein Filtern mehr nach hostname!
                if (groupNodes.Count > 1)
                {
                    for (int i = 0; i < groupNodes.Count; i++)
                    {
                        for (int j = i + 1; j < groupNodes.Count; j++)
                        {
                            var id1 = groupNodes[i].id;
                            var id2 = groupNodes[j].id;
                            var pair = (id1.CompareTo(id2) < 0 ? id1 : id2, id1.CompareTo(id2) < 0 ? id2 : id1);
                            if (!duplicatePairs.Contains(pair))
                            {
                                duplicatePairs.Add(pair);
                                // Bidirektionale Duplicate-Links hinzufügen:
                                links.Add((id1, id2, false, true));
                                links.Add((id2, id1, false, true));
                            }
                        }
                    }
                }
            }

            // 🔹 Duplikate basierend auf Hostname – nur wenn der Hostname nicht leer ist.
            foreach (var group in nodes.GroupBy(n => n.hostname))
            {
                if (string.IsNullOrWhiteSpace(group.Key))
                    continue;

                var groupNodes = group.ToList();
                if (groupNodes.Count > 1)
                {
                    for (int i = 0; i < groupNodes.Count; i++)
                    {
                        for (int j = i + 1; j < groupNodes.Count; j++)
                        {
                            var id1 = groupNodes[i].id;
                            var id2 = groupNodes[j].id;
                            var pair = (id1.CompareTo(id2) < 0 ? id1 : id2, id1.CompareTo(id2) < 0 ? id2 : id1);
                            if (!duplicatePairs.Contains(pair))
                            {
                                duplicatePairs.Add(pair);
                                links.Add((id1, id2, false, true));
                                links.Add((id2, id1, false, true));
                            }
                        }
                    }
                }
            }

            // 🔹 Duplikate basierend auf MAC-Adresse – nur wenn die MAC-Adresse nicht leer ist.
            foreach (var group in nodes.GroupBy(n => n.mac))
            {
                if (string.IsNullOrWhiteSpace(group.Key))
                    continue;

                var groupNodes = group.ToList();
                if (groupNodes.Count > 1)
                {
                    for (int i = 0; i < groupNodes.Count; i++)
                    {
                        for (int j = i + 1; j < groupNodes.Count; j++)
                        {
                            var id1 = groupNodes[i].id;
                            var id2 = groupNodes[j].id;
                            var pair = (id1.CompareTo(id2) < 0 ? id1 : id2, id1.CompareTo(id2) < 0 ? id2 : id1);
                            if (!duplicatePairs.Contains(pair))
                            {
                                duplicatePairs.Add(pair);
                                links.Add((id1, id2, false, true));
                                links.Add((id2, id1, false, true));
                            }
                        }
                    }
                }
            }

            // Erstelle das finale Graph-Datenobjekt inklusive aller Knoten und Links.
            var graphData = new
            {
                nodes,
                links = links.Select(l => new
                {
                    source = l.source,
                    target = l.target,
                    isLookup = l.isLookup,
                    isDuplicate = l.isDuplicate
                }).ToList()
            };

            string json = JsonConvert.SerializeObject(graphData, Formatting.Indented);
            System.IO.File.WriteAllText(jsonFilePath, json, new UTF8Encoding(false));
            Debug.WriteLine("✅ JSON erfolgreich erstellt: " + jsonFilePath);
        }


        //online
        //<script src=""https://unpkg.com/3d-force-graph""></script>

        //offline
        //<script src="libs/three.min.js"></script>
        //<script src="libs/accessor-fn.min.js"></script >
        //<script src="libs/kapsule.min.js"></script>
        //<script src="libs/three-render-objects.min.js"></script >
        //<script src="libs/three-forcegraph.min.js"></script>
        //<script src="libs/3d-force-graph.min.js"></script >

        private void GenerateHTML()
        {
            // Lese den JSON-Inhalt ein
            string jsonContent = System.IO.File.ReadAllText(jsonFilePath, new UTF8Encoding(false));

            string htmlContent = $@"
<!DOCTYPE html>
<html lang=""de"">
<head>
    <meta charset=""UTF-8"">
    <title>Netzwerk Topologie</title>
   <script src=""https://unpkg.com/3d-force-graph""></script>
    <style>
        body {{ margin: 0; overflow: hidden; }}
        #3d-graph {{ width: 100vw; height: 100vh; position: absolute; }}
    </style>
    <script>
        function checkBrowser() {{
            const userAgent = navigator.userAgent;
            if (!userAgent.includes(""Chrome"") && !userAgent.includes(""Edg"")) {{
                alert(""Diese Datei funktioniert nur mit Chrome oder Edge."");
                document.body.innerHTML = """";
            }}
        }}
        document.addEventListener(""DOMContentLoaded"", checkBrowser);
    </script>
</head>
<body>
    <div id=""3d-graph""></div>
    <script>
        // JSON-Daten werden direkt eingebettet
        const graphData = {jsonContent};

        function resizeGraph() {{
            const graphElement = document.getElementById('3d-graph');
            graphElement.style.width = window.innerWidth + 'px';
            graphElement.style.height = window.innerHeight + 'px';
            if (Graph) {{
                Graph.width(window.innerWidth).height(window.innerHeight);
            }}
        }}

        let Graph = ForceGraph3D()(document.getElementById('3d-graph'))
                    .graphData(graphData)
                    .nodeAutoColorBy('group')
                    // Hier werden ausschließlich IP und Hostname als Label angezeigt.
                    .nodeLabel(node => node.group + ' # ' + node.label + ' # ' + node.ip + ' # ' + node.hostname)
                    .linkDirectionalParticles(2)
                    // Pfeile und Linkstile: LookUpIPs oder doppelte Verbindungen werden hervorgehoben.
                    .linkDirectionalArrowLength(link => (link.isLookup || link.isDuplicate) ? 5 : 0)
                    .linkDirectionalArrowRelPos(1)
                    .linkWidth(link => (link.isLookup || link.isDuplicate) ? 1.1 : 1)
                    .linkColor(link => link.isDuplicate ? 'red' : link.isLookup ? 'orange' : 'white');

        // Verzögere den Zoom, damit sich das Layout stabilisiert
        setTimeout(() => {{
            Graph.zoomToFit(500, 100);
        }}, 1000);

        resizeGraph();
        window.addEventListener('resize', resizeGraph);
    </script>
</body>
</html>
";
            System.IO.File.WriteAllText(htmlFilePath, htmlContent, Encoding.UTF8);
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

                    if (System.IO.File.Exists(filePath))
                    {
                        byte[] buffer = System.IO.File.ReadAllBytes(filePath);
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
            webView.CoreWebView2.Navigate("http://localhost:8080/" + htmlFilePath);
        }
    }
}
