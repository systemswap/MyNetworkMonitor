using System.Data;
using System.Text;
using Newtonsoft.Json;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Erzeugt die Daten der 3D-Topologie aus der Ergebnistabelle. Enthaelt
    /// bewusst keinerlei UI-Bezug (im WPF-Original lag alles in
    /// VisualizeTopologieWindow.xaml.cs), damit WPF und Avalonia dieselbe
    /// Darstellung erzeugen.
    /// </summary>
    public static class TopologyGraph
    {
        private const string OnlineLibrary =
            "<script src=\"https://cdn.jsdelivr.net/npm/3d-force-graph@1.76.2/dist/3d-force-graph.min.js\"></script>";

        private const string LocalLibrary =
            "<script src=\"./libs/3d-force-graph.min.js\"></script>";

        private sealed record Node(string id, string group, string label, string hostname, string ip, string mac, string lookupIPs);

        /// <summary>
        /// Baut Knoten und Kanten als JSON. Kanten entstehen aus der
        /// Gruppenzugehoerigkeit, aus LookUpIPs und aus Dubletten (IP, Hostname,
        /// MAC) - letztere jeweils bidirektional, damit sie im Graph auffallen.
        /// </summary>
        public static string BuildGraphJson(DataTable resultTable)
        {
            List<Node> nodes = resultTable.AsEnumerable()
                .Select((row, index) => new Node(
                    id: index.ToString(),
                    group: row["IPGroupDescription"].ToString() ?? string.Empty,
                    label: row["DeviceDescription"].ToString() ?? string.Empty,
                    hostname: row.Table.Columns.Contains("Hostname") ? row["Hostname"].ToString() ?? "Unbekannt" : "Unbekannt",
                    ip: row["IP"].ToString() ?? string.Empty,
                    mac: row["Mac"].ToString() ?? string.Empty,
                    lookupIPs: row["LookUpIPs"] != DBNull.Value ? row["LookUpIPs"].ToString() ?? string.Empty : string.Empty))
                .ToList();

            var links = new HashSet<(string source, string target, bool isLookup, bool isDuplicatedIP,
                                     bool isDuplicatedHostname, bool isDuplicatedMac)>();

            // Geraete derselben IP-Gruppe sternfoermig am ersten Knoten aufhaengen
            foreach (IGrouping<string, Node> group in nodes.GroupBy(n => n.group))
            {
                List<Node> groupNodes = group.ToList();
                if (groupNodes.Count <= 1) continue;

                Node first = groupNodes[0];
                foreach (Node node in groupNodes.Skip(1))
                {
                    links.Add((first.id, node.id, false, false, false, false));
                }
            }

            // LookUpIPs verbinden nur, wenn die Ziel-IP selbst als Geraet in der Tabelle steht
            foreach (Node node in nodes)
            {
                if (string.IsNullOrEmpty(node.lookupIPs)) continue;

                IEnumerable<string> lookupList = node.lookupIPs
                    .Split(new[] { '\n', '\r', ',' }, StringSplitOptions.RemoveEmptyEntries)
                    .Select(ip => ip.Trim())
                    .Where(ip => ip != node.ip);

                foreach (string lookupIp in lookupList)
                {
                    foreach (Node target in nodes.Where(n => n.ip == lookupIp && n.id != node.id))
                    {
                        links.Add((target.id, node.id, true, false, false, false));
                    }
                }
            }

            // Jede Dublette nur einmal erfassen - IP schlaegt Hostname schlaegt MAC
            var duplicatePairs = new HashSet<(string, string)>();

            AddDuplicateLinks(nodes.GroupBy(n => n.ip), skipEmptyKey: false,
                              (a, b) => (a, b, false, true, false, false));

            AddDuplicateLinks(nodes.GroupBy(n => n.hostname), skipEmptyKey: true,
                              (a, b) => (a, b, false, false, true, false));

            AddDuplicateLinks(nodes.GroupBy(n => n.mac), skipEmptyKey: true,
                              (a, b) => (a, b, false, false, false, true));

            var graphData = new
            {
                nodes,
                links = links.Select(l => new
                {
                    source = l.source,
                    target = l.target,
                    isLookup = l.isLookup,
                    isDuplicatedIP = l.isDuplicatedIP,
                    isDuplicatedHostname = l.isDuplicatedHostname,
                    isDuplicatedMac = l.isDuplicatedMac
                }).ToList()
            };

            return JsonConvert.SerializeObject(graphData, Formatting.Indented);

            void AddDuplicateLinks(IEnumerable<IGrouping<string, Node>> groups, bool skipEmptyKey,
                                   Func<string, string, (string, string, bool, bool, bool, bool)> makeLink)
            {
                foreach (IGrouping<string, Node> group in groups)
                {
                    if (skipEmptyKey && string.IsNullOrWhiteSpace(group.Key)) continue;

                    List<Node> groupNodes = group.ToList();
                    if (groupNodes.Count <= 1) continue;

                    for (int i = 0; i < groupNodes.Count; i++)
                    {
                        for (int j = i + 1; j < groupNodes.Count; j++)
                        {
                            string id1 = groupNodes[i].id;
                            string id2 = groupNodes[j].id;

                            (string, string) pair = string.CompareOrdinal(id1, id2) < 0 ? (id1, id2) : (id2, id1);
                            if (!duplicatePairs.Add(pair)) continue;

                            links.Add(makeLink(id1, id2));
                            links.Add(makeLink(id2, id1));
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Bettet die Graph-Daten in die HTML-Seite ein. Die Bibliothek kommt
        /// entweder vom CDN (dann ist die Datei allein weitergebbar) oder aus
        /// dem lokalen Ordner libs/.
        /// </summary>
        public static string BuildHtml(string graphJson, bool useOnlineVersion)
        {
            string libraryTag = useOnlineVersion ? OnlineLibrary : LocalLibrary;

            return $@"
<!DOCTYPE html>
<html lang=""de"">
<head>
    <meta charset=""UTF-8"">
    <title>Network DNS Topology</title>

        {libraryTag}

        <style>
        body {{margin: 0; overflow: hidden; }}
        #3d-graph {{width: 100vw; height: 100vh; position: absolute; }}
        #info-label {{
            position: absolute;
            top: 10px;
            left: 10px;
            background-color: #222222;
            color: white;
            padding: 7px;
            border-radius: 5px;
            font-size: 13px;
            z-index: 10;
        }}
    </style>
</head>
<body>
    <div id=""info-label"">
        lookup IPs will only linked to another network device if they are in the IP column as separate device
    </div>

    <div id=""3d-graph""></div>
    <script>
        const graphData = {graphJson};

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
                    .nodeLabel(node => node.group + ' # ' + node.label + ' # ' + node.ip + ' # ' + node.hostname + ' # ' + node.mac)
                    .linkDirectionalParticles(2)
                    .linkDirectionalArrowLength(link => (link.isLookup || link.isDuplicatedIP || link.isDuplicatedHostname || link.isDuplicatedMac) ? 10 : 0)
                    .linkDirectionalArrowRelPos(1)
                    .linkWidth(link => (link.isLookup || link.isDuplicatedIP || link.isDuplicatedHostname || link.isDuplicatedMac) ? 3 : 1)
                    .linkColor(link => link.isDuplicatedMac ? 'red' : link.isDuplicatedHostname ? 'orange' : link.isDuplicatedIP ? 'yellow' : link.isLookup ? 'cyan' : 'white');

        // Verzoegerter Zoom, damit sich das Layout vorher stabilisiert
        setTimeout(() => {{
            Graph.zoomToFit(500, 100);
        }}, 1000);

        resizeGraph();
        window.addEventListener('resize', resizeGraph);
    </script>
</body>
</html>
";
        }

        /// <summary>
        /// Schreibt die HTML-Datei in den Graph-Ordner und liefert ihren Pfad.
        /// Der Dateiname traegt einen Zeitstempel, damit aufeinanderfolgende
        /// Visualisierungen erhalten bleiben.
        /// </summary>
        public static string WriteHtmlFile(string graphFolder, DataTable resultTable, bool useOnlineVersion)
        {
            Directory.CreateDirectory(graphFolder);

            string html = BuildHtml(BuildGraphJson(resultTable), useOnlineVersion);
            string fileName = $"network_topology_{DateTime.Now:yyyyMMdd_HHmmss}.html";
            string filePath = Path.Combine(graphFolder, fileName);

            File.WriteAllText(filePath, html, new UTF8Encoding(true));
            return filePath;
        }

        /// <summary>
        /// Kopiert die mitgelieferte 3d-force-graph-Bibliothek in den
        /// Unterordner libs/ des Graph-Ordners, damit die Offline-Variante
        /// funktioniert. Fehlt die Quelldatei, bleibt es dabei - dann traegt nur
        /// die Online-Variante.
        /// </summary>
        public static void EnsureLocalLibrary(string graphFolder)
        {
            string sourceFile = Path.Combine(AppContext.BaseDirectory, "3dForceGraphLib", "3d-force-graph.min.js");
            string destinationFolder = Path.Combine(graphFolder, "libs");
            string destinationFile = Path.Combine(destinationFolder, "3d-force-graph.min.js");

            try
            {
                if (!File.Exists(sourceFile)) return;

                Directory.CreateDirectory(destinationFolder);

                if (File.Exists(destinationFile)
                    && new FileInfo(sourceFile).Length == new FileInfo(destinationFile).Length)
                {
                    return;
                }

                File.Copy(sourceFile, destinationFile, true);
            }
            catch (Exception)
            {
                // Ohne lokale Bibliothek bleibt die Online-Variante nutzbar
            }
        }
    }
}
