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
        /// Eine Kante im Graph. Die Merkmale schliessen einander nicht aus -
        /// dieselben zwei Geraete koennen sich eine Adresse und einen Namen
        /// teilen -, die Farbgebung entscheidet sich fuer das schwerere.
        /// </summary>
        private sealed record Link(
            string source, string target,
            bool isLookup, bool isDuplicatedIP, bool isDuplicatedHostname,
            bool isDuplicatedMac, bool isDnsConflict);

        /// <summary>
        /// Baut den Graph aus dem neuen Geraetemodell.
        /// <para>
        /// Gegenueber der <see cref="DataTable"/>-Fassung wird nicht neu
        /// gruppiert, sondern genommen, was der
        /// <see cref="Model.DuplicateDetector"/> bereits festgestellt hat -
        /// zwei Stellen, die dieselbe Frage unabhaengig voneinander
        /// beantworten, geben frueher oder spaeter verschiedene Antworten.
        /// Die Kanten selbst muessen trotzdem hier entstehen: der Detektor
        /// vermerkt am Geraet <em>dass</em> etwas doppelt ist, nicht, mit wem.
        /// </para>
        /// </summary>
        public static string BuildGraphJson(IReadOnlyList<Model.Device> devices)
        {
            ArgumentNullException.ThrowIfNull(devices);

            Dictionary<Model.Device, string> ids = [];
            List<Node> nodes = [];

            for (int i = 0; i < devices.Count; i++)
            {
                Model.Device device = devices[i];
                string id = i.ToString();

                ids[device] = id;

                nodes.Add(new Node(
                    id: id,
                    group: device.GroupDescription,
                    label: device.DisplayName,
                    hostname: device.HostName,
                    ip: device.PrimaryAddress?.Info.Canonical ?? string.Empty,
                    mac: device.MacText,
                    lookupIPs: device.LookupAddressText));
            }

            HashSet<Link> links = [];
            HashSet<(string, string)> duplicatePairs = [];

            // Geraete derselben Gruppe sternfoermig am ersten Knoten aufhaengen
            foreach (IGrouping<string, Model.Device> group in devices.GroupBy(d => d.GroupDescription))
            {
                List<Model.Device> members = [.. group];
                if (members.Count <= 1) continue;

                foreach (Model.Device member in members.Skip(1))
                {
                    links.Add(new Link(ids[members[0]], ids[member], false, false, false, false, false));
                }
            }

            // Doppelt vergebene Adresse. Link-Local bleibt draussen, aus
            // demselben Grund wie im Detektor: fe80::1 je Schnittstelle ist
            // keine Doppelvergabe.
            Pair(devices
                    .SelectMany(d => d.Addresses
                        .Where(a => a.Info.Scope != Network.IpAddressScope.LinkLocal)
                        .Select(a => (Key: a.Info.Canonical, Device: d)))
                    .GroupBy(x => x.Key, x => x.Device, StringComparer.OrdinalIgnoreCase),
                 (a, b) => new Link(a, b, false, true, false, false, false));

            Pair(devices.Where(d => !string.IsNullOrWhiteSpace(d.HostName))
                        .GroupBy(d => d.HostName, StringComparer.OrdinalIgnoreCase),
                 (a, b) => new Link(a, b, false, false, true, false, false));

            // Der Name zeigt auf eine Adresse, an der ein anderes Geraet
            // antwortet. Das ist die Kante, die es ohne DNS nicht gaebe - und
            // die einzige, die zwei Geraete verbindet, die einander sonst
            // nirgends beruehren.
            foreach (Model.Device device in devices.Where(d => d.WasLookedUp))
            {
                foreach (string address in device.LookupAddresses)
                {
                    foreach (Model.Device target in devices)
                    {
                        if (ReferenceEquals(target, device)) continue;

                        bool answersThere = target.Addresses.Any(a =>
                            string.Equals(a.Info.Canonical, address, StringComparison.OrdinalIgnoreCase));

                        if (!answersThere) continue;

                        links.Add(new Link(ids[target], ids[device], true, false, false, false,
                                           device.HasLookupMismatch));
                    }
                }
            }

            var graphData = new { nodes, links = links.ToList() };

            return JsonConvert.SerializeObject(graphData, Formatting.Indented);

            void Pair(IEnumerable<IGrouping<string, Model.Device>> groups, Func<string, string, Link> makeLink)
            {
                foreach (IGrouping<string, Model.Device> group in groups)
                {
                    List<Model.Device> members = [.. group.Distinct()];
                    if (members.Count <= 1) continue;

                    for (int i = 0; i < members.Count; i++)
                    {
                        for (int j = i + 1; j < members.Count; j++)
                        {
                            string id1 = ids[members[i]];
                            string id2 = ids[members[j]];

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
                    isDuplicatedMac = l.isDuplicatedMac,

                    // Die alte Ergebnistabelle unterscheidet nicht, ob ein
                    // Lookup ins Leere zeigt - das Feld gibt es hier nur,
                    // damit beide Fassungen dieselbe Form liefern.
                    isDnsConflict = false
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

        /* Die Netz-Beschriftungen liegen als HTML ueber der Zeichenflaeche und
           nicht als Objekt in der Szene - so behalten sie beim Zoomen ihre
           Groesse und bleiben lesbar. */
        #net-labels {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            overflow: hidden;
            pointer-events: none;
            z-index: 5;
        }}
        .net-label {{
            position: absolute;
            top: 0;
            left: 0;
            white-space: nowrap;
            background-color: rgba(24, 24, 24, 0.78);
            border: 1px solid #666666;
            border-radius: 5px;
            padding: 3px 7px;
            color: white;
            font-family: sans-serif;
            line-height: 1.25;
            text-align: center;
        }}
        .net-label .net-ip {{
            display: block;
            font-size: 13px;
            font-weight: bold;
        }}
        .net-label .net-desc {{
            display: block;
            font-size: 11px;
            opacity: 0.8;
        }}
    </style>
</head>
<body>
    <div id=""info-label"">
        <b>Duplicate assignments</b><br>
        <span style=""color:yellow"">&#9644;</span> same IP address &nbsp;
        <span style=""color:orange"">&#9644;</span> same host name &nbsp;
        <span style=""color:red"">&#9644;</span> same MAC &nbsp;
        <span style=""color:#ff4fd8"">&#9644;</span> DNS points elsewhere &nbsp;
        <span style=""color:cyan"">&#9644;</span> DNS lookup<br>
        <span style=""opacity:.75"">A lookup is only drawn when the resolved address is itself a device in the list.</span>
    </div>

    <div id=""3d-graph""></div>
    <div id=""net-labels""></div>
    <script>
        const graphData = {graphJson};

        // Eine Kante faellt auf, wenn sie etwas bedeutet - die blossen
        // Gruppenkanten bleiben duenn und pfeillos, sonst geht der Befund
        // zwischen ihnen unter.
        function notable(link) {{
            return link.isLookup || link.isDuplicatedIP || link.isDuplicatedHostname
                || link.isDuplicatedMac || link.isDnsConflict;
        }}

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
                    .linkDirectionalArrowLength(link => notable(link) ? 10 : 0)
                    .linkDirectionalArrowRelPos(1)
                    .linkWidth(link => notable(link) ? 3 : 1)
                    .linkColor(link => link.isDuplicatedMac ? 'red'
                                     : link.isDuplicatedHostname ? 'orange'
                                     : link.isDuplicatedIP ? 'yellow'
                                     : link.isDnsConflict ? '#ff4fd8'
                                     : link.isLookup ? 'cyan' : 'white');

        // Die gemeinsame Netzadresse einer Gruppe. Sie steht nirgends in den
        // Daten, laesst sich aber aus den Adressen der Mitglieder ablesen -
        // solange sie sich einig sind; sonst bleibt es bei der Beschreibung.
        function networkOf(members) {{
            const ips = members.map(n => n.ip).filter(ip => ip);
            if (!ips.length) return '';

            if (ips.every(ip => ip.indexOf('.') >= 0 && ip.indexOf(':') < 0)) {{
                for (const length of [3, 2]) {{
                    const prefix = ips[0].split('.').slice(0, length).join('.');
                    if (ips.every(ip => ip.split('.').slice(0, length).join('.') === prefix)) {{
                        return prefix + (length === 3 ? '.0/24' : '.0.0/16');
                    }}
                }}
                return '';
            }}

            // IPv6: der gemeinsame Blockanfang, ohne Praefixlaenge zu behaupten -
            // die abgekuerzte Schreibweise laesst sich so nicht sicher zaehlen.
            const blocks = ips[0].split(':');
            let shared = 0;
            while (shared < blocks.length
                   && blocks[shared] !== ''
                   && ips.every(ip => ip.split(':')[shared] === blocks[shared])) {{
                shared++;
            }}

            return shared > 0 ? blocks.slice(0, shared).join(':') + '::' : '';
        }}

        // Ein Schild je Netz, aufgehaengt ueber dem obersten Knoten der Gruppe
        const labelLayer = document.getElementById('net-labels');
        const netLabels = [];

        (function buildNetLabels() {{
            const byGroup = new Map();

            graphData.nodes.forEach(node => {{
                const key = node.group || '';
                if (!byGroup.has(key)) byGroup.set(key, []);
                byGroup.get(key).push(node);
            }});

            byGroup.forEach((members, key) => {{
                const network = networkOf(members);
                if (!network && !key) return;

                const element = document.createElement('div');
                element.className = 'net-label';
                element.style.borderColor = members[0].color || '#666666';

                const head = document.createElement('span');
                head.className = 'net-ip';
                head.textContent = network || key;
                element.appendChild(head);

                if (network && key) {{
                    const description = document.createElement('span');
                    description.className = 'net-desc';
                    description.textContent = key;
                    element.appendChild(description);
                }}

                labelLayer.appendChild(element);
                netLabels.push({{ members: members, element: element }});
            }});
        }})();

        // Jedes Schild folgt seiner Gruppe: waagerecht mittig, senkrecht ueber
        // dem hoechsten Knoten. Knoten hinter der Kamera bleiben draussen,
        // deren projizierte Lage waere gespiegelt.
        function updateNetLabels() {{
            if (netLabels.length && typeof Graph.graph2ScreenCoords === 'function') {{
                const camera = Graph.cameraPosition();
                const controls = Graph.controls();
                const target = (controls && controls.target) || {{ x: 0, y: 0, z: 0 }};
                const view = {{ x: target.x - camera.x, y: target.y - camera.y, z: target.z - camera.z }};

                netLabels.forEach(label => {{
                    let sumX = 0, top = Infinity, visible = 0;

                    label.members.forEach(node => {{
                        if (node.x === undefined) return;

                        const ahead = (node.x - camera.x) * view.x
                                    + (node.y - camera.y) * view.y
                                    + (node.z - camera.z) * view.z;
                        if (ahead <= 0) return;

                        const point = Graph.graph2ScreenCoords(node.x, node.y, node.z);
                        sumX += point.x;
                        if (point.y < top) top = point.y;
                        visible++;
                    }});

                    const x = sumX / visible;
                    const y = top - 12;

                    if (!visible || x < -300 || x > window.innerWidth + 300
                        || y < -200 || y > window.innerHeight + 200) {{
                        label.element.style.display = 'none';
                        return;
                    }}

                    label.element.style.display = '';
                    label.element.style.transform =
                        'translate(' + x + 'px,' + y + 'px) translate(-50%, -100%)';
                }});
            }}

            requestAnimationFrame(updateNetLabels);
        }}

        requestAnimationFrame(updateNetLabels);

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

            return Write(graphFolder, BuildHtml(BuildGraphJson(resultTable), useOnlineVersion));
        }

        /// <summary>Dieselbe Datei, gebaut aus dem neuen Geraetemodell.</summary>
        public static string WriteHtmlFile(string graphFolder, IReadOnlyList<Model.Device> devices,
                                           bool useOnlineVersion)
        {
            Directory.CreateDirectory(graphFolder);

            return Write(graphFolder, BuildHtml(BuildGraphJson(devices), useOnlineVersion));
        }

        private static string Write(string graphFolder, string html)
        {
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
