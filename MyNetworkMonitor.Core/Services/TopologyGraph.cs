// SPDX-License-Identifier: LicenseRef-MyNetworkMonitor
using System.Data;
using System.Text;
using Newtonsoft.Json;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Generates the data of the 3D topology from the scan results. Deliberately
    /// free of any UI dependency, so every view produces the same rendering.
    /// </summary>
    public static class TopologyGraph
    {
        private const string OnlineLibrary =
            "<script src=\"https://cdn.jsdelivr.net/npm/3d-force-graph@1.76.2/dist/3d-force-graph.min.js\"></script>";

        private const string LocalLibrary =
            "<script src=\"./libs/3d-force-graph.min.js\"></script>";

        /// <summary>A node in the network graph; property names are the JSON names used by the page.</summary>
        private sealed record Node(string id, string group, string label, string hostname, string ip, string mac, string lookupIPs);

        /// <summary>
        /// An edge in the graph. The flags are not mutually exclusive - the same
        /// two devices can share an address and a name -; the coloring picks the
        /// more severe one.
        /// </summary>
        private sealed record Link(
            string source, string target,
            bool isLookup, bool isDuplicatedIP, bool isDuplicatedHostname,
            bool isDuplicatedMac, bool isDnsConflict);

        /// <summary>
        /// Builds the graph from the device model.
        /// <para>
        /// Unlike the <see cref="DataTable"/> variant, nothing is regrouped here;
        /// the graph takes what <see cref="Model.DuplicateDetector"/> has already
        /// determined - two places answering the same question independently
        /// sooner or later give different answers. The edges themselves still
        /// have to be created here: the detector records on the device
        /// <em>that</em> something is duplicated, not with whom.
        /// </para>
        /// </summary>
        /// <param name="devices">The scanned devices.</param>
        /// <returns>The graph as JSON with <c>nodes</c> and <c>links</c> for 3d-force-graph.</returns>
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

            // Attach devices of the same group as a star to the first node.
            foreach (IGrouping<string, Model.Device> group in devices.GroupBy(d => d.GroupDescription))
            {
                List<Model.Device> members = [.. group];
                if (members.Count <= 1) continue;

                foreach (Model.Device member in members.Skip(1))
                {
                    links.Add(new Link(ids[members[0]], ids[member], false, false, false, false, false));
                }
            }

            // Duplicated address. Link-local addresses are excluded for the same
            // reason as in the detector: fe80::1 per interface is no duplicate
            // assignment.
            Pair(devices
                    .SelectMany(d => d.Addresses
                        .Where(a => a.Info.Scope != Network.IpAddressScope.LinkLocal)
                        .Select(a => (Key: a.Info.Canonical, Device: d)))
                    .GroupBy(x => x.Key, x => x.Device, StringComparer.OrdinalIgnoreCase),
                 (a, b) => new Link(a, b, false, true, false, false, false));

            Pair(devices.Where(d => !string.IsNullOrWhiteSpace(d.HostName))
                        .GroupBy(d => d.HostName, StringComparer.OrdinalIgnoreCase),
                 (a, b) => new Link(a, b, false, false, true, false, false));

            // The name points to an address at which another device answers.
            // This edge would not exist without DNS - and it is the only one
            // connecting two devices that otherwise touch nowhere.
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
        /// Builds nodes and edges as JSON from the result table. Edges come from
        /// group membership, from LookUpIPs and from duplicates (IP, host name,
        /// MAC) - the latter in both directions so they stand out in the graph.
        /// </summary>
        /// <param name="resultTable">The scan result table.</param>
        /// <returns>The graph as JSON with <c>nodes</c> and <c>links</c> for 3d-force-graph.</returns>
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

            // Attach devices of the same IP group as a star to the first node.
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

            // LookUpIPs only connect if the target IP is itself a device in the table.
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

            // Record each duplicate only once - IP beats host name beats MAC.
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

                    // The result table does not record whether a lookup
                    // points nowhere - the field exists only so both variants
                    // produce the same shape.
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
        /// Embeds the graph data in the HTML page. The library comes either from
        /// the CDN (then the file can be passed on by itself) or from the local
        /// libs/ folder.
        /// </summary>
        /// <param name="graphJson">The graph from <c>BuildGraphJson</c>.</param>
        /// <param name="useOnlineVersion">Load 3d-force-graph from the CDN instead of the bundled copy.</param>
        /// <returns>The complete HTML page.</returns>
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
        /// Writes the HTML file into the graph folder and returns its path.
        /// The file name carries a timestamp so successive visualizations are
        /// kept.
        /// </summary>
        /// <param name="graphFolder">The target folder; created if missing.</param>
        /// <param name="resultTable">The scan result table.</param>
        /// <param name="useOnlineVersion">Load 3d-force-graph from the CDN instead of the bundled copy.</param>
        /// <returns>The full path of the written HTML file.</returns>
        public static string WriteHtmlFile(string graphFolder, DataTable resultTable, bool useOnlineVersion)
        {
            Directory.CreateDirectory(graphFolder);

            return Write(graphFolder, BuildHtml(BuildGraphJson(resultTable), useOnlineVersion));
        }

        /// <summary>The same file, built from the device model.</summary>
        /// <param name="graphFolder">The target folder; created if missing.</param>
        /// <param name="devices">The scanned devices.</param>
        /// <param name="useOnlineVersion">Load 3d-force-graph from the CDN instead of the bundled copy.</param>
        /// <returns>The full path of the written HTML file.</returns>
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
        /// Copies the bundled 3d-force-graph library into the libs/ subfolder of
        /// the graph folder so the offline variant works. If the source file is
        /// missing, nothing happens - then only the online variant works.
        /// </summary>
        /// <param name="graphFolder">The graph folder that receives the libs/ subfolder.</param>
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
                // Without the local library, the online variant remains usable.
            }
        }
    }
}
