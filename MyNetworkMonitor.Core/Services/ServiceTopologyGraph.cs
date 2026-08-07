using System.Text;
using Newtonsoft.Json;

namespace MyNetworkMonitor.Core.Services
{
    /// <summary>
    /// Zweite Sicht auf dieselben Daten: nicht wer mit wem im Netz liegt,
    /// sondern wo ein Dienst ueberall laeuft.
    /// <para>
    /// Bewusst ein eigener Zweig neben <see cref="TopologyGraph"/> und nicht
    /// eine Erweiterung davon. Die Netzansicht funktioniert; eine zweite
    /// Gruppierung in dieselbe Erzeugung zu ziehen, haette beide Sichten
    /// aneinander gebunden, ohne dass sie sich etwas zu sagen haetten.
    /// </para>
    /// <para>
    /// Gebaut ist es wie die Netzansicht: eine Wolke je Dienst, sternfoermig
    /// um einen Knoten, mit dem Schild darueber. Anders ist nur, was in der
    /// Mitte steht - dort haengt nicht das erste Geraet der Gruppe, sondern
    /// der Dienst selbst.
    /// </para>
    /// <para>
    /// Die Versionen bekommen keine eigene Ebene. Als Zwischenknoten haben sie
    /// den Stern in Buescheln zerlegt und die Wolke unkenntlich gemacht; im
    /// Tooltip des Geraets stehen sie da, wo man sie sucht.
    /// </para>
    /// <para>
    /// Was keinen Dienst fuehrt, kommt nicht in den Graph. Es aufzunehmen waere
    /// richtig und trotzdem unbrauchbar: die leeren Punkte sind die Mehrzahl
    /// und verdecken das, was man sehen will.
    /// </para>
    /// </summary>
    public static class ServiceTopologyGraph
    {
        private const string OnlineLibrary =
            "<script src=\"https://cdn.jsdelivr.net/npm/3d-force-graph@1.76.2/dist/3d-force-graph.min.js\"></script>";

        private const string LocalLibrary =
            "<script src=\"./libs/3d-force-graph.min.js\"></script>";

        /// <summary>
        /// Ein Knoten im Dienstgraph. <c>kind</c> entscheidet ueber Groesse und
        /// Beschriftung, <c>group</c> ueber die Farbe - und der Dienstname als
        /// Gruppe heisst: eine Farbe je Dienst, ueber alle Netze hinweg.
        /// </summary>
        private sealed record Node(
            string id, string kind, string group, string label,
            string service, string versions, string network,
            string ip, string hostname, string mac, string ports, int val);

        private sealed record Link(string source, string target);

        /// <summary>
        /// Baut den Dienstgraph. Genommen wird, was am Geraet als offen vermerkt
        /// ist - dieselbe Quelle wie die Spalte "Running services", damit Graph
        /// und Tabelle nicht auseinanderlaufen.
        /// </summary>
        public static string BuildGraphJson(IReadOnlyList<Model.Device> devices)
        {
            ArgumentNullException.ThrowIfNull(devices);

            List<Node> nodes = [];
            List<Link> links = [];
            int nextId = 0;

            // Die Netzadresse je Gruppe, einmal vorab. Sie ergibt sich aus
            // allen Geraeten der Gruppe - auch aus denen ohne Dienst, die
            // selbst nicht in den Graph kommen: fuer die Adresse des Netzes
            // zaehlt jedes Mitglied.
            Dictionary<string, string> networksByGroup = devices
                .GroupBy(d => d.GroupDescription ?? string.Empty)
                .ToDictionary(
                    g => g.Key,
                    g => NetworkOf([.. g.Select(d => d.PrimaryAddress?.Info.Canonical ?? string.Empty)]));

            // Dienst → Geraete, die ihn fahren. Ein Geraet kann denselben
            // Dienst ueber mehrere Ports melden; gezaehlt wird es einmal.
            IEnumerable<IGrouping<string, (string Service, Model.Device Device, Model.DeviceServiceResult Result)>> byService =
                devices
                    .SelectMany(d => d.OpenServices.Select(s => (Service: s.ServiceName, Device: d, Result: s)))
                    .Where(x => !string.IsNullOrWhiteSpace(x.Service))
                    .GroupBy(x => x.Service, StringComparer.OrdinalIgnoreCase);

            foreach (var serviceGroup in byService.OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase))
            {
                string service = serviceGroup.Key;
                string serviceId = (nextId++).ToString();

                foreach (Model.Device device in serviceGroup
                             .Select(x => x.Device).Distinct()
                             .OrderBy(d => d.DisplayName, StringComparer.OrdinalIgnoreCase))
                {
                    string groupKey = device.GroupDescription ?? string.Empty;
                    string network = networksByGroup.TryGetValue(groupKey, out string? net) ? net : string.Empty;

                    // Die Befunde dieses Geraets zu genau diesem Dienst - ein
                    // Geraet kann ihn ueber mehrere Ports melden.
                    List<Model.DeviceServiceResult> results = [.. device.OpenServices.Where(s =>
                        string.Equals(s.ServiceName, service, StringComparison.OrdinalIgnoreCase))];

                    string deviceId = (nextId++).ToString();

                    nodes.Add(new Node(
                        id: deviceId, kind: "device", group: service,
                        label: device.DisplayName,
                        service: service,
                        versions: Join(results.SelectMany(VersionsOf)),
                        network: NetworkLabel(network, groupKey),
                        ip: device.PrimaryAddress?.Info.Canonical ?? string.Empty,
                        hostname: device.HostName ?? string.Empty,
                        mac: device.MacText ?? string.Empty,
                        ports: PortsOf(results),
                        val: 1));

                    links.Add(new Link(serviceId, deviceId));
                }

                // Der Dienstknoten steht bewusst hinter seinen Geraeten in der
                // Liste: die Kraftsimulation zieht den spaeter eingefuegten
                // Knoten in die Mitte dessen, woran er haengt - genau dorthin,
                // wo die Mitte der Wolke sein soll.
                nodes.Add(new Node(
                    id: serviceId, kind: "service", group: service, label: service,
                    service: service,
                    versions: Join(serviceGroup.SelectMany(x => VersionsOf(x.Result))),
                    network: string.Empty,
                    ip: string.Empty, hostname: string.Empty, mac: string.Empty,
                    ports: PortsOf(serviceGroup.Select(x => x.Result)), val: 12));
            }

            return JsonConvert.SerializeObject(new { nodes, links }, Formatting.Indented);
        }

        /// <summary>
        /// Die Versionen eines Dienstes. Steht im Protokoll ein
        /// "... versions: a, b", sind das die Staende; sonst meldet der Dienst
        /// keine, und es bleibt bei der Feststellung, dass er laeuft.
        /// </summary>
        private static IReadOnlyList<string> VersionsOf(Model.DeviceServiceResult service)
        {
            string? log = service.PortLog;
            if (string.IsNullOrWhiteSpace(log)) return [];

            int marker = log.IndexOf("versions:", StringComparison.OrdinalIgnoreCase);
            if (marker < 0) return [];

            return [.. log[(marker + "versions:".Length)..]
                .Split([',', ';', '\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(p => p.Length > 0)];
        }

        private static string Join(IEnumerable<string> values) =>
            string.Join(", ", values.Where(v => v.Length > 0)
                                    .Distinct(StringComparer.OrdinalIgnoreCase)
                                    .Order(StringComparer.OrdinalIgnoreCase));

        private static string PortsOf(IEnumerable<Model.DeviceServiceResult> services)
        {
            List<int> ports = [.. services.SelectMany(s => s.Ports).Distinct().Order()];
            return ports.Count == 0 ? string.Empty : string.Join(", ", ports);
        }

        /// <summary>Netzadresse, ersatzweise die Beschreibung - eines von beidem gibt es immer.</summary>
        private static string NetworkLabel(string network, string groupDescription) =>
            network.Length > 0
                ? (groupDescription.Length > 0 ? $"{network} ({groupDescription})" : network)
                : (groupDescription.Length > 0 ? groupDescription : "not specified");

        /// <summary>
        /// Die gemeinsame Netzadresse einer Gruppe, aus den Adressen ihrer
        /// Mitglieder abgelesen. Dieselbe Ueberlegung wie in der Netzansicht,
        /// nur hier schon in C#, weil das Netz beim Bauen des Graphs gebraucht
        /// wird und nicht erst beim Zeichnen.
        /// </summary>
        private static string NetworkOf(IReadOnlyList<string> addresses)
        {
            List<string> ips = [.. addresses.Where(a => !string.IsNullOrWhiteSpace(a))];
            if (ips.Count == 0) return string.Empty;

            if (ips.All(ip => ip.Contains('.') && !ip.Contains(':')))
            {
                foreach (int length in (int[])[3, 2])
                {
                    string prefix = string.Join('.', ips[0].Split('.').Take(length));

                    if (ips.All(ip => string.Join('.', ip.Split('.').Take(length)) == prefix))
                    {
                        return prefix + (length == 3 ? ".0/24" : ".0.0/16");
                    }
                }

                return string.Empty;
            }

            // IPv6: nur der gemeinsame Blockanfang, ohne eine Praefixlaenge zu
            // behaupten - die abgekuerzte Schreibweise laesst sich nicht zaehlen.
            string[] blocks = ips[0].Split(':');
            int shared = 0;

            while (shared < blocks.Length && blocks[shared].Length > 0)
            {
                int index = shared;
                if (!ips.All(ip =>
                    {
                        string[] parts = ip.Split(':');
                        return index < parts.Length && parts[index] == blocks[index];
                    }))
                {
                    break;
                }

                shared++;
            }

            return shared > 0 ? string.Join(':', blocks.Take(shared)) + "::" : string.Empty;
        }

        /// <summary>
        /// Dieselbe Seite wie in der Netzansicht, mit dem Unterschied, dass die
        /// Schilder ueber den Dienstwolken stehen statt ueber den Netzen.
        /// </summary>
        public static string BuildHtml(string graphJson, bool useOnlineVersion)
        {
            string libraryTag = useOnlineVersion ? OnlineLibrary : LocalLibrary;

            return $@"
<!DOCTYPE html>
<html lang=""de"">
<head>
    <meta charset=""UTF-8"">
    <title>Service Topology</title>

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

        /* Die Schilder liegen als HTML ueber der Zeichenflaeche und nicht als
           Objekt in der Szene - so behalten sie beim Zoomen ihre Groesse. */
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
        <b>Service topology</b><br>
        One cloud per service: the service in the middle, the devices running it around it.<br>
        <span style=""opacity:.75"">Only devices that actually run a service are drawn.
        Versions and ports are in the tooltip.</span>
    </div>

    <div id=""3d-graph""></div>
    <div id=""net-labels""></div>
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
                    .nodeVal(node => node.val)
                    .nodeLabel(node => {{
                        if (node.kind === 'service') {{
                            return node.service
                                 + (node.versions ? ' # versions ' + node.versions : '')
                                 + (node.ports ? ' # ports ' + node.ports : '');
                        }}
                        return node.service + ' # ' + node.label + ' # ' + node.ip
                             + ' # ' + node.hostname + ' # ' + node.mac
                             + ' # ' + node.network
                             + (node.versions ? ' # versions ' + node.versions : '')
                             + (node.ports ? ' # ports ' + node.ports : '');
                    }})
                    .linkDirectionalParticles(0)
                    .linkWidth(1)
                    .linkColor(() => 'white');

        // Ein Schild je Dienstwolke, aufgehaengt ueber dem obersten Knoten der
        // Wolke - genau wie in der Netzansicht, nur dass die Wolke hier ein
        // Dienst ist und kein Netz.
        const labelLayer = document.getElementById('net-labels');
        const netLabels = [];

        (function buildServiceLabels() {{
            const byService = new Map();

            graphData.nodes.forEach(node => {{
                const key = node.service || '';
                if (!key) return;
                if (!byService.has(key)) byService.set(key, []);
                byService.get(key).push(node);
            }});

            byService.forEach((members, key) => {{
                const devices = members.filter(n => n.kind === 'device').length;

                const element = document.createElement('div');
                element.className = 'net-label';
                element.style.borderColor = members[0].color || '#666666';

                const head = document.createElement('span');
                head.className = 'net-ip';
                head.textContent = key;
                element.appendChild(head);

                const description = document.createElement('span');
                description.className = 'net-desc';
                description.textContent = devices === 1 ? '1 device' : devices + ' devices';
                element.appendChild(description);

                labelLayer.appendChild(element);
                netLabels.push({{ members: members, element: element }});
            }});
        }})();

        // Jedes Schild folgt seiner Wolke: waagerecht mittig, senkrecht ueber
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
        /// Schreibt die Seite in den Graph-Ordner und liefert ihren Pfad. Der
        /// Dateiname unterscheidet sich vom Netzgraph, damit beide Sichten
        /// nebeneinander im Ordner liegen bleiben.
        /// </summary>
        public static string WriteHtmlFile(string graphFolder, IReadOnlyList<Model.Device> devices,
                                           bool useOnlineVersion)
        {
            Directory.CreateDirectory(graphFolder);

            string html = BuildHtml(BuildGraphJson(devices), useOnlineVersion);
            string fileName = $"service_topology_{DateTime.Now:yyyyMMdd_HHmmss}.html";
            string filePath = Path.Combine(graphFolder, fileName);

            File.WriteAllText(filePath, html, new UTF8Encoding(true));
            return filePath;
        }
    }
}