using System.Collections.ObjectModel;
using System.Net.NetworkInformation;
using MyNetworkMonitor.Core.Network;

namespace MyNetworkMonitor.Core.Model
{
    /// <summary>
    /// Haelt die Geraeteliste und ordnet eingehende Sichtungen dem richtigen
    /// Geraet zu. Der Kern des neuen Modells.
    /// <para>
    /// Unter IPv4 genuegte die Adresse als Schluessel. Unter IPv6 nicht mehr:
    /// ein Geraet hat mehrere Adressen, von denen manche taeglich wechseln.
    /// Darum wird ueber eine Kaskade zugeordnet - DUID vor MAC vor Adresse vor
    /// Hostname - und Geraete werden nachtraeglich zusammengefuehrt, sobald
    /// sich herausstellt, dass zwei Eintraege dasselbe Geraet sind.
    /// </para>
    /// <para>
    /// Nicht threadsicher. Aufrufe sind ueber den UI-Dispatcher oder eine
    /// eigene Sperre zu serialisieren - so, wie es die Scan-Module heute schon
    /// mit der Ergebnisliste halten.
    /// </para>
    /// </summary>
    public sealed class DeviceStore
    {
        private readonly ObservableCollection<Device> _devices = [];

        private readonly Dictionary<string, Device> _byDuid = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, Device> _byMac = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, Device> _byHostName = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>
        /// Adresse auf Geraet - und zwar auf <em>alle</em> Geraete, die sie
        /// tragen. Die uebrigen Register kommen mit einem Wert aus, dieses
        /// nicht: eine doppelt vergebene IP ist der Befund, auf den es hier
        /// ankommt, und mit einem einwertigen Register waere das zweite Geraet
        /// beim Indizieren stillschweigend verlorengegangen.
        /// </summary>
        private readonly Dictionary<string, List<Device>> _byAddress = new(StringComparer.OrdinalIgnoreCase);

        public ReadOnlyObservableCollection<Device> Devices { get; }

        /// <summary>
        /// Die Sperre, unter der der Bestand veraendert wird. Wer waehrend
        /// eines Laufs liest - die Ergebnistabelle tut das, damit sie sich
        /// fuellt, statt am Ende auf einen Schlag zu erscheinen - muss sie
        /// ebenfalls halten. Sonst liest die Oberflaeche eine Liste, die ein
        /// Scan-Thread gerade veraendert.
        /// </summary>
        public Lock SyncRoot { get; } = new();

        /// <summary>
        /// Die Anzeigemeldungen der Geraete unterdruecken.
        /// <para>
        /// Waehrend eines Laufs melden die Scan-Module aus beliebigen Aufgaben.
        /// Solange die Tabelle die betroffene Zeile bereits zeigt, liefe die
        /// Bindung damit aus einem Hintergrund-Thread - die Oberflaeche darf
        /// aber nur vom eigenen Thread aus angefasst werden. Wer das setzt,
        /// uebernimmt es, <see cref="Device.NotifyDisplayChanged"/> selbst und
        /// am richtigen Ort nachzuholen.
        /// </para>
        /// </summary>
        public bool DeferDisplayNotifications { get; set; }

        public DeviceStore()
        {
            Devices = new ReadOnlyObservableCollection<Device>(_devices);
        }

        /// <summary>Wird nach jeder Zuordnung ausgeloest - auch wenn nur ergaenzt wurde.</summary>
        public event Action<Device>? DeviceChanged;

        /// <summary>Ein neues Geraet ist aufgetaucht.</summary>
        public event Action<Device>? DeviceAdded;

        /// <summary>
        /// Zwei Eintraege haben sich als dasselbe Geraet erwiesen. Das zweite
        /// Argument ist der aufgeloeste Eintrag und ab dann nicht mehr gueltig.
        /// </summary>
        public event Action<Device, Device>? DevicesMerged;

        /// <summary>
        /// Nimmt eine Sichtung auf und liefert das Geraet, zu dem sie gehoert.
        /// Legt es an, wenn es neu ist, und fuehrt bestehende Eintraege
        /// zusammen, wenn die Sichtung sie verbindet.
        /// </summary>
        public Device Observe(DeviceObservation observation)
        {
            ArgumentNullException.ThrowIfNull(observation);

            Device device;
            bool isNew = false;

            lock (SyncRoot)
            {
                List<Device> candidates = FindCandidates(observation);

                // Was der Sichtung widerspricht, wird nicht zusammengefuehrt,
                // sondern bleibt als eigenes Geraet stehen. Genau daran haengt
                // die Doppelbelegung: zwei Netzkarten mit derselben IP sind
                // zwei Geraete, kein Eintrag mit zwei Namen.
                if (candidates.Count > 0)
                {
                    candidates = [.. candidates.Where(c => !ContradictsObservation(c, observation))];
                }

                if (candidates.Count == 0)
                {
                    device = new Device
                    {
                        FirstSeen = observation.Timestamp,
                        LastSeen = observation.Timestamp
                    };
                    _devices.Add(device);
                    isNew = true;
                }
                else
                {
                    // Der Eintrag mit der staerksten Identitaet bleibt bestehen,
                    // die uebrigen gehen in ihm auf.
                    device = candidates.OrderBy(d => (int)d.IdentityKey).First();

                    // Auch untereinander muessen die Kandidaten zusammenpassen.
                    // Traegt die Sichtung nur eine Adresse, kann sie auf zwei
                    // Geraete mit verschiedenen MACs passen - die beiden aber
                    // deshalb zu verschmelzen, waere gerade der Fehler.
                    foreach (Device other in candidates.Where(c => !ReferenceEquals(c, device)))
                    {
                        if (Contradicts(device, other)) continue;

                        MergeInto(device, other);
                    }
                }

                Apply(device, observation);
                Reindex(device);
            }

            // Die Anzeigeeigenschaften sind berechnet und haengen an Adressen
            // und Diensten - deren Aenderungen bemerkt die Bindung nicht von
            // allein.
            if (!DeferDisplayNotifications) device.NotifyDisplayChanged();

            if (isNew) DeviceAdded?.Invoke(device);
            DeviceChanged?.Invoke(device);

            return device;
        }

        /// <summary>Leert die Liste samt aller Zuordnungen.</summary>
        public void Clear()
        {
            lock (SyncRoot)
            {
                _devices.Clear();
                _byDuid.Clear();
                _byMac.Clear();
                _byAddress.Clear();
                _byHostName.Clear();
            }
        }

        /// <summary>
        /// Ersetzt den Bestand durch gespeicherte Geraete und baut die Register
        /// neu auf.
        /// <para>
        /// Bewusst nicht ueber <see cref="Observe"/>: die Geraete sind bereits
        /// zusammengefuehrt. Sie noch einmal durch die Identitaetskaskade zu
        /// schicken, wuerde genau die Doppelbelegungen wieder verschmelzen, die
        /// beim letzten Lauf gefunden wurden.
        /// </para>
        /// </summary>
        public void LoadFrom(IEnumerable<Device> devices)
        {
            ArgumentNullException.ThrowIfNull(devices);

            lock (SyncRoot)
            {
                Clear();

                foreach (Device device in devices)
                {
                    _devices.Add(device);
                    Reindex(device);
                }
            }
        }

        /// <summary>
        /// Mischt Geraete in den Bestand, die woanders gefunden wurden - das
        /// Ergebnis eines Satelliten.
        /// <para>
        /// Wie <see cref="LoadFrom"/> bewusst <b>nicht</b> ueber
        /// <see cref="Observe"/>: die Geraete sind bereits zusammengefuehrt,
        /// und die Identitaetskaskade wuerde genau die Doppelbelegungen wieder
        /// verschmelzen, die der Satellit gefunden hat.
        /// </para>
        /// <para>
        /// Anders als <see cref="LoadFrom"/> wird der vorhandene Bestand nicht
        /// geleert: der Satellit kennt nur sein Segment, alles andere bleibt
        /// stehen. Und auch das schon bekannte Geraet wird nicht ersetzt,
        /// sondern ergaenzt - ein Satellitenlauf bringt immer nur mit, was
        /// <em>dieser</em> Auftrag gefunden hat. Wer nur die Namen nachholt,
        /// schickt ein Geraet ohne Dienste zurueck; ersetzt man damit den
        /// Eintrag, waeren die Dienstbefunde des vorherigen Laufs weg.
        /// </para>
        /// </summary>
        /// <returns>Wie viele Geraete aufgenommen wurden.</returns>
        public int MergeFrom(IEnumerable<Device> devices)
        {
            ArgumentNullException.ThrowIfNull(devices);

            int taken = 0;
            List<Device> touched = [];

            lock (SyncRoot)
            {
                foreach (Device incoming in devices)
                {
                    Device? target = FindExisting(incoming);

                    if (target is null)
                    {
                        _devices.Add(incoming);
                        Reindex(incoming);
                        touched.Add(incoming);
                    }
                    else
                    {
                        Absorb(target, incoming);
                        Reindex(target);
                        touched.Add(target);
                    }

                    taken++;
                }
            }

            // Die Anzeigeeigenschaften haengen an Adressen und Diensten - deren
            // Aenderungen bemerkt die Bindung nicht von allein. Ohne das bliebe
            // die Zeile stehen, wie sie war, obwohl der Satellit gerade etwas
            // dazugelegt hat.
            if (!DeferDisplayNotifications)
            {
                foreach (Device device in touched) device.NotifyDisplayChanged();
            }

            return taken;
        }

        /// <summary>
        /// Das vorhandene Geraet, in das die Meldung gehoert - oder
        /// <c>null</c>, wenn sie ein neues Geraet beschreibt.
        /// <para>
        /// Gesucht wird ueber dieselbe Kaskade wie bei einer Sichtung: erst die
        /// harten Kennungen, dann die Adressen. Was der Meldung widerspricht -
        /// andere MAC, andere DUID - kommt nicht in Frage; unter einer doppelt
        /// vergebenen Adresse haengen zwei Geraete, und in das falsche zu
        /// schreiben waere schlimmer, als ein drittes anzulegen.
        /// </para>
        /// </summary>
        private Device? FindExisting(Device incoming)
        {
            if (incoming.Duid is { Length: > 0 } duid &&
                _byDuid.TryGetValue(duid, out Device? byDuid) && !Contradicts(byDuid, incoming))
            {
                return byDuid;
            }

            if (incoming.Mac is not null &&
                _byMac.TryGetValue(MacKey(incoming.Mac), out Device? byMac) && !Contradicts(byMac, incoming))
            {
                return byMac;
            }

            foreach (DeviceAddress address in incoming.Addresses)
            {
                if (!_byAddress.TryGetValue(address.Info.Canonical, out List<Device>? holders)) continue;

                foreach (Device holder in holders)
                {
                    if (!Contradicts(holder, incoming)) return holder;
                }
            }

            return null;
        }

        /// <summary>
        /// Traegt ein, was der Satellit gemeldet hat. Wie
        /// <see cref="Apply(Device, DeviceObservation)"/> gilt: eine Angabe
        /// ueberschreibt die alte, eine fehlende loescht nichts. Der Satellit
        /// hat frisch nachgesehen, aber eben nur nach dem, wonach der Auftrag
        /// gefragt hat.
        /// </summary>
        private static void Absorb(Device target, Device incoming)
        {
            foreach (DeviceAddress address in incoming.Addresses)
            {
                DeviceAddress? mine = target.Addresses.FirstOrDefault(a =>
                    string.Equals(a.Info.Canonical, address.Info.Canonical, StringComparison.OrdinalIgnoreCase));

                if (mine is null)
                {
                    target.Addresses.Add(address);
                    continue;
                }

                if (address.LastSeen > mine.LastSeen) mine.LastSeen = address.LastSeen;
                if (address.FirstSeen != default && (mine.FirstSeen == default || address.FirstSeen < mine.FirstSeen))
                {
                    mine.FirstSeen = address.FirstSeen;
                }

                if (address.Origin != AddressOrigin.Unknown) mine.Origin = address.Origin;
                if (address.State != AddressState.Unknown) mine.State = address.State;
                if (address.ValidUntil is not null) mine.ValidUntil = address.ValidUntil;
                if (address.PreferredUntil is not null) mine.PreferredUntil = address.PreferredUntil;
                if (address.IsResponding) mine.IsResponding = true;
                if (!string.IsNullOrWhiteSpace(address.DiscoveredBy)) mine.DiscoveredBy = address.DiscoveredBy;
            }

            if (incoming.Duid is { Length: > 0 }) target.Duid = incoming.Duid;
            if (incoming.Mac is not null) target.Mac = incoming.Mac;

            if (!string.IsNullOrWhiteSpace(incoming.Vendor)) target.Vendor = incoming.Vendor;
            if (!string.IsNullOrWhiteSpace(incoming.HostName)) target.HostName = incoming.HostName;
            if (!string.IsNullOrWhiteSpace(incoming.Domain)) target.Domain = incoming.Domain;
            if (!string.IsNullOrWhiteSpace(incoming.NetBiosName)) target.NetBiosName = incoming.NetBiosName;
            if (!string.IsNullOrWhiteSpace(incoming.GroupDescription)) target.GroupDescription = incoming.GroupDescription;

            // Der selbst vergebene Name gehoert dem Nutzer hier und wird von
            // einem fremden Bestand nicht angetastet - nur nachgetragen, wo
            // noch keiner steht.
            if (string.IsNullOrWhiteSpace(target.InternalName)) target.InternalName = incoming.InternalName;

            // Der Lookup wird als Ganzes uebernommen, nicht ergaenzt: er
            // beschreibt den Stand im DNS zum Zeitpunkt der Abfrage.
            if (incoming.WasLookedUp)
            {
                target.WasLookedUp = true;
                target.LookupAddresses.Clear();
                target.LookupAddresses.AddRange(incoming.LookupAddresses);
            }

            foreach (string alias in incoming.Aliases.Where(a => !target.Aliases.Contains(a, StringComparer.OrdinalIgnoreCase)))
            {
                target.Aliases.Add(alias);
            }

            foreach (string source in incoming.SeenBy) target.SeenBy.Add(source);

            foreach (KeyValuePair<string, string> detail in incoming.Details)
            {
                target.Details[detail.Key] = detail.Value;
            }

            if (incoming.Ttl > 0) target.Ttl = incoming.Ttl;

            if (!string.IsNullOrWhiteSpace(incoming.SwitchName)) target.SwitchName = incoming.SwitchName;
            if (!string.IsNullOrWhiteSpace(incoming.SwitchPort)) target.SwitchPort = incoming.SwitchPort;
            if (!string.IsNullOrWhiteSpace(incoming.Vlan)) target.Vlan = incoming.Vlan;

            if (!string.IsNullOrWhiteSpace(incoming.WebTitle)) target.WebTitle = incoming.WebTitle;
            if (!string.IsNullOrWhiteSpace(incoming.CertificateSubject)) target.CertificateSubject = incoming.CertificateSubject;
            if (!string.IsNullOrWhiteSpace(incoming.CertificateIssuer)) target.CertificateIssuer = incoming.CertificateIssuer;
            if (incoming.CertificateExpires is not null) target.CertificateExpires = incoming.CertificateExpires;
            if (incoming.CertificateIsSelfSigned) target.CertificateIsSelfSigned = true;

            foreach (DeviceServiceResult service in incoming.Services)
            {
                DeviceServiceResult? mine = target.Services.FirstOrDefault(s => IsSameFinding(s, service));

                if (mine is null)
                {
                    target.Services.Add(service);
                    continue;
                }

                if (service.StatusIPv4 is not null) mine.StatusIPv4 = service.StatusIPv4;
                if (service.StatusIPv6 is not null) mine.StatusIPv6 = service.StatusIPv6;
                if (!string.IsNullOrEmpty(service.PortLog)) mine.PortLog = service.PortLog;
            }

            if (incoming.FirstSeen != default && (target.FirstSeen == default || incoming.FirstSeen < target.FirstSeen))
            {
                target.FirstSeen = incoming.FirstSeen;
            }

            if (incoming.LastSeen > target.LastSeen) target.LastSeen = incoming.LastSeen;
        }

        /// <summary>Sucht ein Geraet zu einer Adresse. Fuer Nachscans einzelner Ziele.</summary>
        public Device? FindByAddress(IpAddressInfo address) =>
            _byAddress.GetValueOrDefault(address.Canonical)?.FirstOrDefault();

        /// <summary>
        /// Alle Geraete, die diese Adresse tragen. Mehr als eines heisst, dass
        /// die Adresse doppelt vergeben ist.
        /// </summary>
        public IReadOnlyList<Device> FindAllByAddress(IpAddressInfo address) =>
            _byAddress.GetValueOrDefault(address.Canonical) ?? (IReadOnlyList<Device>)[];

        // ------------------------------------------------------- Zuordnung

        /// <summary>
        /// Sucht alle bestehenden Eintraege, auf die die Sichtung passt.
        /// Mehr als einer bedeutet, dass die Sichtung sie verbindet - dann
        /// werden sie zusammengefuehrt.
        /// </summary>
        private List<Device> FindCandidates(DeviceObservation o)
        {
            List<Device> found = [];

            void Add(Device? d)
            {
                if (d is not null && !found.Any(x => ReferenceEquals(x, d))) found.Add(d);
            }

            if (!string.IsNullOrWhiteSpace(o.Duid))
                Add(_byDuid.GetValueOrDefault(o.Duid));

            if (o.Mac is not null)
                Add(_byMac.GetValueOrDefault(MacKey(o.Mac)));

            // Eine EUI-64-Adresse traegt die MAC in sich. Damit laesst sich ein
            // ueber IPv6 gefundenes Geraet demselben Eintrag zuordnen wie das
            // ueber ARP gefundene - ohne dass jemand beides zugleich gesehen hat.
            if (o.Address?.DerivedMac is { } derived)
                Add(_byMac.GetValueOrDefault(MacKey(derived)));

            // Die weiche MAC darf zuordnen: meldet SNMP die Basis-MAC eines
            // Geraets, das schon ueber einen anderen Anschluss bekannt ist,
            // gehoert die Sichtung dorthin. Verhindern darf sie nichts - dafuer
            // sorgt ContradictsObservation, das sie nicht ansieht.
            if (o.SoftMac is not null)
                Add(_byMac.GetValueOrDefault(MacKey(o.SoftMac)));

            // Traegt die Adresse mehr als ein Geraet, kommen alle in Betracht -
            // welches davon gemeint ist, entscheidet erst die MAC-Pruefung.
            if (o.Address is not null && _byAddress.TryGetValue(o.Address.Canonical, out List<Device>? holders))
            {
                foreach (Device holder in holders) Add(holder);
            }

            // Hostnamen sind schwach: mehrere Geraete koennen denselben Namen
            // melden. Nur heranziehen, wenn sonst nichts passt.
            if (found.Count == 0 && !string.IsNullOrWhiteSpace(o.HostName))
                Add(_byHostName.GetValueOrDefault(o.HostName));

            return found;
        }

        /// <summary>
        /// Die Sichtung kann nicht zu diesem Geraet gehoeren, weil beide eine
        /// harte Kennung tragen und die sich unterscheidet.
        /// <para>
        /// Nur DUID und MAC zaehlen als hart. Ein abweichender Hostname
        /// bedeutet nichts - Geraete haben mehrere Namen. Eine fehlende Angabe
        /// auf einer der beiden Seiten widerspricht ebenfalls nicht; sie sagt
        /// nur, dass niemand nachgesehen hat.
        /// </para>
        /// <para>
        /// <see cref="DeviceObservation.SoftMac"/> bleibt ebenfalls aussen vor.
        /// SNMP liest die MAC jedes Anschlusses (ifPhysAddress) - auch die von
        /// Anschluessen, die gar nicht an diesem Netz haengen. Genommen als
        /// harte Kennung, widersprach so eine MAC der per ARP gesehenen, und
        /// dasselbe Geraet stand zweimal in der Liste.
        /// </para>
        /// </summary>
        private static bool ContradictsObservation(Device device, DeviceObservation o)
        {
            if (device.Duid is { Length: > 0 } && o.Duid is { Length: > 0 } &&
                !string.Equals(device.Duid, o.Duid, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            // Die aus EUI-64 zurueckgerechnete MAC bleibt hier aussen vor: sie
            // ist geraten, und ein geratener Wert darf keine Zuordnung
            // verhindern.
            return device.Mac is not null && o.Mac is not null && !device.Mac.Equals(o.Mac);
        }

        /// <summary>
        /// Zwei Eintraege koennen nicht dasselbe Geraet sein. Gleiche Regel wie
        /// bei <see cref="ContradictsObservation"/>.
        /// </summary>
        private static bool Contradicts(Device a, Device b)
        {
            if (a.Duid is { Length: > 0 } && b.Duid is { Length: > 0 } &&
                !string.Equals(a.Duid, b.Duid, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return a.Mac is not null && b.Mac is not null && !a.Mac.Equals(b.Mac);
        }

        /// <summary>Traegt die Angaben der Sichtung am Geraet ein.</summary>
        private void Apply(Device device, DeviceObservation o)
        {
            // Waehrend eines Laufs kommt die Sichtung aus einem Scan-Thread.
            // Jede der folgenden Zuweisungen wuerde von dort aus melden, und
            // eine gebundene Zeile verarbeitete das auf dem fremden Thread.
            // Das Nachholen uebernimmt die Liste in NotifyDisplayChanged.
            if (DeferDisplayNotifications) device.IsQuiet = true;

            if (o.Timestamp > device.LastSeen) device.LastSeen = o.Timestamp;
            if (device.FirstSeen == default || o.Timestamp < device.FirstSeen) device.FirstSeen = o.Timestamp;

            device.SeenBy.Add(o.Source);

            if (!string.IsNullOrWhiteSpace(o.Duid)) device.Duid = o.Duid;

            // Eine unmittelbar beobachtete MAC ist verlaesslicher als eine aus
            // EUI-64 zurueckgerechnete oder eine von SNMP genannte - darum nur
            // ergaenzen, nicht ueberschreiben.
            //
            // Die weiche MAC fuellt nur eine Luecke: ein Geraet, das allein
            // ueber SNMP gefunden wurde - hinter einem Router etwa, wo ARP
            // nicht hinkommt -, stuende sonst ohne MAC da. Ueberschriebe sie
            // die per ARP gesehene, waere derselbe Schaden angerichtet wie
            // vorher, nur andersherum.
            if (o.Mac is not null) device.Mac = o.Mac;
            else if (device.Mac is null && o.Address?.DerivedMac is { } derived) device.Mac = derived;
            else if (device.Mac is null && o.SoftMac is not null) device.Mac = o.SoftMac;

            if (!string.IsNullOrWhiteSpace(o.Vendor)) device.Vendor = o.Vendor;
            if (!string.IsNullOrWhiteSpace(o.HostName)) device.HostName = o.HostName;
            if (!string.IsNullOrWhiteSpace(o.Domain)) device.Domain = o.Domain;
            if (!string.IsNullOrWhiteSpace(o.NetBiosName)) device.NetBiosName = o.NetBiosName;
            if (!string.IsNullOrWhiteSpace(o.GroupDescription)) device.GroupDescription = o.GroupDescription;

            // Der Lookup wird als Ganzes uebernommen, nicht ergaenzt: er
            // beschreibt den Stand im DNS zum Zeitpunkt der Abfrage. Alte
            // Adressen dazuzumischen wuerde genau den Befund verwischen, um den
            // es geht.
            if (o.LookupAddresses is not null)
            {
                device.WasLookedUp = true;
                device.LookupAddresses.Clear();
                device.LookupAddresses.AddRange(o.LookupAddresses);
            }

            if (o.Aliases is not null)
            {
                foreach (string alias in o.Aliases.Where(a => !device.Aliases.Contains(a, StringComparer.OrdinalIgnoreCase)))
                {
                    device.Aliases.Add(alias);
                }
            }

            if (o.Details is not null)
            {
                foreach (KeyValuePair<string, string> detail in o.Details)
                {
                    device.Details[detail.Key] = detail.Value;
                }
            }

            // Eine gemessene TTL ersetzt die vorherige, eine fehlende loescht
            // nichts: nur der Ping fuellt das Feld, jede andere Sichtung traegt
            // dort eine 0 und wuerde die Messung sonst wieder ausradieren.
            if (o.Ttl > 0) device.Ttl = o.Ttl;

            if (!string.IsNullOrWhiteSpace(o.SwitchName)) device.SwitchName = o.SwitchName;
            if (!string.IsNullOrWhiteSpace(o.SwitchPort)) device.SwitchPort = o.SwitchPort;
            if (!string.IsNullOrWhiteSpace(o.Vlan)) device.Vlan = o.Vlan;

            if (!string.IsNullOrWhiteSpace(o.WebTitle)) device.WebTitle = o.WebTitle;
            if (!string.IsNullOrWhiteSpace(o.CertificateSubject)) device.CertificateSubject = o.CertificateSubject;
            if (!string.IsNullOrWhiteSpace(o.CertificateIssuer)) device.CertificateIssuer = o.CertificateIssuer;
            if (o.CertificateExpires is not null) device.CertificateExpires = o.CertificateExpires;
            if (o.CertificateIsSelfSigned is { } selfSigned) device.CertificateIsSelfSigned = selfSigned;

            if (o.Address is not null) ApplyAddress(device, o);
            if (o.Services is not null) ApplyServices(device, o);
        }

        /// <summary>
        /// Traegt Dienstbefunde ein. Ein Verfahren prueft immer nur eine
        /// Adressfamilie, darum wird je Seite gesetzt und die andere nicht
        /// angetastet - sonst wuerde der IPv4-Lauf den IPv6-Befund loeschen
        /// und die Gegenueberstellung ginge verloren.
        /// <para>
        /// Zusammengefasst wird nach Dienst <b>und</b> Ports. Ein Dienst wird
        /// gegen mehrere Ports geprueft - "WebServices" etwa gegen 80, 443,
        /// 8080 und weitere - und liefert je Port einen eigenen Befund. Wuerde
        /// allein der Name den Ausschlag geben, landeten alle neun Befunde auf
        /// einem Eintrag und der zuletzt eingetroffene ueberschriebe den Rest:
        /// eine Webseite auf Port 80 verschwaende, weil Port 8443 danach
        /// nicht geantwortet hat.
        /// </para>
        /// </summary>
        private static void ApplyServices(Device device, DeviceObservation o)
        {
            foreach (DeviceServiceResult incoming in o.Services!)
            {
                // Ein Port, den ein Verfahren namentlich erkannt hat, braucht
                // daneben keine Zeile "TCP {Port}" - das ist dieselbe Tuer,
                // einmal mit Namen. In welcher Reihenfolge die Befunde
                // eintreffen, ist nicht festgelegt, darum beide Richtungen:
                // der Platzhalter weicht dem Namen, und wo schon ein Name
                // steht, kommt kein Platzhalter mehr dazu.
                if (IsOpenPortPlaceholder(incoming))
                {
                    if (device.Services.Any(s => !IsOpenPortPlaceholder(s) && s.IsRunning && Covers(s, incoming)))
                        continue;
                }
                else if (incoming.IsRunning)
                {
                    device.Services.RemoveAll(s => IsOpenPortPlaceholder(s) && Covers(incoming, s));
                }

                DeviceServiceResult? existing = device.Services.FirstOrDefault(s => IsSameFinding(s, incoming));

                if (existing is null)
                {
                    device.Services.Add(incoming);
                    continue;
                }

                if (incoming.StatusIPv4 is not null) existing.StatusIPv4 = incoming.StatusIPv4;
                if (incoming.StatusIPv6 is not null) existing.StatusIPv6 = incoming.StatusIPv6;
                if (!string.IsNullOrEmpty(incoming.PortLog)) existing.PortLog = incoming.PortLog;
            }
        }

        /// <summary>
        /// Derselbe Befund: gleicher Dienst an genau denselben Ports. Erst das
        /// macht aus dem IPv4- und dem IPv6-Lauf eine Zeile und laesst zugleich
        /// die einzelnen Ports desselben Dienstes nebeneinander bestehen.
        /// </summary>
        /// <summary>
        /// Ein offener Port ohne erkannten Dienst - "TCP 3306", "UDP 5353".
        /// Angelegt wird er von den Verfahren, deren Sonde zwar eine
        /// Verbindung bekam, aber keine passende Antwort.
        /// </summary>
        private static bool IsOpenPortPlaceholder(DeviceServiceResult s) =>
            string.Equals(s.Category, "Open ports", StringComparison.OrdinalIgnoreCase);

        /// <summary>Der benannte Befund deckt den Port des Platzhalters ab.</summary>
        private static bool Covers(DeviceServiceResult named, DeviceServiceResult placeholder) =>
            placeholder.Ports.Count == 1 && named.Ports.Contains(placeholder.Ports[0]);

        private static bool IsSameFinding(DeviceServiceResult a, DeviceServiceResult b) =>
            string.Equals(a.ServiceName, b.ServiceName, StringComparison.OrdinalIgnoreCase) &&
            a.Ports.Count == b.Ports.Count &&
            !a.Ports.Except(b.Ports).Any();

        private static void ApplyAddress(Device device, DeviceObservation o)
        {
            IpAddressInfo info = o.Address!;

            DeviceAddress? existing = device.Addresses
                .FirstOrDefault(a => string.Equals(a.Info.Canonical, info.Canonical, StringComparison.OrdinalIgnoreCase));

            if (existing is null)
            {
                existing = new DeviceAddress
                {
                    Info = info,
                    FirstSeen = o.Timestamp,
                    LastSeen = o.Timestamp,
                    DiscoveredBy = o.Source
                };
                device.Addresses.Add(existing);
            }
            else if (o.Timestamp > existing.LastSeen)
            {
                existing.LastSeen = o.Timestamp;
            }

            if (o.Origin != AddressOrigin.Unknown) existing.Origin = o.Origin;
            if (o.State != AddressState.Unknown) existing.State = o.State;
            if (o.ValidUntil is not null) existing.ValidUntil = o.ValidUntil;
            if (o.PreferredUntil is not null) existing.PreferredUntil = o.PreferredUntil;
            if (o.IsResponding) existing.IsResponding = true;
        }

        /// <summary>
        /// Fuehrt <paramref name="other"/> in <paramref name="target"/> zusammen
        /// und entfernt es aus der Liste. Bestehende Angaben am Ziel bleiben
        /// stehen; der aufgeloeste Eintrag fuellt nur Luecken.
        /// </summary>
        private void MergeInto(Device target, Device other)
        {
            foreach (DeviceAddress address in other.Addresses)
            {
                bool alreadyThere = target.Addresses.Any(a =>
                    string.Equals(a.Info.Canonical, address.Info.Canonical, StringComparison.OrdinalIgnoreCase));

                if (!alreadyThere) target.Addresses.Add(address);
            }

            target.Duid ??= other.Duid;
            target.Mac ??= other.Mac;

            if (string.IsNullOrWhiteSpace(target.Vendor)) target.Vendor = other.Vendor;
            if (string.IsNullOrWhiteSpace(target.HostName)) target.HostName = other.HostName;
            if (string.IsNullOrWhiteSpace(target.Domain)) target.Domain = other.Domain;
            if (string.IsNullOrWhiteSpace(target.NetBiosName)) target.NetBiosName = other.NetBiosName;
            if (string.IsNullOrWhiteSpace(target.InternalName)) target.InternalName = other.InternalName;
            if (string.IsNullOrWhiteSpace(target.GroupDescription)) target.GroupDescription = other.GroupDescription;

            if (!target.WasLookedUp && other.WasLookedUp)
            {
                target.WasLookedUp = true;
                target.LookupAddresses.AddRange(other.LookupAddresses);
            }

            foreach (string alias in other.Aliases.Where(a => !target.Aliases.Contains(a, StringComparer.OrdinalIgnoreCase)))
            {
                target.Aliases.Add(alias);
            }

            foreach (string source in other.SeenBy) target.SeenBy.Add(source);

            foreach (KeyValuePair<string, string> detail in other.Details)
            {
                target.Details.TryAdd(detail.Key, detail.Value);
            }

            foreach (DeviceServiceResult service in other.Services)
            {
                DeviceServiceResult? mine = target.Services
                    .FirstOrDefault(s => IsSameFinding(s, service));

                if (mine is null)
                {
                    target.Services.Add(service);
                }
                else
                {
                    mine.StatusIPv4 ??= service.StatusIPv4;
                    mine.StatusIPv6 ??= service.StatusIPv6;
                    mine.PortLog ??= service.PortLog;
                }
            }

            if (other.FirstSeen != default && other.FirstSeen < target.FirstSeen) target.FirstSeen = other.FirstSeen;
            if (other.LastSeen > target.LastSeen) target.LastSeen = other.LastSeen;

            RepointIndexes(other, target);
            _devices.Remove(other);

            DevicesMerged?.Invoke(target, other);
        }

        // -------------------------------------------------------- Register

        private void Reindex(Device device)
        {
            if (!string.IsNullOrWhiteSpace(device.Duid)) _byDuid[device.Duid] = device;
            if (device.Mac is not null) _byMac[MacKey(device.Mac)] = device;
            if (!string.IsNullOrWhiteSpace(device.HostName)) _byHostName[device.HostName] = device;

            foreach (DeviceAddress address in device.Addresses)
            {
                List<Device> holders = _byAddress.TryGetValue(address.Info.Canonical, out List<Device>? existing)
                    ? existing
                    : _byAddress[address.Info.Canonical] = [];

                if (!holders.Any(d => ReferenceEquals(d, device))) holders.Add(device);
            }
        }

        /// <summary>
        /// Haengt alle Eintraege, die auf <paramref name="from"/> zeigen, auf
        /// <paramref name="to"/> um - statt sie zu entfernen.
        /// <para>
        /// Ein Geraet kann unter mehreren Schluesseln bekannt sein: zwei MACs
        /// bei WLAN und Kabel, mehrere Hostnamen, viele Adressen. Wuerden die
        /// Schluessel des aufgeloesten Eintrags geloescht, laege dieselbe
        /// Sichtung spaeter wieder als neues Geraet vor.
        /// </para>
        /// </summary>
        private void RepointIndexes(Device from, Device to)
        {
            Repoint(_byDuid);
            Repoint(_byMac);
            Repoint(_byHostName);

            void Repoint(Dictionary<string, Device> index)
            {
                foreach (string key in index.Where(kv => ReferenceEquals(kv.Value, from))
                                            .Select(kv => kv.Key)
                                            .ToList())
                {
                    index[key] = to;
                }
            }

            // Im Adressregister steht der aufgeloeste Eintrag moeglicherweise
            // neben einem weiteren Halter derselben Adresse - er wird darum
            // ersetzt, nicht die ganze Liste.
            foreach (List<Device> holders in _byAddress.Values)
            {
                for (int i = holders.Count - 1; i >= 0; i--)
                {
                    if (!ReferenceEquals(holders[i], from)) continue;

                    if (holders.Any(d => ReferenceEquals(d, to))) holders.RemoveAt(i);
                    else holders[i] = to;
                }
            }
        }

        /// <summary>
        /// Einheitlicher Schluessel fuer eine MAC. <see cref="PhysicalAddress"/>
        /// als Schluessel taugt nicht - es vergleicht nach Referenz.
        /// </summary>
        private static string MacKey(PhysicalAddress mac) =>
            Convert.ToHexString(mac.GetAddressBytes());
    }
}
