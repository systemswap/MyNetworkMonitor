using System.Net.Sockets;
using System.Text;
using static MyNetworkMonitor.ServiceScanData;

namespace MyNetworkMonitor.Core.Scanning.ServiceScans
{
    /// <summary>
    /// SECS/GEM ueber HSMS (SEMI E37). Halbleiter- und Elektronikfertigung:
    /// die Anlage spricht mit dem Leitsystem, ueblich ist Port 5000.
    /// <para>
    /// HSMS kennt zwei Rollen. Wer <em>passiv</em> ist, wartet auf die
    /// Verbindung - das ist die Seite, die hier gefunden werden kann. Wer
    /// <em>aktiv</em> ist, baut sie selbst auf und hat gar keinen offenen
    /// Port; solche Anlagen sind ueber diesen Weg grundsaetzlich nicht
    /// sichtbar, egal wie lange gesucht wird.
    /// </para>
    /// </summary>
    public sealed class SecsGemProbe : ServiceProbeBase
    {
        public override ServiceType Service => ServiceType.SecsGem;
        public override string Group => ServiceGroups.Industrial;

        /// <summary>
        /// 5000 ist die Gewohnheit, nicht die Vorschrift - HSMS schreibt
        /// keinen Port vor. 5001 und 5002 kommen dort vor, wo mehrere Anlagen
        /// oder mehrere Schnittstellen auf einem Rechner liegen. Wer es anders
        /// eingerichtet hat, traegt es in der Dienstverwaltung nach.
        /// </summary>
        public override IReadOnlyList<int> DefaultPorts => [5000, 5001, 5002];

        /// <summary>
        /// Select.req - die Frage, mit der jede HSMS-Verbindung beginnt.
        /// <para>
        /// Vier Byte Laenge (10), dann der Kopf: Sitzungsnummer 0xFFFF, zwei
        /// unbenutzte Byte, PType 0 (SECS-II), SType 1 (Select.req) und vier
        /// Byte laufende Nummer, die die Antwort wieder nennen muss.
        /// </para>
        /// </summary>
        public override byte[] Hello => Frame(0xFFFF, 0x00, 0x00, SType.SelectReq, HelloSystemBytes);

        /// <summary>
        /// Feste laufende Nummer im Erkennungspaket, damit die Spalte
        /// "HelloBytePackage" der Dienstverwaltung bei jedem Start dieselben
        /// Bytes zeigt. Fuer die Auskunft danach wird gezaehlt.
        /// </summary>
        private const uint HelloSystemBytes = 0x00000001;

        /// <summary>
        /// Eine Antwort passt, wenn sie ein HSMS-Rahmen ist und ihre
        /// Steuernachricht eine ist, die auf ein Select.req folgen darf.
        /// <para>
        /// Nicht nur Select.rsp: eine Anlage, die bereits mit ihrem Leitsystem
        /// verbunden ist, laesst keine zweite Sitzung zu und antwortet mit
        /// Reject.req. Das ist kein Fehlschlag der Erkennung, sondern ihr
        /// staerkster Beleg - so antwortet nur, wer HSMS spricht.
        /// </para>
        /// </summary>
        public override bool Identify(byte[] response)
        {
            if (!TryReadHeader(response, out Header header)) return false;

            return header.PType == 0 && header.SType is
                SType.SelectRsp or SType.DeselectRsp or SType.LinktestRsp or SType.RejectReq;
        }

        /// <summary>
        /// Was die Select-Antwort selbst schon sagt. Die Auskunft ueber die
        /// Anlage folgt in <see cref="InterrogateAsync"/> auf derselben
        /// Verbindung.
        /// <para>
        /// Diese Zeile steht immer, auch wenn danach nichts mehr kommt - sie
        /// ist der Beleg, dass die Sitzung zustande kam, und haelt zugleich den
        /// Standardsatz "Antwort passt zum erwarteten Protokoll" aus dem
        /// Protokoll heraus, der in der Detailansicht nichts verloren haette.
        /// </para>
        /// </summary>
        protected override string? Describe(byte[] response)
        {
            if (!TryReadHeader(response, out Header header)) return null;

            if (header.SType == SType.RejectReq)
            {
                // Der Grund steht in Byte 3 des Kopfes. Der haeufige Fall ist
                // eine Anlage, deren einzige erlaubte Sitzung schon vergeben ist.
                return $"HSMS select rejected (reason {header.Byte3}) - link probably already in use.";
            }

            if (header.SType != SType.SelectRsp) return "HSMS answered, but did not open a session.";

            // Select-Status ungleich 0: 1 heisst "bereits aktiv", 2 "nicht
            // bereit", 3 "schon verbunden".
            return header.Byte3 == 0
                ? "HSMS select accepted."
                : $"HSMS select refused (status {header.Byte3}).";
        }

        /// <summary>
        /// Die Frage, wer da steht - auf der Verbindung, die schon steht.
        /// <para>
        /// Genau darauf kommt es an, und es war der Grund, warum die Auskunft
        /// zunaechst ausblieb: eine Anlage, die auf ihr Leitsystem wartet,
        /// stellt sich <em>von sich aus</em> vor, sobald eine Sitzung
        /// zustandekommt - gemessen rund 800 ms nach der Select-Antwort. Wer
        /// dafuer eine zweite Verbindung aufbaut, bekommt nichts: die Anlage
        /// hat ihren Versuch gerade an die erste gerichtet und wartet danach
        /// den T5-Zeitgeber ab, ehe sie es erneut versucht. Zehn Sekunden, die
        /// kein Scan abwartet.
        /// </para>
        /// <para>
        /// Gefragt wird mit S1F1 "Are You There" - und nur dann mit S1F13, wenn
        /// die Dienstverwaltung es ausdruecklich erlaubt. Warum das eine
        /// Entscheidung des Betreibers ist und keine der Sonde, steht bei
        /// <see cref="ProbeContext.ActiveInquiry"/>.
        /// </para>
        /// </summary>
        protected override async Task<string?> InterrogateAsync(
            NetworkStream stream, byte[] firstResponse, ProbeContext context, CancellationToken token)
        {
            if (!TryReadHeader(firstResponse, out Header select)) return null;

            // Ohne zustandegekommene Sitzung gibt es nichts zu fragen.
            if (select.SType != SType.SelectRsp || select.Byte3 != 0) return null;

            List<string> lines = [];

            try
            {
                // Die Select-Antwort und die Vorstellung koennen im selben Stueck
                // angekommen sein - TCP kennt keine Nachrichtengrenzen. Dann steht
                // die Auskunft schon da und muss nicht erfragt werden.
                if (firstResponse.Length > 14)
                {
                    AppendFrom(lines, firstResponse.AsSpan(14).ToArray());
                }

                if (lines.Count == 0)
                {
                    await AskAsync(stream, context, token);

                    Message? answer = await ReadDataAsync(stream, token);

                    if (answer is not null)
                    {
                        AppendIdentity(lines, answer.Body, answer.Header.SessionId);
                        await AcknowledgeAsync(stream, answer, token);
                    }
                }
            }
            finally
            {
                await SeparateAsync(stream);
            }

            return lines.Count == 0 ? null : string.Join(Environment.NewLine, lines);
        }

        /// <summary>
        /// Liest eine Vorstellung aus einem Stueck, das hinter der Select-Antwort
        /// noch im selben Puffer lag.
        /// </summary>
        private static void AppendFrom(List<string> lines, byte[] trailing)
        {
            if (!TryReadHeader(trailing, out Header header)) return;
            if (header.SType != SType.Data || header.Byte3 == 0) return;
            if (trailing.Length < 14) return;

            AppendIdentity(lines, trailing[14..], header.SessionId);
        }

        /// <summary>
        /// Der zweite Anlauf fuer einen Port, der zwar offen ist, aber auf das
        /// Erkennungspaket geschwiegen hat.
        /// </summary>
        public override async Task<PortResult> ProbeAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            PortResult portResult = await base.ProbeAsync(context, address, port, token);

            if (portResult.Status == PortStatus.Open)
            {
                Knock knock = await KnockAgainAsync(context, address, port, token);

                if (knock.Note is not null)
                {
                    portResult.Status = PortStatus.IsRunning;

                    // Wer erst auf den zweiten Anlauf geantwortet hat, ist
                    // erkannt - aber die Auskunft darunter setzt eine Sitzung
                    // voraus, die es hier gerade nicht gibt.
                    portResult.PortLog = knock.Note;
                    return portResult;
                }

                if (knock.Silent)
                {
                    // Der Port nimmt jede Verbindung an und schweigt zu allem.
                    // Das ist kein Fund - auf 5000 kann alles Moegliche sitzen -,
                    // aber es ist genau das Bild, das eine belegte Anlage
                    // abgibt: HSMS-SS kennt nur eine Sitzung, und wer sie
                    // bereits an sein Leitsystem vergeben hat, laesst ein
                    // zweites Select unbeantwortet liegen.
                    //
                    // Darum bleibt es beim offenen Port, nur mit einer
                    // Erklaerung daneben. Wer sie liest, sucht den Fehler nicht
                    // mehr im Scanner.
                    const string Silent =
                        "Connection accepted, but HSMS select and linktest stayed unanswered - " +
                        "typical of an HSMS passive endpoint whose single session is already taken.";

                    string? before = portResult.PortLog?.TrimEnd();

                    portResult.PortLog = string.IsNullOrWhiteSpace(before)
                        ? Silent
                        : before + Environment.NewLine + Silent;
                }

                return portResult;
            }

            // HSMS steht fest, aber die Anlage hat sich in der Basispruefung
            // nicht vorgestellt. Ein kurzer zweiter Anlauf lohnt trotzdem: die
            // Basispruefung hat nur ein knappes Zeitfenster, und ein
            // Aufnahmewunsch, der eine Regung zu spaet kam, faellt hier noch an.
            //
            // Laenger zu warten bringt nichts, siehe <see cref="IntroductionWaitMs"/>.
            if (portResult.Status == PortStatus.IsRunning &&
                portResult.PortLog?.Contains(ModelPrefix, StringComparison.Ordinal) != true)
            {
                string? late = await WaitForIntroductionAsync(context, address, port, token);

                if (late is not null)
                {
                    string? before = portResult.PortLog?.TrimEnd();

                    portResult.PortLog = string.IsNullOrWhiteSpace(before)
                        ? late
                        : before + Environment.NewLine + late;
                }
            }

            return portResult;
        }

        /// <summary>Die Zeile, an der eine geglueckte Vorstellung zu erkennen ist.</summary>
        private const string ModelPrefix = "Model: ";

        /// <summary>
        /// Wie lange einer bestaetigten HSMS-Gegenstelle noch zugehoert wird,
        /// nachdem die Sitzung stand.
        /// <para>
        /// Bewusst knapp, aus zwei Gruenden. Erstens stellt eine Anlage, die es
        /// tut, sich sofort vor - gemessen binnen 200 bis 800 Millisekunden,
        /// nachdem das Select bestaetigt ist; tut sie es nicht, tut sie es auch
        /// in zwanzig Sekunden nicht, sondern wartet auf eine Antwort, die ein
        /// Scanner nicht geben darf. 21 Sekunden Warten brachten in drei von
        /// vier Laeufen nichts ausser 21 Sekunden.
        /// </para>
        /// <para>
        /// Zweitens, und wichtiger: HSMS-SS kennt nur <b>eine</b> Sitzung.
        /// Solange die Sonde sie haelt, kommt das echte Leitsystem nicht herein.
        /// Die ganze Sitzung dauert gemessen rund 330 Millisekunden, und
        /// unmittelbar nach dem Separate.req nimmt die Anlage wieder an - so
        /// soll es bleiben.
        /// </para>
        /// </summary>
        private const int IntroductionWaitMs = 2500;

        /// <summary>
        /// Eroeffnet eine Sitzung und hoert zu, bis die Anlage sich vorstellt.
        /// <c>null</c>, wenn sie es in der Zeit nicht tut.
        /// <para>
        /// Gefragt wird nicht mehr: S1F1 laesst diese Anlage unbeantwortet, wie
        /// es GEM fuer den Zustand "nicht kommunizierend" vorsieht - nur auf
        /// eine falsche Geraetenummer kommt ein S9F1 zurueck. Die Vorstellung
        /// kommt allein aus ihrem eigenen S1F13, und das kommt, wenn ihr Takt
        /// es will.
        /// </para>
        /// </summary>
        private static async Task<string?> WaitForIntroductionAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            try
            {
                using var client = new TcpClient();

                Task connect = client.ConnectAsync(address, port, token).AsTask();
                if (await Task.WhenAny(connect, Task.Delay(context.TimeoutMs, token)) != connect) return null;
                await connect;

                NetworkStream stream = client.GetStream();

                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
                timeout.CancelAfter(IntroductionWaitMs);
                CancellationToken listen = timeout.Token;

                await stream.WriteAsync(Frame(0xFFFF, 0x00, 0x00, SType.SelectReq, 1), listen);

                Message? select = await ReadMessageAsync(stream, listen);
                if (select is null || select.Header.SType != SType.SelectRsp || select.Header.Byte3 != 0) return null;

                List<string> lines = [];

                try
                {
                    // Auch hier gefragt und nicht nur gelauscht: der erste Anlauf
                    // ist an seiner knappen Zeitgrenze gescheitert, nicht daran,
                    // dass die Anlage nichts zu sagen haette.
                    await AskAsync(stream, context, listen);

                    Message? introduction = await ReadDataAsync(stream, listen);

                    if (introduction is not null)
                    {
                        AppendIdentity(lines, introduction.Body, introduction.Header.SessionId);
                        await AcknowledgeAsync(stream, introduction, listen);
                    }
                }
                finally
                {
                    await SeparateAsync(stream);
                }

                return lines.Count == 0 ? null : string.Join(Environment.NewLine, lines);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                // Zeitlimit oder abgebrochene Verbindung: der Fund bleibt, die
                // Vorstellung entfaellt.
                return null;
            }
        }

        /// <summary>
        /// Der zweite Anlauf fuer einen Port, der offen ist, aber auf das
        /// Erkennungspaket geschwiegen hat. <c>null</c>, wenn auch hier nichts
        /// kommt - dann bleibt es beim blossen offenen Port.
        /// <para>
        /// Zwei Gruende, warum eine HSMS-Gegenstelle ein Select.req wortlos
        /// verwirft. Erstens die Sitzungsnummer: das Erkennungspaket traegt
        /// 0xFFFF, wie es fuer Steuernachrichten ueblich ist, aber manche
        /// Umsetzungen von HSMS-SS erwarten dort die eingerichtete
        /// Geraetenummer und schweigen zu jeder anderen. Zweitens die Lage der
        /// Gegenstelle: wer schon verbunden ist, antwortet auf ein zweites
        /// Select mitunter gar nicht.
        /// </para>
        /// <para>
        /// Darum hier erst Select mit den ueblichen Geraetenummern und zuletzt
        /// ein Linktest - die Nachricht, mit der HSMS prueft, ob die Leitung
        /// noch steht. Ohne eroeffnete Sitzung muss die Gegenseite ihn
        /// zurueckweisen, und genau diese Zurueckweisung ist die Auskunft: so
        /// antwortet nur, wer HSMS spricht.
        /// </para>
        /// </summary>
        /// <summary>
        /// Das Ergebnis des zweiten Anlaufs. <paramref name="Note"/> traegt die
        /// Zeile einer geglueckten Antwort, <paramref name="Silent"/> sagt, ob
        /// die Gegenseite die Verbindung angenommen und dann bis zum Zeitlimit
        /// geschwiegen hat.
        /// <para>
        /// Der Unterschied ist wichtiger, als er aussieht: <em>schweigen</em>
        /// tut eine belegte Anlage, <em>zuschlagen</em> tut jeder fremde Dienst,
        /// der mit unseren Bytes nichts anfangen kann. Ohne die Unterscheidung
        /// bekam ein RDP-Port die Erklaerung angehaengt, die nur einer
        /// HSMS-Gegenstelle zusteht.
        /// </para>
        /// </summary>
        private readonly record struct Knock(string? Note, bool Silent);

        /// <inheritdoc cref="Knock"/>
        private static async Task<Knock> KnockAgainAsync(
            ProbeContext context, string address, int port, CancellationToken token)
        {
            // Kuerzer als im ersten Anlauf: hier geht es nur um die Frage, ob
            // ueberhaupt geantwortet wird.
            int timeoutMs = Math.Min(context.TimeoutMs, 1500);

            (ushort Session, byte SType, string Note)[] knocks =
            [
                (0, SType.SelectReq, "HSMS answered on session 0."),
                (1, SType.SelectReq, "HSMS answered on session 1."),
                (0xFFFF, SType.LinktestReq, "HSMS linktest answered without a session.")
            ];

            bool silent = false;

            foreach ((ushort session, byte sType, string note) in knocks)
            {
                token.ThrowIfCancellationRequested();

                try
                {
                    using var client = new TcpClient();

                    Task connect = client.ConnectAsync(address, port, token).AsTask();
                    if (await Task.WhenAny(connect, Task.Delay(timeoutMs, token)) != connect) continue;
                    await connect;

                    NetworkStream stream = client.GetStream();

                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
                    timeout.CancelAfter(timeoutMs);

                    await stream.WriteAsync(Frame(session, 0x00, 0x00, sType, 1), timeout.Token);

                    Message? answer = await ReadMessageAsync(stream, timeout.Token);

                    if (answer is not null && answer.Header.PType == 0) return new Knock(note, false);

                    // Ohne Antwort zurueck heisst: die Gegenseite hat die
                    // Verbindung von sich aus beendet oder etwas geschickt, das
                    // kein HSMS ist. Beides ist kein Schweigen.
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    throw;
                }
                catch (OperationCanceledException)
                {
                    // Das eigene Zeitlimit - die Verbindung stand, und es kam
                    // bis zuletzt nichts. Genau das tut eine belegte Anlage.
                    silent = true;
                }
                catch (Exception)
                {
                    // Zugeschlagene Verbindung, Socketfehler: dieser Anlauf hat
                    // nichts gebracht, der naechste vielleicht.
                }
            }

            return new Knock(null, silent);
        }

        /// <summary>
        /// Was in S1F2 steht: eine Liste aus Modellname (MDLN) und
        /// Softwarestand (SOFTREV), beides Text.
        /// <para>
        /// Dieselben zwei Texte stehen in S1F13, mit dem eine Anlage die
        /// Kommunikation von sich aus aufnehmen will. Gemessen an einer
        /// laufenden Anlage ist das sogar der haeufigere Weg: sie wartet auf
        /// ihren Host, und kaum steht die Sitzung, stellt sie sich unaufgefordert
        /// vor - noch bevor die eigene Frage ueberhaupt beantwortet ist. Darum
        /// wird hier gelesen, was an Text dasteht, und nicht, welche Nachricht
        /// es war.
        /// </para>
        /// <para>
        /// Beide duerfen leer sein - eine Anlage, die nur bestaetigt, dass sie
        /// da ist, schickt zwei leere Texte. Dann steht wenigstens fest, unter
        /// welcher Geraetenummer sie antwortet, und das ist fuer die Anbindung
        /// die eigentlich gesuchte Angabe.
        /// </para>
        /// </summary>
        private static void AppendIdentity(List<string> lines, byte[] body, ushort deviceId)
        {
            List<string> texts = [.. ReadTexts(body)];

            string model = texts.Count > 0 ? texts[0] : string.Empty;
            string revision = texts.Count > 1 ? texts[1] : string.Empty;

            // Ohne Modellnamen ist es keine Vorstellung. Die Geraetenummer
            // allein waere keine Auskunft ueber die Anlage, sondern nur die
            // Notiz, dass irgendeine Nachricht kam - in der Detailansicht stand
            // dann "Device ID: 0" und sonst nichts.
            if (model.Length == 0) return;

            lines.Add($"Device ID: {deviceId}");
            lines.Add($"{ModelPrefix}{model}");

            if (revision.Length > 0) lines.Add($"Software revision: {revision}");
        }

        /// <summary>
        /// Die Texte einer SECS-II-Nachricht, in der Reihenfolge, in der sie
        /// stehen.
        /// <para>
        /// Aufbau eines Elements: ein Byte, dessen obere sechs Bit das Format
        /// nennen und dessen untere zwei sagen, wie viele Byte die Laenge
        /// belegt - danach die Laenge, danach der Inhalt. Format 0 ist eine
        /// Liste, deren Laenge die Zahl ihrer Elemente ist und die selbst
        /// keinen Inhalt hat; Format 16 ist Text. Alles andere wird
        /// uebersprungen, denn hier werden nur Namen gesucht.
        /// </para>
        /// </summary>
        private static IEnumerable<string> ReadTexts(byte[] body)
        {
            const int Ascii = 16;
            const int List = 0;

            int at = 0;

            // Grenze gegen eine Nachricht, die sich selbst im Kreis beschreibt:
            // mehr Elemente als Byte kann es nicht geben.
            for (int guard = 0; guard <= body.Length && at < body.Length; guard++)
            {
                int format = body[at] >> 2;
                int lengthBytes = body[at] & 0x03;

                if (lengthBytes == 0) yield break;
                if (at + 1 + lengthBytes > body.Length) yield break;

                int length = 0;
                for (int i = 0; i < lengthBytes; i++) length = length << 8 | body[at + 1 + i];

                at += 1 + lengthBytes;

                // Eine Liste hat keinen eigenen Inhalt; ihre Elemente folgen
                // unmittelbar und werden im naechsten Durchgang gelesen.
                if (format == List) continue;

                if (at + length > body.Length) yield break;

                if (format == Ascii)
                {
                    yield return Printable(Encoding.ASCII.GetString(body, at, length), 64);
                }

                at += length;
            }
        }

        /// <summary>
        /// Stellt die Frage nach der Identitaet - alle Fassungen davon, und
        /// zwar hintereinander, bevor auf eine Antwort gewartet wird.
        /// <para>
        /// Beide Fragen gehen hintereinander raus, bevor gelesen wird - die
        /// Geraetenummer steht in der Sitzungsnummer, kennt nur, wer die Anlage
        /// eingerichtet hat, und auf eine falsche kommt hoechstens ein S9F1,
        /// das ohnehin uebergangen wird. Nacheinander gefragt und gelesen
        /// haette die erste Nummer das ganze Zeitbudget verbraucht.
        /// </para>
        /// <para>
        /// Gefragt wird allein mit S1F1 "Are You There". <b>Kein S1F13</b> -
        /// und das ist keine Feinheit, sondern an dieser Anlage gemessen: auf
        /// ein S1F13 antwortet sie zwar zuverlaessig mit dem gewuenschten
        /// S1F14, geht dabei aber in den kommunizierenden Zustand und haelt den
        /// Fragenden fuer ihr Leitsystem. Binnen einer halben Sekunde kamen
        /// darauf eine Alarmmeldung "Communication ok" und laufend S6F1 mit
        /// echten Produktionsdaten - Losnummern, Messwerte. Wo Spooling
        /// eingerichtet ist, koennte die Anlage sie als zugestellt verbuchen,
        /// und dem echten Leitsystem fehlten sie. Ein Scanner fragt, er nimmt
        /// keine Daten entgegen, die jemand anderem gehoeren.
        /// </para>
        /// <para>
        /// Der Preis dafuer ist, dass eine Anlage, die S1F1 im Zustand "nicht
        /// kommunizierend" liegen laesst - GEM erlaubt es -, sich nur von sich
        /// aus vorstellt. Das tut sie beim ersten Kontakt nach einer Ruhephase
        /// zuverlaessig.
        /// </para>
        /// </summary>
        private static async Task AskAsync(
            NetworkStream stream, ProbeContext context, CancellationToken token)
        {
            foreach (ushort deviceId in (ushort[])[0, 1])
            {
                await stream.WriteAsync(Frame(deviceId, 0x81, 0x01, SType.Data, 10u + deviceId), token);
            }

            if (!context.ActiveInquiry) return;

            // Nur auf ausdruecklichen Wunsch: die Frage, die eine Antwort
            // erzwingt - und den Zustand der Anlage veraendert. Siehe
            // <see cref="ProbeContext.ActiveInquiry"/>.
            foreach (ushort deviceId in (ushort[])[0, 1])
            {
                await stream.WriteAsync(
                    Frame(deviceId, 0x81, 0x0D, SType.Data, 20u + deviceId, EstablishRequest), token);
            }
        }

        /// <summary>
        /// Der Rumpf eines S1F13: <c>L,2 { MDLN, SOFTREV }</c>, beide leer.
        /// <para>
        /// Leer ist zulaessig und hier das Richtige: die beiden Felder sagen,
        /// wer <em>fragt</em>, und ein Scanner ist kein Leitsystem mit Modell
        /// und Ausgabestand. Die Antwort haengt nicht davon ab.
        /// </para>
        /// </summary>
        private static readonly byte[] EstablishRequest = [0x01, 0x02, 0x41, 0x00, 0x41, 0x00];

        /// <summary>
        /// Quittiert den Aufnahmewunsch einer Anlage - S1F14 auf ihr S1F13 -
        /// und zwar ablehnend.
        /// <para>
        /// Ohne diese Antwort wartet die Anlage auf ihren T3-Zeitgeber, ehe sie
        /// den naechsten Versuch startet; gemessen blieb sie danach knapp eine
        /// Minute stumm, und ein zweiter Scan in dieser Zeit bekam nur noch
        /// "select accepted" ohne Modell. Quittiert steht ihr Zyklus sofort
        /// wieder bereit.
        /// </para>
        /// <para>
        /// COMMACK ist mit Absicht <b>1</b> - "nicht angenommen". Eine 0 hiesse
        /// "angenommen" und wuerde die Anlage in den kommunizierenden Zustand
        /// versetzen: sie haette dann ein Leitsystem, das keines ist. Mit der 1
        /// endet nur ihr Warten auf eine Antwort, ihr Zustand bleibt, was er
        /// war, und gespoolte Ereignisse bleiben, wo sie sind - die holt nur
        /// ab, wer sich wirklich anmeldet.
        /// </para>
        /// <para>
        /// Die laufende Nummer der Anfrage muss zurueckgespiegelt werden, sonst
        /// ordnet die Anlage die Antwort ihrer Frage nicht zu und wartet weiter.
        /// </para>
        /// </summary>
        private static async Task AcknowledgeAsync(
            NetworkStream stream, Message request, CancellationToken token)
        {
            // Ohne W-Bit erwartet die Gegenseite keine Antwort - dann waere
            // eine ungefragte Quittung selbst ein Protokollfehler.
            if ((request.Header.Byte2 & 0x80) == 0) return;
            if (request.Header.Byte3 != 13) return;

            // L,2 { COMMACK = 1, L,2 { MDLN = "", SOFTREV = "" } }
            byte[] body =
            [
                0x01, 0x02,
                0x21, 0x01, 0x01,
                0x01, 0x02,
                0x41, 0x00,
                0x41, 0x00
            ];

            await stream.WriteAsync(
                Frame(request.Header.SessionId, 0x01, 0x0E, SType.Data, request.Header.SystemBytes, body),
                token);
        }

        /// <summary>
        /// Loest die eigene Sitzung auf: Separate.req, das Trennsignal von
        /// HSMS. Die Gegenseite weiss damit sofort, dass die Leitung frei ist,
        /// und wartet auf keinen Zeitgeber.
        /// <para>
        /// Steht bei jedem Aufrufer in einem <c>finally</c>, und das ist der
        /// Punkt: der haeufigste Ausgang ist eine Anlage, die nichts sagt und
        /// das Lesen in sein Zeitlimit laufen laesst. Stand das Trennen
        /// dahinter, wurde es genau dann uebersprungen, wenn es am ehesten
        /// gebraucht wird.
        /// </para>
        /// <para>
        /// Mit eigener, kurzer Zeitgrenze statt des uebergebenen Tokens - das
        /// ist an dieser Stelle meist schon abgelaufen, und mit ihm wuerde das
        /// Schreiben abgewiesen, bevor ein Byte das Haus verlaesst. Auch ein
        /// abgebrochener Lauf soll sich noch ordentlich verabschieden; es
        /// kostet Mikrosekunden.
        /// </para>
        /// <para>
        /// Dass die Sitzung <em>haengen</em> bleibt, kann trotzdem nicht
        /// passieren: sie lebt nur innerhalb der TCP-Verbindung, und die wird
        /// in jedem Fall geschlossen. Separate.req macht das Ende nur
        /// ausdruecklich, statt es die Gegenseite aus dem Verbindungsabbau
        /// schliessen zu lassen.
        /// </para>
        /// </summary>
        private static async Task SeparateAsync(NetworkStream stream)
        {
            try
            {
                using CancellationTokenSource quick = new(SeparateTimeoutMs);

                await stream.WriteAsync(Frame(0xFFFF, 0x00, 0x00, SType.SeparateReq, 99), quick.Token);
            }
            catch (Exception)
            {
                // Hoeflichkeit, kein Ergebnis. Ist die Verbindung schon weg,
                // ist auch die Sitzung weg - dann war nichts mehr zu trennen.
            }
        }

        /// <summary>Zeitgrenze fuer das Trennsignal - es geht raus oder gar nicht.</summary>
        private const int SeparateTimeoutMs = 500;

        /// <summary>Die Steuernachrichten von HSMS, wie SEMI E37 sie nummeriert.</summary>
        private static class SType
        {
            public const byte Data = 0;
            public const byte SelectReq = 1;
            public const byte SelectRsp = 2;
            public const byte DeselectRsp = 4;
            public const byte LinktestReq = 5;
            public const byte LinktestRsp = 6;
            public const byte RejectReq = 7;
            public const byte SeparateReq = 9;
        }

        /// <summary>Der Kopf einer HSMS-Nachricht - zehn Byte hinter der Laenge.</summary>
        private readonly record struct Header(
            ushort SessionId, byte Byte2, byte Byte3, byte PType, byte SType, uint SystemBytes);

        private sealed record Message(Header Header, byte[] Body);

        /// <summary>
        /// Liest den Kopf aus einem Puffer, so wie die Basispruefung ihn
        /// vorliegen hat: vier Byte Laenge, dann der Kopf.
        /// </summary>
        private static bool TryReadHeader(byte[] response, out Header header)
        {
            header = default;

            if (response is null || response.Length < 14) return false;

            uint length = (uint)(response[0] << 24 | response[1] << 16 | response[2] << 8 | response[3]);

            // Kuerzer als der Kopf gibt es nicht, und eine Nachricht von mehr
            // als einem Megabyte ist kein HSMS mehr, sondern ein Zufallstreffer
            // in einem fremden Protokoll.
            if (length < 10 || length > 0x100000) return false;

            header = new Header(
                (ushort)(response[4] << 8 | response[5]),
                response[6],
                response[7],
                response[8],
                response[9],
                (uint)(response[10] << 24 | response[11] << 16 | response[12] << 8 | response[13]));

            return true;
        }

        /// <summary>Eine fertige Nachricht: vier Byte Laenge, zehn Byte Kopf, dann der Inhalt.</summary>
        private static byte[] Frame(
            ushort sessionId, byte byte2, byte byte3, byte sType, uint systemBytes, byte[]? body = null)
        {
            body ??= [];

            uint length = (uint)(10 + body.Length);
            byte[] frame = new byte[4 + length];

            frame[0] = (byte)(length >> 24);
            frame[1] = (byte)(length >> 16);
            frame[2] = (byte)(length >> 8);
            frame[3] = (byte)length;

            frame[4] = (byte)(sessionId >> 8);
            frame[5] = (byte)sessionId;
            frame[6] = byte2;
            frame[7] = byte3;
            frame[8] = 0x00;        // PType 0: der Inhalt ist SECS-II
            frame[9] = sType;

            frame[10] = (byte)(systemBytes >> 24);
            frame[11] = (byte)(systemBytes >> 16);
            frame[12] = (byte)(systemBytes >> 8);
            frame[13] = (byte)systemBytes;

            body.CopyTo(frame, 14);

            return frame;
        }

        /// <summary>
        /// Wartet auf eine Datennachricht und beantwortet nebenher, was die
        /// Gegenseite an Steuernachrichten dazwischenschiebt.
        /// <para>
        /// Ein Linktest ist der Herzschlag von HSMS: bleibt er unbeantwortet,
        /// wirft die Anlage die Sitzung weg - mitten in der Frage, auf deren
        /// Antwort hier gewartet wird.
        /// </para>
        /// </summary>
        private static async Task<Message?> ReadDataAsync(NetworkStream stream, CancellationToken token)
        {
            // Gelesen wird, bis die Vorstellung kommt oder die Zeit ausgeht -
            // nicht eine feste Zahl von Nachrichten lang. Dazwischen liegt, was
            // eine Anlage sonst noch schickt: Linktests, und ein S9F1 fuer jede
            // Geraetenummer, die nicht ihre eigene ist. Wer die erste beliebige
            // Nachricht nimmt, haelt so ein S9F1 fuer die Antwort und traegt
            // eine Geraetenummer ohne Modell in die Details.
            while (!token.IsCancellationRequested)
            {
                Message? message = await ReadMessageAsync(stream, token);
                if (message is null) return null;

                if (message.Header.SType == SType.LinktestReq)
                {
                    await stream.WriteAsync(
                        Frame(0xFFFF, 0x00, 0x00, SType.LinktestRsp, message.Header.SystemBytes),
                        token);

                    continue;
                }

                if (message.Header.SType != SType.Data) continue;

                // Stream 1, Funktion 2, 13 oder 14: die Antwort auf "Are You
                // There", der Aufnahmewunsch der Anlage und die Antwort auf
                // unseren eigenen. Alle drei tragen Modellname und
                // Softwarestand, und nur sie sind eine Vorstellung.
                int stream1 = message.Header.Byte2 & 0x7F;

                if (stream1 == 1 && message.Header.Byte3 is 2 or 13 or 14) return message;
            }

            return null;
        }

        /// <summary>Eine Nachricht mit Laengenvorsatz: vier Byte Laenge, dann so viele Byte.</summary>
        private static async Task<Message?> ReadMessageAsync(NetworkStream stream, CancellationToken token)
        {
            byte[]? head = await ReadExactAsync(stream, 4, token);
            if (head is null) return null;

            uint length = (uint)(head[0] << 24 | head[1] << 16 | head[2] << 8 | head[3]);
            if (length < 10 || length > 0x100000) return null;

            byte[]? rest = await ReadExactAsync(stream, (int)length, token);
            if (rest is null) return null;

            byte[] all = new byte[4 + length];
            head.CopyTo(all, 0);
            rest.CopyTo(all, 4);

            if (!TryReadHeader(all, out Header header)) return null;

            return new Message(header, rest[10..]);
        }

        private static async Task<byte[]?> ReadExactAsync(NetworkStream stream, int count, CancellationToken token)
        {
            if (count <= 0) return [];

            byte[] buffer = new byte[count];
            int got = 0;

            while (got < count)
            {
                int read = await stream.ReadAsync(buffer.AsMemory(got, count - got), token);
                if (read <= 0) return null;
                got += read;
            }

            return buffer;
        }
    }
}
