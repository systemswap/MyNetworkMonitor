using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace MyNetworkMonitor.Platform.Windows
{
    /// <summary>
    /// Legt die Steuerpipe des Dienstes mit einer Zugriffsliste an.
    /// <para>
    /// Ohne die geht es nicht: der Dienst laeuft als LocalSystem, die
    /// Oberflaeche als angemeldeter Nutzer. Eine Pipe gehoert standardmaessig
    /// dem, der sie anlegt - der Nutzer bekaeme beim Verbinden "Zugriff
    /// verweigert", und das Fenster zeigte dauerhaft, der Dienst antworte
    /// nicht.
    /// </para>
    /// <para>
    /// Vergeben wird genau so viel, wie zum Fragen noetig ist: Lesen und
    /// Schreiben fuer die lokale Gruppe der Benutzer. Kein
    /// <c>FullControl</c> - wer die Pipe benutzen darf, soll sie deswegen
    /// nicht auch aendern duerfen.
    /// </para>
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class WindowsPipeServerFactory
    {
        public static NamedPipeServerStream Create(string name)
        {
            PipeSecurity security = new();

            // Ueber die bekannte Kennung und nicht ueber den Namen: die Gruppe
            // heisst auf einem deutschen Windows "Benutzer", die Kennung ist
            // ueberall dieselbe.
            security.AddAccessRule(new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                PipeAccessRights.ReadWrite,
                AccessControlType.Allow));

            security.AddAccessRule(new PipeAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                PipeAccessRights.FullControl,
                AccessControlType.Allow));

            return NamedPipeServerStreamAcl.Create(
                name,
                PipeDirection.InOut,
                maxNumberOfServerInstances: 1,
                PipeTransmissionMode.Byte,
                PipeOptions.Asynchronous,
                inBufferSize: 0,
                outBufferSize: 0,
                security);
        }
    }
}
