using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace MyNetworkMonitor.Platform.Windows
{
    /// <summary>
    /// Creates the control pipe of the service with an access control list.
    /// <para>
    /// The ACL is required: the service runs as LocalSystem, the user interface
    /// as the logged-on account. By default a pipe belongs to its creator, so
    /// connecting from the user interface fails with "access denied" and the
    /// window permanently reports that the service does not respond.
    /// </para>
    /// <para>
    /// The ACL grants exactly what querying needs: read and write for the local
    /// Users group. No <c>FullControl</c>: being allowed to use the pipe does
    /// not imply being allowed to change it.
    /// </para>
    /// </summary>
    [SupportedOSPlatform("windows")]
    public static class WindowsPipeServerFactory
    {
        /// <summary>Creates the server end of the named pipe with the access rules described above.</summary>
        /// <param name="name">Name of the pipe.</param>
        /// <returns>The pipe server stream, not yet connected.</returns>
        public static NamedPipeServerStream Create(string name)
        {
            PipeSecurity security = new();

            // Uses the well-known SID rather than the name: the group name is
            // localized (e.g. "Benutzer" on German Windows), the SID is the
            // same everywhere.
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
