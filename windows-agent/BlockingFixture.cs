using System.Threading;
using System.Reflection;
#if REMOTE
[assembly: AssemblyProduct("AnyDesk")]
[assembly: AssemblyDescription("AnyDesk remote-control fixture")]
#else
[assembly: AssemblyProduct("WindowsProtect Harmless Fixture")]
[assembly: AssemblyDescription("Harmless application fixture")]
#endif
internal static class BlockingFixture {static void Main(){Thread.Sleep(60000);}}
