using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace LDAPFragger.Core
{
    class NamedPipe
    {

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool PeekNamedPipe(SafeHandle handle, byte[] buffer, uint nBufferSize, ref uint bytesRead, ref uint bytesAvail, ref uint BytesLeftThisMessage);

        private NamedPipeClientStream pipeClient;
        private string pipeName;

        private const int MaxBufferSize = 1024 * 1024;

        public NamedPipe(string pipeName)
        {
            this.pipeName = pipeName;
            this.pipeClient = getPipe(this.pipeName);
            this.pipeClient.Connect();
        }

        /// <summary>
        ///     Reads a frame from the NamedPipe
        ///     thx: https://github.com/ryhanson/ExternalC2/blob/master/ExternalC2/Channels/BeaconChannel.cs
        /// </summary>
        /// <returns>The frame bytes</returns>
        public byte[] ReadFrame()
        {
            if (DataAvailable(this.pipeClient))
            {

                var reader = new BinaryReader(pipeClient);
                var bufferSize = reader.ReadInt32();

                var size = bufferSize > MaxBufferSize
                    ? MaxBufferSize
                    : bufferSize;

                return reader.ReadBytes(size);
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        ///     Writes a frame to the NamedPipe
        ///     thx: https://github.com/ryhanson/ExternalC2/blob/master/ExternalC2/Channels/BeaconChannel.cs
        /// </summary>
        /// <param name="buffer"></param>
        public void SendFrame(byte[] buffer)
        {
            var writer = new BinaryWriter(pipeClient);

            writer.Write(buffer.Length);
            writer.Write(buffer);
        }


        /// <summary>
        /// Receives data from the named pipe
        /// </summary>
        /// <param name="client"></param>
        /// <returns></returns>
        public byte[] Receive()
        {
            try
            {
                if (!pipeClient.IsConnected)
                    pipeClient.Connect();

                // Peek into the stream to see if we have data available
                if (DataAvailable(pipeClient))
                {
                    // Receive first 4 bytes to determine the length of the stream
                    byte[] msgLength = new byte[4];
                    pipeClient.Read(msgLength, 0, 4);

                    // frames sent by CS are 4 bytes at minimum
                    if (msgLength.Length < 4)
                        return null;

                    // read remainder of the stream
                    int iMsg = BitConverter.ToInt32(msgLength, 0);
                    byte[] buffer = new byte[iMsg];
                    pipeClient.Read(buffer, 0, iMsg);
                    return buffer;
                }

                return null;
               
            }
            catch (Exception ex)
            {
                if (this.pipeClient.IsConnected)
                    throw new Exception("Beacon died.");
                else
                    throw ex;                
            } 
        }

        /// <summary>
        /// Sends data to named pipe
        /// </summary>
        /// <param name="client"></param>
        /// <returns></returns>
        public void Send(byte[] data)
        {            
            // Add length of the byte array
            byte[] dataLen = Misc.convertToLE(data.Length);
            byte[] toSend = Misc.Combine(dataLen, data);

            if (!this.pipeClient.IsConnected)
            {
                try
                {
                    pipeClient.Connect();
                }
                catch(Exception ex) 
                {
                    // Not sure what to do right now
                    Console.WriteLine("[-] Cannot send frame over named pipe.");
                    Console.WriteLine("[-] Exception: {0}", ex.Message);
                    return;
                }

            }

            this.pipeClient.Write(toSend, 0, toSend.Length);

            this.pipeClient.Flush();
        }
        
        /// <summary>
        /// Peeks into the stream to checker whether data is available
        /// </summary>
        /// <param name="client"></param>
        /// <returns></returns>
        private static bool DataAvailable(NamedPipeClientStream client)
        {
            byte[] aPeekBuffer = new byte[4];
            uint aPeekedBytes  = 0;
            uint aAvailBytes   = 0;
            uint aLeftBytes    = 0;                        

            bool aPeekedSuccess = PeekNamedPipe(client.SafePipeHandle, aPeekBuffer, 4, ref aPeekedBytes, ref aAvailBytes, ref aLeftBytes);
            return aPeekedSuccess && aAvailBytes > 4;           
        }

        /// <summary>
        /// returns a client to interact with a named pipe
        /// </summary>
        /// <param name="pipeName"></param>
        /// <returns></returns>
        private NamedPipeClientStream getPipe(string pipeName)
        {
            NamedPipeClientStream pipeClient =
                        new NamedPipeClientStream(".", pipeName,
                            PipeDirection.InOut, PipeOptions.None,
                            TokenImpersonationLevel.Impersonation);

            return pipeClient;
        }

    }
}
