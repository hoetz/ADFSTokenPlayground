using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace ADFSTokenPlayground
{
    class Program
    {
        static void Main(string[] args)
        {
            //some code in this sample is based on https://github.com/thinktecture/Thinktecture.IdentityServer.v2/tree/master/src/Libraries/Thinktecture.IdentityServer.Protocols/AdfsIntegration
            ADFSUsernameMixedTokenProvider adfsTokenProvider = new ADFSUsernameMixedTokenProvider(new Uri("https://adfs.yourcompany.com/adfs/services/trust/13/usernamemixed"));
            var token = adfsTokenProvider.RequestToken("bob", "bob", "https://app.yourcompany.com");

            SamlToJwtConverter conv = new SamlToJwtConverter(
                new SecurityTokenValidator("99558998c56a2dc3ad4c041c8e54ae93ef4d9033", "ADFS Signing - adfs.yourcompany.com"), //fill in your ADFS signing cert's thumbprint
                10080);

            var jwtResponse = conv.ConvertToJwt(token, "https://app.yourcompany.com", "app", getMyTokenSignCert());
       
        }

        private static X509Certificate2 getMyTokenSignCert()
        {
            X509Certificate2 certificate = null;

            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            certificate = store.Certificates.Find(X509FindType.FindByThumbprint, "84558998d22a2dc3ad4c041c8e54ae93ef4d9042", false)[0]; //fill in the thumbprint of the certificate you want to use for signing your jwt tokens
            return certificate;
        }
    }
}
