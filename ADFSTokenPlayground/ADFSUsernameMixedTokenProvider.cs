using System;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.ServiceModel;
using System.ServiceModel.Security;
using Thinktecture.IdentityModel.WSTrust;

namespace ADFSTokenPlayground
{
    public class ADFSUsernameMixedTokenProvider
    {
        private readonly Uri ADFSUserNameMixedEndpoint;

        /// <summary>
        ///
        /// </summary>
        /// <param name="adfsUserNameMixedEndpoint">i.e. https://adfs.mycompany.com/adfs/services/trust/13/usernamemixed </param>
        public ADFSUsernameMixedTokenProvider(Uri adfsUserNameMixedEndpoint)
        {
            this.ADFSUserNameMixedEndpoint = adfsUserNameMixedEndpoint;
        }

        public GenericXmlSecurityToken RequestToken(string username, string password, string relyingPartyId)
        {
            var factory = new WSTrustChannelFactory(
                    new UserNameWSTrustBinding(SecurityMode.TransportWithMessageCredential),
                     new EndpointAddress(this.ADFSUserNameMixedEndpoint));

            factory.TrustVersion = TrustVersion.WSTrust13;

            factory.Credentials.UserName.UserName = username;
            factory.Credentials.UserName.Password = password;

            var rst = new RequestSecurityToken
            {
                RequestType = RequestTypes.Issue,
                AppliesTo = new EndpointReference(relyingPartyId),
                KeyType = KeyTypes.Bearer
            };
            IWSTrustChannelContract channel = factory.CreateChannel();
            GenericXmlSecurityToken genericToken = channel.Issue(rst) as GenericXmlSecurityToken;

            return genericToken;
        }
    }
}