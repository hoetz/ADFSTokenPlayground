using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security;
using System.Xml;
using Thinktecture.IdentityModel.Extensions;

namespace ADFSTokenPlayground
{
    public class SecurityTokenValidator
    {
        private readonly string trustedIssuerCertificateThumbPrint;
        private readonly string trustedIssuerName;

        public SecurityTokenValidator(string trustedIssuerCertificateThumbPrint, string trustedIssuerName)
        {
            this.trustedIssuerCertificateThumbPrint = trustedIssuerCertificateThumbPrint;
            this.trustedIssuerName = trustedIssuerName;
        }

        public ClaimsIdentity ValidateSamlToken(GenericXmlSecurityToken securityToken)
        {
            var _handler = SecurityTokenHandlerCollection.CreateDefaultSecurityTokenHandlerCollection();
            var tokenString = securityToken.ToTokenXmlString();

            var samlToken2 = _handler.ReadToken(new XmlTextReader(new StringReader(tokenString)));

            var configuration = new SecurityTokenHandlerConfiguration();
            configuration.AudienceRestriction.AudienceMode = AudienceUriMode.Never;
            configuration.CertificateValidationMode = X509CertificateValidationMode.None;
            configuration.RevocationMode = X509RevocationMode.NoCheck;
            configuration.CertificateValidator = X509CertificateValidator.None;

            var registry = new ConfigurationBasedIssuerNameRegistry();
            registry.AddTrustedIssuer(trustedIssuerCertificateThumbPrint, trustedIssuerName);
            configuration.IssuerNameRegistry = registry;

            var handler = SecurityTokenHandlerCollection.CreateDefaultSecurityTokenHandlerCollection(configuration);
            var identity = handler.ValidateToken(samlToken2).First();
            return identity;
        }
    }
}