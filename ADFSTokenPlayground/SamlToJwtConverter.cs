using System;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace ADFSTokenPlayground
{
    public class SamlToJwtConverter
    {
        private SecurityTokenValidator tokenValidator;
        private readonly int tokenLifeTimeMinutes;

        public SamlToJwtConverter(SecurityTokenValidator tokenValidator, int tokenLifeTimeMinutes)
        {
            this.tokenValidator = tokenValidator;
            this.tokenLifeTimeMinutes = tokenLifeTimeMinutes;
        }

        public TokenResponse ConvertToJwt(GenericXmlSecurityToken securityToken, string appliesToAddress, string issuerName, X509Certificate2 SigningCertificate)
        {
            var subject = this.tokenValidator.ValidateSamlToken(securityToken);

            var descriptor = new SecurityTokenDescriptor
            {
                Subject = subject,
                AppliesToAddress = appliesToAddress,
                SigningCredentials = new X509SigningCredentials(SigningCertificate),
                TokenIssuerName = issuerName,
                Lifetime = new Lifetime(DateTime.UtcNow, DateTime.UtcNow.AddMinutes(tokenLifeTimeMinutes))
            };

            var jwtHandler = new JwtSecurityTokenHandler();
            var jwt = jwtHandler.CreateToken(descriptor);

            return new TokenResponse
            {
                AccessToken = jwtHandler.WriteToken(jwt),
                ExpiresIn = tokenLifeTimeMinutes
            };
        }
    }
}