using IdentityModel;
using IdentityModel.Client;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Runtime.Caching;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SSRS.OpenIDConnect.Security.OIDC
{
    /// <summary>
    /// Helper Class to Work with Open ID Connect Protocol
    /// </summary>
    public class OIDCUtilities
    {
        const string CACHE_DISCO = "OIDC.CACHE.DISCO";


        // Connection Details for our API
        private Uri m_authUri;

        /// <summary>
        /// Constructs a Helper Class to Query the PE Api
        /// </summary>
        /// <param name="Url">URL to a PE instance</param>
        public OIDCUtilities(Uri authUri)
        {
            m_authUri = authUri;
        }

        /// <summary>
        /// Returns the Open ID Connect Bearer Discovery Information
        /// </summary>
        /// <returns></returns>
        public DiscoveryResponse DiscoverOidcSettings()
        {
            if (!MemoryCache.Default.Contains(CACHE_DISCO))
            {
                var disco = DiscoveryClient.GetAsync(m_authUri.AbsoluteUri);
                MemoryCache.Default.Add(CACHE_DISCO, disco.Result, DateTimeOffset.Now.AddHours(2));
            }

            return MemoryCache.Default[CACHE_DISCO] as DiscoveryResponse;
        }

        /// <summary>
        /// Builds a Login Uri to redirect the user for login
        /// </summary>
        /// <returns></returns>
        public string BuildAuthorizeUrl(string state)
        {
            var nonce = Guid.NewGuid().ToString("N");
            MemoryCache.Default.Add(nonce, nonce, DateTimeOffset.Now.AddMinutes(10));
            var disco = DiscoverOidcSettings();
            var authorizeUrl = new RequestUrl(disco.AuthorizeEndpoint).CreateAuthorizeUrl(
                clientId: "pe.app",
                responseType: "id_token",
                scope: "openid profile",
                redirectUri: "http://localhost:44078/home/callback",
                state: state,
                nonce: nonce,
                responseMode: "form_post");

            return authorizeUrl;
        }

        /// <summary>
        /// Validates an Identity Token
        /// </summary>
        /// <param name="idToken">The Received ID Token</param>
        /// <returns></returns>
        public ClaimsPrincipal ValidateIdentityToken(string idToken)
        {
            var user = ValidateJwt(idToken);

            var nonce = user.FindFirst("nonce")?.Value ?? "";
            if (MemoryCache.Default[nonce] as string != nonce)
                throw new Exception("invalid nonce");

            return user;
        }

        /// <summary>
        /// Validates a JWT token
        /// </summary>
        /// <param name="jwt">the JWT Token</param>
        /// <returns></returns>
        private ClaimsPrincipal ValidateJwt(string jwt)
        {
            // read discovery document to find issuer and key material
            var disco = DiscoverOidcSettings();

            var keys = new List<SecurityKey>();
            foreach (var webKey in disco.KeySet.Keys)
            {
                var e = Base64Url.Decode(webKey.E);
                var n = Base64Url.Decode(webKey.N);

                var key = new RsaSecurityKey(new RSAParameters { Exponent = e, Modulus = n })
                {
                    KeyId = webKey.Kid
                };

                keys.Add(key);
            }

            var parameters = new TokenValidationParameters
            {
                ValidIssuer = disco.Issuer,
                ValidAudience = "pe.app",
                IssuerSigningKeys = keys,

                NameClaimType = JwtClaimTypes.Name,
                RoleClaimType = JwtClaimTypes.Role
            };

            var handler = new JwtSecurityTokenHandler();
            handler.InboundClaimTypeMap.Clear();

            var user = handler.ValidateToken(jwt, parameters, out var _);
            return user;
        }
    }
}
