using IdentityModel.Client;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.Caching;
using System.Text;
using System.Threading.Tasks;

namespace SSRS.OpenIDConnect.Security.PE
{
    /// <summary>
    /// Helper Class to Query the PE Api
    /// </summary>
    public class PEUtilities
    {
        const string CACHE_DISCO = "PE.CACHE.DISCO";
        const string CACHE_TOKEN = "PE.CACHE.TOKEN";
        const string CACHE_GROUPS = "PE.CACHE.GROUPS";
        const string CACHE_PEUSER = "PE.USER.{0}";
        const string CACHE_USER_TOKEN = "PE.USER.TOKEN.{0}";


        // Connection Details for our API
        private string m_peAuthUrl;
        private string m_peAppUrl;
        private string m_peAppID;
        private string m_peAppKey;
        private string m_peIntegrationSecret;

        /// <summary>
        /// Constructs a Helper Class to Query the PE Api
        /// </summary>
        /// <param name="AuthUrl">URL to a PE instance</param>
        /// <param name="AppID">App ID Setup for this purpose</param>
        /// <param name="AppKey">App Key setup for this purpose</param>
        public PEUtilities(string AuthUrl, string AppUrl, string AppID, string AppKey, string IntegrationSecret)
        {
#if DEBUG
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
#endif
            m_peAuthUrl = AuthUrl;
            m_peAppUrl = AppUrl;
            m_peAppID = AppID;
            m_peAppKey = AppKey;
            m_peIntegrationSecret = IntegrationSecret;
        }

        /// <summary>
        /// Returns the Open ID Connect Bearer Discovery Information
        /// </summary>
        /// <returns></returns>
        public DiscoveryResponse DiscoverOidcSettings()
        {
            if (!MemoryCache.Default.Contains(CACHE_DISCO))
            { 
                var disco = DiscoveryClient.GetAsync(m_peAuthUrl).Result;
                if (disco.IsError)
                    throw new NullReferenceException("OIDC Discovery Failed!  Is the Authentication App running?");

                MemoryCache.Default.Add(CACHE_DISCO, disco, DateTimeOffset.Now.AddHours(2));
            }

            return MemoryCache.Default[CACHE_DISCO] as DiscoveryResponse;
        }

        /// <summary>
        /// Returns a Valid API Access Token
        /// </summary>
        /// <returns></returns>
        public TokenResponse GetApiToken()
        {
            var disco = DiscoverOidcSettings();
            var tokenClient = new TokenClient(disco.TokenEndpoint, m_peAppID, m_peAppKey, style: AuthenticationStyle.PostValues);
            var token = tokenClient.RequestClientCredentialsAsync("pe.api").Result;
            if (token.IsError)
                throw new Exception("Failed to get Access Token from OIDC Endpoint");
            return token;
        }

        /// <summary>
        /// Returns a Valid API Access Token
        /// </summary>
        /// <returns></returns>
        public bool ValidateUserCredentials(string username, string password)
        {
            var disco = DiscoverOidcSettings();
            var tokenClient = new TokenClient(disco.TokenEndpoint, "pe.ssrs", m_peIntegrationSecret, style: AuthenticationStyle.PostValues);
            var token = tokenClient.RequestResourceOwnerPasswordAsync(username, password, scope: "pe.sqlreports").Result;
            if (token.IsError)
                return false;
            return true;
        }

        /// <summary>
        /// Returns a List of All Groups
        /// </summary>
        /// <returns></returns>
        public JObject GetAdminDetails()
        {
            if (!MemoryCache.Default.Contains(CACHE_GROUPS))
            {
                var httpClient = new HttpClient();
                var token = GetApiToken();
                httpClient.SetBearerToken(token.AccessToken);
                httpClient.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

                var urlBuilder = new UriBuilder(m_peAppUrl);
                urlBuilder.Path += "api/Security/GetPermissionDetails";
                urlBuilder.Query = null;

                var response = httpClient.PostAsync(urlBuilder.Uri.AbsoluteUri, new StringContent("", Encoding.UTF8, "appliation/json")).Result;
                if (!response.IsSuccessStatusCode)
                    throw new Exception(String.Format("HTTP Failure {0} - {1}", response.StatusCode, response.ReasonPhrase));

                var json = response.Content.ReadAsStringAsync().Result;
                var jobj = JObject.Parse(json);
                var roles = jobj.Property("Roles").Value.Values<string>();


                MemoryCache.Default.Add(CACHE_GROUPS, jobj, DateTimeOffset.Now.AddMinutes(5));
            }

            return MemoryCache.Default[CACHE_GROUPS] as JObject;
        }

        /// <summary>
        /// Lists All Groups Available
        /// </summary>
        /// <returns></returns>
        public IEnumerable<string> ListAllGroups()
        {
            var adminDetails = GetAdminDetails();
            var roles = adminDetails.Property("Roles").Value.Values<string>();
            return roles;
        }

        /// <summary>
        /// Lists All Groups a user is member of
        /// </summary>
        /// <param name="username">The Username to check</param>
        /// <returns></returns>
        public IEnumerable<string> ListGroupsForUser(string username)
        {
            var adminDetails = GetAdminDetails();
            var roles = adminDetails.Property("RoleUsers").Value.Values<JObject>();
            List<string> userRoles = new List<string>();
            foreach(var role in roles)
            {
                if (role.Property("Usernames").Value.Values<string>().Contains(username))
                    userRoles.Add(role.Property("Role").Value.Value<string>());
            }

            return userRoles;
        }

        /// <summary>
        /// Validates a User
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public bool IsUserValid(string user)
        {
            // Create a Very Standard Cache Value
            var userCacheID = String.Format(CACHE_PEUSER, user.ToLower());

            if (!MemoryCache.Default.Contains(userCacheID))
            {
                // Default to False
                bool hasMatch = false;

                // Call the PE API
                var httpClient = new HttpClient();
                var token = GetApiToken();
                httpClient.SetBearerToken(token.AccessToken);
                httpClient.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

                var urlBuilder = new UriBuilder(m_peAppUrl);
                urlBuilder.Path += "api/Security/FindUsers";
                urlBuilder.Query = null;

                // Build a Request
                StringContent content = new StringContent(
                    new JObject(
                        new JProperty("MaxResults", 10),
                        new JProperty("Search", user)).ToString(Newtonsoft.Json.Formatting.None),
                    Encoding.UTF8, "application/json");

                // Execute the API
                var response = httpClient.PostAsync(urlBuilder.Uri.AbsoluteUri, content).Result;

                // Interpret the Response and cache all results
                if (response.Content.Headers.ContentLength > 0)
                {
                    var json = response.Content.ReadAsStringAsync().Result;
                    var matches = JArray.Parse(json);
                    foreach(JObject match in matches)
                    {
                        var resultLogin = match.Property("StaffUser").Value.Value<string>();
                        if (!String.IsNullOrWhiteSpace(resultLogin))
                        {
                            var resultCacheID = String.Format(CACHE_PEUSER, resultLogin.ToLower());
                            MemoryCache.Default.Add(resultCacheID, match, DateTimeOffset.Now.AddHours(1));

                            // If this user matches, set the result
                            if (resultLogin.Equals(user, StringComparison.OrdinalIgnoreCase))
                            {
                                hasMatch = true;
                            }
                        }
                    }
                }

                // Return the Result of the API Call
                return hasMatch;
            }

            // User is in Cache
            return true;
        }

        /// <summary>
        /// Returns a Principal Name
        /// </summary>
        /// <param name="principal"></param>
        /// <returns></returns>
        public bool ValidatePrincipal(string principal)
        {
            // Try Groups first
            var groups = ListAllGroups();
            if (groups.Contains(principal))
                return true;

            // Now Check the specific User
            return IsUserValid(principal);
        }
    }
}
