using IdentityModel.Client;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
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


        // Connection Details for our API
        private string m_peUrl;
        private string m_peAppID;
        private string m_peAppKey;

        /// <summary>
        /// Constructs a Helper Class to Query the PE Api
        /// </summary>
        /// <param name="Url">URL to a PE instance</param>
        /// <param name="AppID">App ID Setup for this purpose</param>
        /// <param name="AppKey">App Key setup for this purpose</param>
        public PEUtilities(string Url, string AppID, string AppKey)
        {
            m_peUrl = Url;
            m_peAppID = AppID;
            m_peAppKey = AppKey;
        }

        /// <summary>
        /// Returns the Open ID Connect Bearer Discovery Information
        /// </summary>
        /// <returns></returns>
        public DiscoveryResponse DiscoverOidcSettings()
        {
            if (!MemoryCache.Default.Contains(CACHE_DISCO))
            { 
                var urlBuilder = new UriBuilder(m_peUrl);
                urlBuilder.Path = "/auth";
                urlBuilder.Query = null;
                var disco = DiscoveryClient.GetAsync(urlBuilder.Uri.AbsoluteUri);
                MemoryCache.Default.Add(CACHE_DISCO, disco.Result, DateTimeOffset.Now.AddHours(2));
            }

            return MemoryCache.Default[CACHE_DISCO] as DiscoveryResponse;
        }

        /// <summary>
        /// Returns a Valid API Access Token
        /// </summary>
        /// <returns></returns>
        public TokenResponse GetApiToken()
        {
            if (!MemoryCache.Default.Contains(CACHE_TOKEN))
            {
                var disco = DiscoverOidcSettings();
                var tokenClient = new TokenClient(disco.TokenEndpoint, m_peAppID, m_peAppKey, style:AuthenticationStyle.PostValues);
                var token = tokenClient.RequestClientCredentialsAsync("pe.api").Result;
                MemoryCache.Default.Add(CACHE_TOKEN, token, DateTimeOffset.Now.AddSeconds((token.ExpiresIn-60)));
            }

            return MemoryCache.Default[CACHE_TOKEN] as TokenResponse;
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

                var urlBuilder = new UriBuilder(m_peUrl);
                urlBuilder.Path = "/PE/api/Security/GetPermissionDetails";
                urlBuilder.Query = null;

                var response = httpClient.PostAsync(urlBuilder.Uri.AbsoluteUri, new StringContent("")).Result;
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

                var urlBuilder = new UriBuilder(m_peUrl);
                urlBuilder.Path = "/PE/api/Security/FindUsers";
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
