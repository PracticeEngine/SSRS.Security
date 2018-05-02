using Microsoft.ReportingServices.Interfaces;
using SSRS.OpenIDConnect.Security.PE;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Security.Principal;
using System.Timers;
using System.Web;
using System.Xml;

namespace SSRS.OpenIDConnect.Security
{
    public class SSRSAuthentication : IAuthenticationExtension2
    {

        #region Static IdentityManagement
        /// <summary>
        ///  Dictionary of GCHandles for Identities by Username
        /// </summary>
        static ConcurrentDictionary<string, GCHandle> staticIdentities = new ConcurrentDictionary<string, GCHandle>();

        /// <summary>
        /// List of when to Free the GCHandles
        /// </summary>
        static ConcurrentDictionary<string, DateTimeOffset> cleanUpList = new ConcurrentDictionary<string, DateTimeOffset>();

        /// <summary>
        /// Our Cleanup Timer
        /// </summary>
        static Timer cleanupTimer;

        /// <summary>
        /// Static Constructor to setup our Cleanup Timer
        /// </summary>
        static SSRSAuthentication()
        {
            cleanupTimer = new Timer(TimeSpan.FromMinutes(1).TotalMilliseconds);
            cleanupTimer.AutoReset = true;
            cleanupTimer.Elapsed += CleanupTimer_Elapsed;
            cleanupTimer.Start();
        }

        /// <summary>
        /// Cleanup Event - Free Unused Identities
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private static void CleanupTimer_Elapsed(object sender, ElapsedEventArgs e)
        {
            foreach(var cleanUp in cleanUpList)
            {
                if (cleanUp.Value < DateTimeOffset.Now)
                {
                    // Remove the Idenity and Free the Handle so GC can Happen
                    GCHandle handle;
                    if (staticIdentities.TryRemove(cleanUp.Key, out handle)) {
                        handle.Free();
                    }

                    // Ensure the Item is removed from the cleanup list
                    DateTimeOffset expires;
                    cleanUpList.TryRemove(cleanUp.Key, out expires);
                }
            }
        }

        #endregion Static IdentityManagement

        // Configuration Items (read from rsreportserver.config Configuration File)
        private string m_oidcAuthority;
        private string m_peAppUrl;
        private string m_peAppID;
        private string m_peAppKey;
        private string m_peIntegrationSecret;


        public string LocalizedName
        {
            get
            {
                return null;
            }
        }

        public void GetUserInfo(out IIdentity userIdentity, out IntPtr userId)
        {
            // If the current user identity is not null,
            // set the userIdentity parameter to that of the current user 
            if (HttpContext.Current != null
                  && HttpContext.Current.User != null)
            {

                // This is the custom bit - Create a Custom PE Identity
                var handle = GetIdentityHandle(HttpContext.Current.User.Identity.Name);
                userIdentity = (ClaimsIdentity)handle.Target;
                userId = GCHandle.ToIntPtr(handle);
            }
            else
            {
                // No Anonymous Access
                userIdentity = null;
                userId = IntPtr.Zero;
            }
        }

        public void GetUserInfo(IRSRequestContext requestContext, out IIdentity userIdentity, out IntPtr userId)
        {
            userIdentity = null;
            if (requestContext.User != null)
            {
                // This is the custom bit - Create a Custom PE Identity
                var handle = GetIdentityHandle(requestContext.User.Name);
                userIdentity = (ClaimsIdentity)handle.Target;
                userId = GCHandle.ToIntPtr(handle);
            }
            else
            {
                // No Anonymous Access
                userIdentity = null;
                userId = IntPtr.Zero;
            }
        }

        /// <summary>
        /// Checks to see if the user is valid
        /// </summary>
        /// <param name="principalName"></param>
        /// <returns></returns>
        public bool IsValidPrincipalName(string principalName)
        {
            var peUtils = new PEUtilities(m_oidcAuthority, m_peAppUrl, m_peAppID, m_peAppKey, m_peIntegrationSecret);
            return peUtils.ValidatePrincipal(principalName);
        }

        /// <summary>
        /// Supports WebService Logins (via SSMS or calling the .asmx Web Services)
        /// </summary>
        /// <param name="userName">Username for the User</param>
        /// <param name="password">Password to verify with the Open Id Provider</param>
        /// <param name="authority">Not used if password is provided.  If no password is empty, a valid OIDC AccessToken can be sent here</param>
        /// <returns></returns>
        public bool LogonUser(string userName, string password, string authority)
        {
            // Support Basic Password Authentication
            if (!String.IsNullOrWhiteSpace(userName) && !String.IsNullOrWhiteSpace(password))
            {
                var peUtils = new PEUtilities(m_oidcAuthority, m_peAppUrl, m_peAppID, m_peAppKey, m_peIntegrationSecret);
                return peUtils.ValidateUserCredentials(userName, password);
            }
            // Also support passing in a validatable token as Authority
            if (!String.IsNullOrWhiteSpace(userName) && !String.IsNullOrWhiteSpace(authority))
            {
                var oidcUtils = new OIDC.OIDCUtilities(new Uri(m_oidcAuthority));
                // Do not validate the Nonce as this was not an interactive login
                var principal = oidcUtils.ValidateIdentityToken(authority, false);
                return userName.Equals(principal.Identity.Name);
            }
            return false;
        }

        /// <summary>
        /// Called at Startup to Configure the Extension
        /// </summary>
        /// <param name="configuration"></param>
        public void SetConfiguration(string configuration)
        {
            /* This method has a nasty bug - the RSPortal.exe passes the innerText value instead of the innerXML value.
             * This means sometimes we are passed a string of the values, but no XML formatting
             * In order to make heads or tails of hte values, we need to delimit the values, so we can sort out the configured values.
             * See bug report here: https://github.com/Microsoft/Reporting-Services/issues/81 for further details.
             * To get around this, we will just append a (pipe) symbol '|' to the end of each setting. This should suffice until a permanent fix is available
             */

            try
            {


                // Retrieve admin user and password from the config settings
                // and verify
                XmlDocument doc = new XmlDocument();
                doc.LoadXml(configuration);
                if (doc.DocumentElement.Name == "Authentication")
                {
                    foreach (XmlNode child in doc.DocumentElement.ChildNodes)
                    {
                        if (child.Name == "PEUrl")
                        {
                            m_peAppUrl = child.InnerText.Replace("|", "");
                        }
                        else if (child.Name == "AuthUrl")
                        {
                            m_oidcAuthority = child.InnerText.Replace("|", "");
                        }
                        else if (child.Name == "PEAppId")
                        {
                            m_peAppID = child.InnerText.Replace("|", "");
                        }
                        else if (child.Name == "PEAppKey")
                        {
                            m_peAppKey = child.InnerText.Replace("|", "");
                        }
                        else if (child.Name == "SSRSIntegrationSecret")
                        {
                            m_peIntegrationSecret = child.InnerText.Replace("|", "");
                        }
                        else
                        {
                            throw new Exception(string.Format(CultureInfo.InvariantCulture,
                              "Authentication Contained a Node that was unexpected: {0}", child.Name));
                        }
                    }
                }
                else
                    throw new Exception(string.Format(CultureInfo.InvariantCulture,
                       "Missing Authentication, Got this Instead: {0}", doc.DocumentElement.Name));
            }
            catch (XmlException ex)
            {
                var split = configuration.Split('|');
                if (split.Length != 5)
                    throw new Exception(string.Format(CultureInfo.InvariantCulture,
                       "Bad Configuration, Got this: {0}", configuration));
                m_oidcAuthority = split[0];
                m_peAppUrl = split[1];
                m_peAppID = split[2];
                m_peAppKey = split[3];
                m_peIntegrationSecret = split[4];
            }
        }

        /// <summary>
        /// Returns a Handle whose Target is the Identity for the User
        /// </summary>
        /// <param name="username">Name of the user to get Identity For</param>
        /// <returns>Handle whose Target is a ClaimsIdentity</returns>
        private GCHandle GetIdentityHandle(string username)
        {
            GCHandle handle;
            if (!staticIdentities.TryGetValue(username, out handle))
            {
                // Create an Identity
                var identity = CreatePEIdentity(username);
                handle = GCHandle.Alloc(identity);
                if (!staticIdentities.TryAdd(username, handle))
                {
                    // Someone else beat us to it - destroy this handle and the the one already there
                    if (!staticIdentities.TryGetValue(username, out handle))
                    {
                        throw new Exception("Unsupported Race Situation has occurred retrieving identity");
                    }
                }
            }

            // Make sure Expires is updated to 10 minutes from now
            var expiresAt = DateTimeOffset.Now.AddMinutes(10);
            cleanUpList.AddOrUpdate(username, expiresAt, (un, dt) => expiresAt);
            return handle;
        }

        /// <summary>
        /// Creates a PE Identity from a Username - nOt to be called from IAuthenticationExtension2 Methods
        /// </summary>
        /// <param name="username">The Username to Create an Identity For</param>
        /// <returns>ClaimsIdenity with Name and Roles</returns>
        private ClaimsIdentity CreatePEIdentity(string username)
        {
            // Create a Custom Identity
            var claims = new List<Claim>();
            claims.Add(new Claim(ClaimTypes.Name, username));
            var peUtils = new PEUtilities(m_oidcAuthority, m_peAppUrl, m_peAppID, m_peAppKey, m_peIntegrationSecret);

            // add PE Roles
            var roles = peUtils.ListGroupsForUser(username);
            claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

            return new ClaimsIdentity(claims, "custom", ClaimTypes.Name, ClaimTypes.Role);
        }
    }
}
