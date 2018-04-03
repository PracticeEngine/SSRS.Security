using Microsoft.ReportingServices.Interfaces;
using SSRS.OpenIDConnect.Security.PE;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Web;
using System.Xml;

namespace SSRS.OpenIDConnect.Security
{
    public class SSRSAuthentication : IAuthenticationExtension2, IExtension
    {
        // Configuration Items (read from rsreportserver.config Configuration File)
        private string m_oidcAuthority;
        private string m_peUrl;
        private string m_peAppID;
        private string m_peAppKey;

        public string LocalizedName
        {
            get
            {
                return "PE.SSRS.Authentication";
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
                userIdentity = CreatePEIdentity(HttpContext.Current.User.Identity.Name);
            }
            else
            // The current user identity is null. This happens when the user attempts an anonymous logon.
            // Although it is ok to return userIdentity as a null reference, it is best to throw an appropriate
            // exception for debugging purposes.
            // To configure for anonymous logon, return a Gener
            {
                //System.Diagnostics.Debug.Assert(false, "Warning: userIdentity is null! Modify your code if you wish to support anonymous logon.");
                throw new NullReferenceException("Anonymous logon is not configured. userIdentity should not be null!");
            }

            // initialize a pointer to the current user id to zero
            userId = IntPtr.Zero;
        }

        public void GetUserInfo(IRSRequestContext requestContext, out IIdentity userIdentity, out IntPtr userId)
        {
            userIdentity = null;
            if (requestContext.User != null)
            {
                // This is the custom bit - Create a Custom PE Identity
                userIdentity = CreatePEIdentity(requestContext.User.Name);
            }

            // initialize a pointer to the current user id to zero
            userId = IntPtr.Zero;
        }

        /// <summary>
        /// Checks to see if the user is valid
        /// </summary>
        /// <param name="principalName"></param>
        /// <returns></returns>
        public bool IsValidPrincipalName(string principalName)
        {
            var peUtils = new PEUtilities(m_peUrl, m_peAppID, m_peAppKey);
            return peUtils.ValidatePrincipal(principalName);
        }

        public bool LogonUser(string userName, string password, string authority)
        {
            // Need to do this, so we can Consume WebService Methods
            throw new NotImplementedException();
        }

        /// <summary>
        /// Called at Startup to Configure the Extension
        /// </summary>
        /// <param name="configuration"></param>
        public void SetConfiguration(string configuration)
        {
            // Retrieve admin user and password from the config settings
            // and verify
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(configuration);
            if (doc.DocumentElement.Name == "SiteConfiguration")
            {
                foreach (XmlNode child in doc.DocumentElement.ChildNodes)
                {
                    if (child.Name == "Authority")
                    {
                        m_oidcAuthority = child.InnerText;
                    }
                    else if(child.Name == "PEUrl")
                    {
                        m_peUrl = child.InnerText;
                    }
                    else if (child.Name == "PEAppId")
                    {
                        m_peAppID = child.InnerText;
                    }
                    else if (child.Name == "PEAppKey")
                    {
                        m_peAppKey = child.InnerText;
                    }
                    else
                    {
                        throw new Exception(string.Format(CultureInfo.InvariantCulture,
                          "SiteConfiguration Contained a Node that was unexpected: {0}", child.Name));
                    }
                }
            }
            else
                throw new Exception(string.Format(CultureInfo.InvariantCulture,
                   "Missing SiteConfiguration, Got this Instead: {0}", doc.DocumentElement.Name));
        }

        /// <summary>
        /// Creates a PE Identity from a Username
        /// </summary>
        /// <param name="username">The Username to Create an Identity For</param>
        /// <returns>ClaimsIdenity with Name and Roles</returns>
        private ClaimsIdentity CreatePEIdentity(string username)
        {
            // Create a Custom Identity
            var claims = new List<Claim>();
            claims.Add(new Claim(ClaimTypes.Name, HttpContext.Current.User.Identity.Name));
            var peUtils = new PEUtilities(m_peUrl, m_peAppID, m_peAppKey);

            // add PE Roles
            var roles = peUtils.ListGroupsForUser(HttpContext.Current.User.Identity.Name);
            claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

            return new ClaimsIdentity(claims, "custom");
        }
    }
}
