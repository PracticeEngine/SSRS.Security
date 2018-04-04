using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SSRS.OpenIDConnect.Security.PE;

namespace SSRS.OpenIDConnect.Security.Tests.PE
{
    [TestClass]
    public class PEUtilitiesTests
    {
        // These Must be Set to Valid Values for the Integration Tests To Pass
        string authUrl = "https://localhost:44357/";
        string appUrl = "https://localhost:44333/PE/";
        string appID = "cecbab46d3a6441aa6dcd3a058fa352a";
        string appKey = "uSqw5Ub3ydj8FB6v1S280QXq5o1gPVmAMmCGi/MPkI4=";
        string integrationSecret = "SSRS.Integration S#cret";

        [TestCategory("Integration")]
        [TestMethod]
        public void ListGroups_Returns_Data()
        {
            var peutils = new PEUtilities(authUrl, appUrl, appID, appKey, integrationSecret);
            var groups = peutils.ListAllGroups();

            Assert.IsTrue(groups.Count() > 0, "No Groups Returned");
        }

        [TestCategory("Integration")]
        [TestMethod]
        public void FindUser_Returns_Data()
        {
            var peutils = new PEUtilities(authUrl, appUrl, appID, appKey, integrationSecret);
            var hasUser = peutils.IsUserValid("ryan@praceng.us");

            Assert.IsTrue(hasUser, "No User Returned");
        }

        [TestCategory("Integration")]
        [TestMethod]
        public void List_UserGroups_Returns_Data()
        {
            var peutils = new PEUtilities(authUrl, appUrl, appID, appKey, integrationSecret);
            var groups = peutils.ListGroupsForUser("ryan@praceng.us");

            Assert.IsTrue(groups.Count() > 0, "No Groups Returned");
        }

        [TestCategory("Integration")]
        [TestMethod]
        public void Validate_UserCredentials_Works()
        {
            var peutils = new PEUtilities(authUrl, appUrl, appID, appKey, integrationSecret);
            var isValid = peutils.ValidateUserCredentials("ryan@praceng.us", "password");

            Assert.IsTrue(isValid, "User Not Validated");
        }
    }
}
