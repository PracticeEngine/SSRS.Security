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
        string url = "https://pes.pehosted.com";
        string appID = "87b2b36f245a4583aac5727c64b72082";
        string appKey = "rbjt/RENS6ZF4qhxpEqzDHoju9iziw9W/GpEoTMsegc=";

        [TestCategory("Integration")]
        [TestMethod]
        public void ListGroups_Returns_Data()
        {
            var peutils = new PEUtilities(url, appID, appKey);
            var groups = peutils.ListAllGroups();

            Assert.IsTrue(groups.Count() > 0, "No Groups Returned");
        }

        [TestCategory("Integration")]
        [TestMethod]
        public void FindUser_Returns_Data()
        {
            var peutils = new PEUtilities(url, appID, appKey);
            var hasUser = peutils.IsUserValid("ryan@praceng.us");

            Assert.IsTrue(hasUser, "No User Returned");
        }

        [TestCategory("Integration")]
        [TestMethod]
        public void List_UserGroups_Returns_Data()
        {
            var peutils = new PEUtilities(url, appID, appKey);
            var groups = peutils.ListGroupsForUser("ryan@praceng.us");

            Assert.IsTrue(groups.Count() > 0, "No Groups Returned");
        }
    }
}
