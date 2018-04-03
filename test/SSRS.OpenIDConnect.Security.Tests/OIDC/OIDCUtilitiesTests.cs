using System;
using System.Linq;
using System.Runtime.Caching;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SSRS.OpenIDConnect.Security.OIDC;

namespace SSRS.OpenIDConnect.Security.Tests.OIDC
{
    [TestClass]
    public class OIDCUtilitiesTests
    {
        string authURL = "https://pes.pehosted.com/auth";

        [TestCategory("Integration")]
        [TestMethod]
        public void BuildUri_Returns_Valid_Uri()
        {
            var oidcUtils = new OIDCUtilities(new Uri(authURL));

            var auth = oidcUtils.BuildAuthorizeUrl("test");

            var parser = new UriBuilder(auth);
            Assert.AreEqual("https", parser.Scheme);
            Assert.AreEqual("pes.pehosted.com", parser.Host);
        }

        [TestCategory("Integration")]
        [TestMethod]
        public void BuildUri_Returns_Has_Valid_Nonce()
        {
            var oidcUtils = new OIDCUtilities(new Uri(authURL));

            var auth = oidcUtils.BuildAuthorizeUrl("test");

            var parser = new UriBuilder(auth);
            var values = System.Web.HttpUtility.ParseQueryString(parser.Query);
            Assert.IsTrue(values.AllKeys.Contains("nonce"));
            Assert.IsNotNull(MemoryCache.Default[values["nonce"]]);
        }
    }
}
