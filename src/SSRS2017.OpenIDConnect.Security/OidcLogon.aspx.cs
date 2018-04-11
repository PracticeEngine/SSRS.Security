using SSRS.OpenIDConnect.Security.OIDC;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Security;

namespace SSRS.OpenIDConnect.Security
{
    public class OidcLogon : System.Web.UI.Page
    {

        #region Web Form Designer generated code
        override protected void OnInit(EventArgs e)
        {
            InitializeComponent();
            base.OnInit(e);
        }

        private void InitializeComponent()
        {
            this.Load += new System.EventHandler(this.Page_Load);

        }
        #endregion

        public string Authority { get; set; }

        private void Page_Load(object sender, System.EventArgs e)
        {
            if (Request.HttpMethod.Equals("get", StringComparison.OrdinalIgnoreCase))
            {

                var oidcUtils = new OIDCUtilities(new Uri(Authority));

                // Store Return Url in State
                var state = Convert.ToBase64String(Encoding.UTF8.GetBytes(Request.QueryString["ReturnUrl"]));

                // URL must be clean (no QueryString, etc)
                var callbackBuilder = new UriBuilder(Request.Url.AbsoluteUri);
                callbackBuilder.Query = null;
                var callback = callbackBuilder.Uri.AbsoluteUri;
                Response.Redirect(oidcUtils.BuildAuthorizeUrl(state, callback), true);
            }
            if (Request.HttpMethod.Equals("post", StringComparison.OrdinalIgnoreCase))
            {
                var oidcUtils = new OIDCUtilities(new Uri(Authority));

                // Pull out state and token
                var origUrl = Encoding.UTF8.GetString(Convert.FromBase64String(Request.Form["state"]));
                var idToken = Request.Form["id_token"];

                // Validate then set Auth cookie and redirect
                var principal = oidcUtils.ValidateIdentityToken(idToken);
                FormsAuthentication.SetAuthCookie(
                  principal.Identity.Name, false);
                Response.Redirect(origUrl);
            }
        }
    }
}
